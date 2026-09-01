package iam

// RFC 8628 device flow, ported from kagi: the CLI starts a grant, the user
// approves it from the browser (an authenticated web_device page), and the
// CLI polls the token endpoint for a DPoP-bound session.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/crypto"
)

const (
	// grantTTL is how long a device grant stays pending.
	grantTTL = 15 * time.Minute
	// slowDownPenalty is the extra interval RFC 8628 section 3.5 asks a
	// client to add after each slow_down response.
	slowDownPenalty = 5 * time.Second
	// deviceInterval is the default poll interval hint. Default 5s.
	deviceInterval   = 5 * time.Second
	deviceSessionTTL = 7 * 24 * time.Hour

	grantPending  = "pending"
	grantApproved = "approved"
	grantDenied   = "denied"
)

// DeviceOptions configures the device flow.
type DeviceOptions struct {
	// VerificationURI is the browser page the user opens: /device.
	VerificationURI string
	// Interval is the poll interval hint returned to the device.
	Interval time.Duration
	// SessionTTL is the lifetime of the session the flow issues. Zero
	// means the service default.
	SessionTTL time.Duration
	// Cache stores grants and poll bookkeeping. Required.
	Cache cache.Cache
}

// DeviceFlow implements the RFC 8628 endpoints on top of the service.
type DeviceFlow struct {
	svc   *Service
	opts  DeviceOptions
	cache cache.Cache
}

// NewDeviceFlow builds the device flow handler.
func NewDeviceFlow(svc *Service, opts DeviceOptions) (*DeviceFlow, error) {
	if svc == nil || opts.Cache == nil {
		return nil, errors.New("iam: device flow requires a service and cache")
	}
	if svc.baseURL == "" {
		return nil, errors.New("iam: device flow requires a baseURL")
	}
	opts.VerificationURI = svc.baseURL + "/device"
	if opts.Interval <= 0 {
		opts.Interval = deviceInterval
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = deviceSessionTTL
	}
	return &DeviceFlow{svc: svc, opts: opts, cache: opts.Cache}, nil
}

// grant is a cross-request device grant, stored under both the device code
// and the user code. Sessions issued from a device login stay unpinned:
// users are global and act per-request in a workspace, like every other
// interactive login.
type deviceGrant struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	Status     string `json:"status"`
	UserID     string `json:"user_id,omitempty"`
}

type pollState struct {
	last       time.Time
	violations int
}

// Begin starts a device grant (POST /auth/device). Public: the CLI has no
// credentials yet.
func (h *DeviceFlow) Begin(w http.ResponseWriter, r *http.Request) {
	deviceCode, err := crypto.RandomString(32)
	if err != nil {
		writeOAuthError(w, "server_error")
		return
	}
	userCode, err := randomUserCode()
	if err != nil {
		writeOAuthError(w, "server_error")
		return
	}

	g := deviceGrant{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		Status:     grantPending,
	}
	b, _ := json.Marshal(g)
	if err := h.cache.Set(r.Context(), "device:code:"+deviceCode, b, grantTTL); err != nil ||
		h.cache.Set(r.Context(), "device:user:"+userCode, b, grantTTL) != nil {
		writeOAuthError(w, "server_error")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          h.opts.VerificationURI,
		"verification_uri_complete": h.opts.VerificationURI + "?user_code=" + userCode,
		"expires_in":                int(grantTTL.Seconds()),
		"interval":                  int(h.opts.Interval.Seconds()),
	})
}

// Verify marks a grant approved (POST /auth/device/verify). Mounted behind
// RequireLogin so the approving principal is present. The user code is the
// only input.
func (h *DeviceFlow) Verify(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, true)
}

// Deny marks a grant denied (POST /auth/device/deny) so a concurrent poll
// returns access_denied and the device aborts the flow.
func (h *DeviceFlow) Deny(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, false)
}

func (h *DeviceFlow) decide(w http.ResponseWriter, r *http.Request, approve bool) {
	p, ok := PrincipalFromContext(r.Context())
	if !ok || p.Kind != KindUser {
		WriteError(w, http.StatusUnauthorized, "unauthenticated", "sign in to approve a device")
		return
	}

	userCode := normalizeUserCode(r.FormValue("user_code"))
	if userCode == "" {
		WriteError(w, http.StatusBadRequest, "missing_user_code", "missing user_code")
		return
	}

	b, err := h.cache.Get(r.Context(), "device:user:"+userCode)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_or_expired_code", "invalid or expired code")
		return
	}
	var g deviceGrant
	if err := json.Unmarshal(b, &g); err != nil || g.Status != grantPending {
		WriteError(w, http.StatusBadRequest, "invalid_or_expired_code", "invalid or expired code")
		return
	}

	if approve {
		g.Status = grantApproved
	} else {
		g.Status = grantDenied
	}
	g.UserID = p.ID
	b, _ = json.Marshal(g)
	if err := h.cache.Set(r.Context(), "device:code:"+g.DeviceCode, b, grantTTL); err != nil {
		writeOAuthError(w, "server_error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Poll is the device token endpoint (POST /auth/device/token): pending
// returns authorization_pending or slow_down (RFC 8628 section 3.5),
// approval issues a DPoP-bound session, denial access_denied.
func (h *DeviceFlow) Poll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	deviceCode := r.FormValue("device_code")
	if deviceCode == "" {
		writeOAuthError(w, "invalid_request")
		return
	}

	b, err := h.cache.Get(ctx, "device:code:"+deviceCode)
	if err != nil {
		writeOAuthError(w, "expired_token")
		return
	}
	var g deviceGrant
	if err := json.Unmarshal(b, &g); err != nil {
		writeOAuthError(w, "expired_token")
		return
	}

	switch g.Status {
	case grantPending:
		if h.pollTrack(ctx, deviceCode) {
			writeOAuthError(w, "slow_down")
			return
		}
		writeOAuthError(w, "authorization_pending")
	case grantDenied:
		// Consume the grant: a CLI left polling must not re-record the
		// denial as an audit event on every poll until the TTL expires.
		if _, err := h.cache.GetDel(ctx, "device:code:"+deviceCode); err != nil {
			writeOAuthError(w, "expired_token") // a concurrent poll consumed it
			return
		}
		_ = h.cache.Delete(ctx, "device:user:"+g.UserCode)
		h.svc.record(
			ctx,
			Event{
				Action: ActionLoginDenied,
				Method: MethodDevice,
				UserID: g.UserID,
				Detail: "access denied",
			},
		)
		writeOAuthError(w, "access_denied")
	case grantApproved:
		u, err := h.svc.GetUser(ctx, g.UserID)
		if err != nil || !u.Active {
			writeOAuthError(w, "access_denied")
			return
		}

		binding, derr := h.deviceBinding(ctx, r)
		if derr != nil {
			// A proof error is retryable, so the grant stays usable: the
			// device re-signs with the advertised nonce and polls again.
			if errors.Is(derr, ErrDPoPNonce) && h.svc.DPoP != nil {
				w.Header().Set("DPoP-Nonce", h.svc.DPoP.CurrentNonce())
				writeOAuthError(w, "use_dpop_nonce")
			} else {
				writeOAuthError(w, "invalid_dpop_proof")
			}
			return
		}

		// Consume the grant before issuing, so one approval can never yield
		// two sessions no matter how the polls race. Past this point a
		// failure costs the device its grant and it re-runs the flow.
		if _, err := h.cache.GetDel(ctx, "device:code:"+deviceCode); err != nil {
			writeOAuthError(w, "expired_token") // a concurrent poll consumed it
			return
		}
		_ = h.cache.Delete(ctx, "device:user:"+g.UserCode)

		sess, token, err := h.svc.Sessions.Issue(ctx, SessionParams{
			SubjectID: u.ID,
			Kind:      KindCLI,
			Method:    MethodDevice,
			Binding:   binding,
			TTL:       h.opts.SessionTTL,
		})
		if err != nil {
			writeOAuthError(w, "server_error")
			return
		}
		h.svc.record(ctx, Event{
			Action: ActionLoginSucceeded,
			Kind:   KindCLI,
			Method: MethodDevice,
			UserID: u.ID,
			Email:  u.Email,
		})
		tokenType := "Bearer"
		if binding != "" {
			tokenType = "DPoP"
		}
		resp := map[string]any{
			"access_token": token,
			"token_type":   tokenType,
			"method":       string(MethodDevice),
			"user_id":      g.UserID,
		}
		if sess.ExpiresAt != nil {
			resp["expires_in"] = int(time.Until(*sess.ExpiresAt).Seconds())
		}
		WriteJSON(w, http.StatusOK, resp)
	}
}

// Nonce advertises the current DPoP nonce over an unauthenticated endpoint
// (GET /auth/device/nonce), so devices can fetch one before their first
// DPoP-protected call (RFC 9449 section 8). Returns 204.
func (h *DeviceFlow) Nonce(w http.ResponseWriter, _ *http.Request) {
	if h.svc.DPoP == nil {
		WriteError(w, http.StatusNotFound, "dpop_disabled", "dpop disabled")
		return
	}
	w.Header().Set("DPoP-Nonce", h.svc.DPoP.CurrentNonce())
	w.WriteHeader(http.StatusNoContent)
}

// deviceBinding returns the DPoP key thumbprint the session should be bound
// to: the verified proof's jkt, or "" when no verifier is configured or the
// device sent no proof.
func (h *DeviceFlow) deviceBinding(ctx context.Context, r *http.Request) (string, error) {
	if h.svc.DPoP == nil {
		return "", nil
	}
	proof := r.Header.Get("DPoP")
	if proof == "" {
		return "", nil
	}
	return h.svc.DPoP.Verify(ctx, proof, "", r.Method, h.svc.requestHTU(r))
}

// requestHTU reconstructs the request URL for DPoP htu checks: the public
// base URL plus the request path.
func (s *Service) requestHTU(r *http.Request) string {
	return s.baseURL + r.URL.Path
}

// pollTrack records one poll and reports whether it came too fast. The
// required interval grows by slowDownPenalty per slow_down, and a too-fast
// poll does not move the last-accepted timestamp. A cache failure allows
// the poll.
func (h *DeviceFlow) pollTrack(ctx context.Context, deviceCode string) bool {
	key := "device:poll:" + deviceCode
	var st pollState
	if b, err := h.cache.Get(ctx, key); err == nil {
		st = decodePollState(b)
	}

	required := h.opts.Interval + time.Duration(st.violations)*slowDownPenalty
	now := time.Now()
	if !st.last.IsZero() && now.Sub(st.last) < required {
		st.violations++
		_ = h.cache.Set(ctx, key, encodePollState(st), grantTTL)
		return true
	}
	st.last = now
	_ = h.cache.Set(ctx, key, encodePollState(st), grantTTL)
	return false
}

func encodePollState(st pollState) []byte {
	return []byte(strconv.FormatInt(st.last.UnixNano(), 10) + ":" + strconv.Itoa(st.violations))
}

func decodePollState(b []byte) pollState {
	lastS, vS, _ := strings.Cut(string(b), ":")
	nano, err := strconv.ParseInt(lastS, 10, 64)
	if err != nil {
		return pollState{}
	}
	v, _ := strconv.Atoi(vS)
	return pollState{last: time.Unix(0, nano), violations: v}
}

// randomUserCode returns a short, human-typed code like "ABCD-EFGH". Approval
// still requires an authenticated session, so it is a correlation handle, not
// a secret. Characters avoid 0/O/1/I ambiguity.
func randomUserCode() (string, error) {
	const chars = "BCDFGHJKLMNPQRSTVWXZ23456789"
	out := make([]byte, 8)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		out[i] = chars[n.Int64()]
	}
	return string(out[:4]) + "-" + string(out[4:]), nil
}

// normalizeUserCode canonicalizes a typed user code: uppercased with
// separators and whitespace removed and re-dashed, so a user typing
// "ABCDEFGH" or "abcd efgh" still matches the issued "XXXX-XXXX" grant.
func normalizeUserCode(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	for _, r := range strings.ToUpper(strings.TrimSpace(code)) {
		if r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	s := b.String()
	if len(s) == 8 {
		return s[:4] + "-" + s[4:]
	}
	return s
}

// writeOAuthError writes the RFC 6749 section 5.2 error shape the device
// client parses: {"error": "..."}.
func writeOAuthError(w http.ResponseWriter, code string) {
	WriteJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}
