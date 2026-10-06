package iam

// RFC 8628 device flow. The CLI starts a grant, the user approves it in the
// browser, and the CLI polls for a DPoP-bound session.

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/util"
)

const (
	// maxLabel keeps a terminal's user agent readable in the sessions list.
	maxLabel = 64

	grantTTL        = 15 * time.Minute
	slowDownPenalty = 5 * time.Second
	deviceInterval  = 5 * time.Second
	// deviceSessionTTL is how long a terminal stays signed in. The session
	// only works with the key of its machine, so what this bounds is a
	// machine nobody noticed was lost: it can mint certificates for this
	// long, and use the last one for its lifetime on top.
	deviceSessionTTL = 30 * 24 * time.Hour

	deviceURLHeader = "Nokku-Api-Url"
	grantPending    = "pending"
	grantApproved   = "approved"
	grantDenied     = "denied"
)

// deviceGrantEntries bounds the grants waiting for an approval, two entries
// each. Anyone can start one, so they have a store nothing else lives in.
const deviceGrantEntries = 10_000

type DeviceFlow struct {
	svc    *Service
	grants *cache.Memory
}

// deviceGrant is stored under the device code, and under the user code until
// someone decides on it.
type deviceGrant struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	Status     string `json:"status"`
	UserID     string `json:"user_id,omitempty"`
	// Who asked. The approval page shows it, so a code someone else started
	// stands out.
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type pollState struct {
	last       time.Time
	violations int
}

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
		IP:         util.SanitizeUTF8(util.ClientIP(r.Header, r.RemoteAddr)),
		UserAgent:  truncate(util.SanitizeUTF8(r.Header.Get("User-Agent")), maxUserAgent),
	}
	b, _ := json.Marshal(g)
	if err := h.grants.Set(r.Context(), "device:code:"+deviceCode, b, grantTTL); err != nil ||
		h.grants.Set(r.Context(), "device:user:"+userCode, b, grantTTL) != nil {
		writeOAuthError(w, "server_error")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          h.svc.baseURL + "/device",
		"verification_uri_complete": h.svc.baseURL + "/device?user_code=" + userCode,
		"expires_in":                int(grantTTL.Seconds()),
		"interval":                  int(deviceInterval.Seconds()),
	})
}

// Info tells the approver who asked for a code. It does not spend the code.
func (h *DeviceFlow) Info(w http.ResponseWriter, r *http.Request) {
	userCode := normalizeUserCode(r.URL.Query().Get("user_code"))
	var g deviceGrant
	b, err := h.grants.Get(r.Context(), "device:user:"+userCode)
	if err != nil || json.Unmarshal(b, &g) != nil || g.Status != grantPending {
		writeError(w, http.StatusNotFound, "invalid or expired code")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"ip": g.IP, "user_agent": g.UserAgent})
}

func (h *DeviceFlow) Verify(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, true)
}

func (h *DeviceFlow) Deny(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, false)
}

func (h *DeviceFlow) decide(w http.ResponseWriter, r *http.Request, approve bool) {
	p, ok := actor.PrincipalFromContext(r.Context())
	if !ok || p.Kind != actor.KindUser {
		writeError(w, http.StatusUnauthorized, "sign in to approve a device")
		return
	}

	userCode := normalizeUserCode(r.FormValue("user_code"))
	if userCode == "" {
		writeError(w, http.StatusBadRequest, "missing user_code")
		return
	}

	// Consuming the user code makes the decision single-use.
	b, err := h.grants.GetDel(r.Context(), "device:user:"+userCode)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired code")
		return
	}
	var g deviceGrant
	if err := json.Unmarshal(b, &g); err != nil || g.Status != grantPending {
		writeError(w, http.StatusBadRequest, "invalid or expired code")
		return
	}

	if approve {
		g.Status = grantApproved
	} else {
		g.Status = grantDenied
	}
	g.UserID = p.ID
	b, _ = json.Marshal(g)
	if err := h.grants.Set(r.Context(), "device:code:"+g.DeviceCode, b, grantTTL); err != nil {
		writeOAuthError(w, "server_error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *DeviceFlow) Poll(w http.ResponseWriter, r *http.Request) {
	// The session and its audit events carry the terminal's address.
	ctx := ContextWithRequestMeta(r.Context(), RequestMeta{Header: r.Header, RemoteAddr: r.RemoteAddr})
	deviceCode := r.FormValue("device_code")
	if deviceCode == "" {
		writeOAuthError(w, "invalid_request")
		return
	}

	b, err := h.grants.Get(ctx, "device:code:"+deviceCode)
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
		// Consume it so a CLI left polling doesn't audit the denial every poll.
		if _, err := h.grants.GetDel(ctx, "device:code:"+deviceCode); err != nil {
			writeOAuthError(w, "expired_token") // a concurrent poll consumed it
			return
		}
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
		u, err := h.svc.getUserByID(ctx, g.UserID)
		if err != nil || !u.Active {
			writeOAuthError(w, "access_denied")
			return
		}

		binding, derr := h.deviceBinding(ctx, r)
		if derr != nil {
			// Retryable, the grant stays usable. The advertised URL also
			// fixes clients that signed the wrong htu.
			h.svc.AdvertiseDPoPNonce(w.Header())
			if errors.Is(derr, ErrDPoPNonce) {
				writeOAuthError(w, "use_dpop_nonce")
			} else {
				writeOAuthError(w, "invalid_dpop_proof")
			}
			return
		}

		// Consume before issuing so racing polls never yield two sessions.
		if _, err := h.grants.GetDel(ctx, "device:code:"+deviceCode); err != nil {
			writeOAuthError(w, "expired_token") // a concurrent poll consumed it
			return
		}

		sess, token, err := h.svc.IssueSession(ctx, SessionParams{
			SubjectID: u.ID,
			Kind:      actor.KindCLI,
			Method:    MethodDevice,
			Binding:   binding,
			Label:     cmp.Or(truncate(util.SanitizeUTF8(r.Header.Get("User-Agent")), maxLabel), "Terminal"),
			TTL:       deviceSessionTTL,
		})
		if err != nil {
			writeOAuthError(w, "server_error")
			return
		}
		// Only a key the account has not signed in with before is mailed, so
		// the mail stays rare enough to be read. An approval the user was
		// tricked into always comes from such a key.
		if h.svc.rememberTerminal(ctx, u.ID, binding, sess.Label) && h.svc.OnNewDeviceLogin != nil {
			go h.svc.OnNewDeviceLogin(context.WithoutCancel(ctx), u, sess, sess.Label, sess.Ip)
		}
		h.svc.record(ctx, Event{
			Action: ActionLoginSucceeded,
			Kind:   actor.KindCLI,
			Method: MethodDevice,
			UserID: u.ID,
			Email:  u.Email,
		})
		resp := map[string]any{
			"access_token": token,
			"token_type":   "DPoP",
			"method":       string(MethodDevice),
			"user_id":      g.UserID,
		}
		if sess.ExpiresAt != nil {
			resp["expires_in"] = int(time.Until(*sess.ExpiresAt).Seconds())
		}
		WriteJSON(w, http.StatusOK, resp)
	}
}

// rememberTerminal reports whether binding is a key the account has not
// signed in with before, and remembers it. The marker is the one a browser
// gets from RememberDevice, with the key in place of the cookie.
func (s *Service) rememberTerminal(ctx context.Context, userID, binding, label string) bool {
	sessions, err := s.sys.ListSessionsBySubject(ctx, userID)
	if err != nil {
		slog.Error("failed to look up remembered terminals", "error", err)
		return true
	}
	now := s.now()
	for _, sess := range sessions {
		if sess.Kind != string(actor.KindDevice) || sess.Binding != binding {
			continue
		}
		if sess.ExpiresAt != nil && !sess.ExpiresAt.After(now) {
			continue
		}
		if err := s.sys.TouchSession(
			ctx,
			&db.TouchSessionParams{TokenHash: sess.TokenHash, LastSeenAt: &now},
		); err != nil {
			slog.Debug("failed to touch device session", "error", err)
		}
		return false
	}
	// The marker's token goes nowhere, nothing can present it.
	if _, _, err := s.IssueSession(ctx, SessionParams{
		SubjectID: userID,
		Kind:      actor.KindDevice,
		Method:    MethodDevice,
		Binding:   binding,
		Label:     label,
		TTL:       deviceMarkerTTL,
	}); err != nil {
		slog.Error("failed to remember terminal", "error", err)
	}
	return true
}

// Nonce lets devices fetch a nonce before their first proof.
func (h *DeviceFlow) Nonce(w http.ResponseWriter, _ *http.Request) {
	h.svc.AdvertiseDPoPNonce(w.Header())
	w.WriteHeader(http.StatusNoContent)
}

func (h *DeviceFlow) deviceBinding(ctx context.Context, r *http.Request) (string, error) {
	proof := r.Header.Get("DPoP")
	if proof == "" {
		return "", ErrDPoPNonce
	}
	return h.svc.DPoP.Verify(ctx, proof, "", r.Method, h.svc.baseURL+r.URL.Path)
}

// pollTrack reports a too-fast poll. The interval grows per slow_down, and a
// cache failure allows the poll.
func (h *DeviceFlow) pollTrack(ctx context.Context, deviceCode string) bool {
	key := "device:poll:" + deviceCode
	var st pollState
	if b, err := h.grants.Get(ctx, key); err == nil {
		st = decodePollState(b)
	}

	required := deviceInterval + time.Duration(st.violations)*slowDownPenalty
	now := time.Now()
	if !st.last.IsZero() && now.Sub(st.last) < required {
		st.violations++
		_ = h.grants.Set(ctx, key, encodePollState(st), grantTTL)
		return true
	}
	st.last = now
	_ = h.grants.Set(ctx, key, encodePollState(st), grantTTL)
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

// randomUserCode is a correlation handle, not a secret, since approval needs a
// session. The charset avoids 0/O/1/I.
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

// writeOAuthError uses the RFC 6749 section 5.2 shape.
func writeOAuthError(w http.ResponseWriter, code string) {
	WriteJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}
