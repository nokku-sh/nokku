package iam

// RFC 8628 device flow. The CLI starts a grant, the user approves it in the browser, the CLI polls for a session.

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/realip"
)

const (
	// maxLabel keeps a terminal's user agent readable in the sessions list.
	maxLabel = 64

	grantTTL        = 15 * time.Minute
	slowDownPenalty = 5 * time.Second
	deviceInterval  = 5 * time.Second
	// deviceSessionTTL bounds a lost machine nobody noticed, the session only works with the key of its machine.
	deviceSessionTTL = 30 * 24 * time.Hour

	deviceURLHeader = "Nokku-Api-Url"
	grantPending    = "pending"
	grantApproved   = "approved"
	grantDenied     = "denied"
)

// DeviceFlow keeps its grants in device_grants, under the workspace of the host like every tenant row.
type DeviceFlow struct {
	svc *Service
}

func (h *DeviceFlow) Begin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Only a workspace's own host can approve a code, the root host of the hosted service has none to offer.
	if actor.WorkspaceIDFromContext(ctx) == "" {
		WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_request", "error_description": "sign in at the URL of your workspace",
		})
		return
	}

	deviceCode := crypto.RandomString(32)
	var userCode string
	var err error
	// Two grants of one workspace may draw the same user code, rarely.
	for range 3 {
		if userCode, err = randomUserCode(); err != nil {
			break
		}
		err = h.svc.conn.Tenant().CreateDeviceGrant(ctx, &db.CreateDeviceGrantParams{
			DeviceCodeHash: crypto.HashToken(deviceCode),
			UserCode:       userCode,
			Ip:             strings.ToValidUTF8(realip.Client(r.Header, r.RemoteAddr), ""),
			UserAgent:      truncate(strings.ToValidUTF8(r.Header.Get("User-Agent"), ""), maxUserAgent),
			ExpiresAt:      h.svc.now().Add(grantTTL),
		})
		if !db.IsUniqueViolation(err) {
			break
		}
	}
	if err != nil {
		writeOAuthError(w, "server_error")
		return
	}

	base := baseURL(ctx)
	WriteJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          base + "/device",
		"verification_uri_complete": base + "/device?user_code=" + userCode,
		"expires_in":                int(grantTTL.Seconds()),
		"interval":                  int(deviceInterval.Seconds()),
	})
}

// Info tells the approver who asked for a code. It does not spend the code.
func (h *DeviceFlow) Info(w http.ResponseWriter, r *http.Request) {
	userCode := normalizeUserCode(r.URL.Query().Get("user_code"))
	g, err := h.svc.conn.Tenant().GetPendingDeviceGrant(r.Context(), userCode)
	if err != nil {
		writeError(w, http.StatusNotFound, "invalid or expired code")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"ip": g.Ip, "user_agent": g.UserAgent})
}

func (h *DeviceFlow) Verify(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, true)
}

func (h *DeviceFlow) Deny(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, false)
}

// decide spends the code. The CLI session inherits how the approving session signed in, so enforcing single sign-on
// can tell it apart.
func (h *DeviceFlow) decide(w http.ResponseWriter, r *http.Request, approve bool) {
	p, ok := actor.PrincipalFromContext(r.Context())
	tok, _ := CurrentToken(r.Context())
	if !ok || p.Kind != actor.KindUser {
		writeError(w, http.StatusUnauthorized, "sign in to approve a device")
		return
	}

	userCode := normalizeUserCode(r.FormValue("user_code"))
	if userCode == "" {
		writeError(w, http.StatusBadRequest, "missing user_code")
		return
	}

	status := grantDenied
	if approve {
		status = grantApproved
	}
	if _, err := h.svc.conn.Tenant().DecideDeviceGrant(r.Context(), &db.DecideDeviceGrantParams{
		Status:         status,
		UserID:         &p.ID,
		ApprovedMethod: new(tok.Method),
		UserCode:       userCode,
	}); err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired code")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *DeviceFlow) Poll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	deviceCode := r.FormValue("device_code")
	if deviceCode == "" {
		writeOAuthError(w, "invalid_request")
		return
	}

	hash := crypto.HashToken(deviceCode)
	g, err := h.svc.conn.Tenant().GetDeviceGrant(ctx, hash)
	if err != nil {
		writeOAuthError(w, "expired_token")
		return
	}
	consume := func() bool {
		_, err := h.svc.conn.Tenant().ConsumeDeviceGrant(ctx, &db.ConsumeDeviceGrantParams{
			DeviceCodeHash: hash, Status: g.Status,
		})
		return err == nil
	}

	switch g.Status {
	case grantPending:
		if h.tooFast(ctx, g) {
			writeOAuthError(w, "slow_down")
			return
		}
		writeOAuthError(w, "authorization_pending")
	case grantDenied:
		// Consumed, so a CLI left polling doesn't audit the denial every poll.
		if !consume() {
			writeOAuthError(w, "expired_token") // a concurrent poll consumed it
			return
		}
		h.svc.record(
			ctx,
			event{
				Action: actionLoginDenied,
				Method: MethodDevice,
				UserID: deref(g.UserID),
				Detail: "access denied",
			},
		)
		writeOAuthError(w, "access_denied")
	case grantApproved:
		u, err := h.svc.getUser(ctx, deref(g.UserID))
		if err != nil || !u.Active {
			writeOAuthError(w, "access_denied")
			return
		}

		binding, derr := h.deviceBinding(ctx, r)
		if derr != nil {
			// Retryable, the grant stays usable. The advertised URL also fixes clients that signed the wrong htu.
			h.svc.AdvertiseDPoPNonce(ctx, w.Header())
			if errors.Is(derr, ErrDPoPNonce) {
				writeOAuthError(w, "use_dpop_nonce")
			} else {
				writeOAuthError(w, "invalid_dpop_proof")
			}
			return
		}

		// Consume before issuing so racing polls never yield two sessions.
		if !consume() {
			writeOAuthError(w, "expired_token") // a concurrent poll consumed it
			return
		}

		sess, token, err := h.svc.IssueToken(ctx, TokenParams{
			SubjectID: u.ID,
			Kind:      actor.KindCLI,
			Method:    Method(cmp.Or(deref(g.ApprovedMethod), string(MethodDevice))),
			Binding:   binding,
			Label:     cmp.Or(truncate(strings.ToValidUTF8(r.Header.Get("User-Agent"), ""), maxLabel), "Terminal"),
			TTL:       deviceSessionTTL,
		})
		if err != nil {
			writeOAuthError(w, "server_error")
			return
		}
		// Only a key new to the account is mailed, so the mail stays rare enough to be read.
		if !h.svc.seenDevice(ctx, u.ID, binding) {
			if _, err := h.svc.addDevice(ctx, u, binding, sess.UserAgent, sess.Label, sess.Ip); err != nil {
				slog.Error("failed to remember terminal", "error", err)
			}
		}
		h.svc.record(ctx, event{
			Action: actionLoginSucceeded,
			Kind:   actor.KindCLI,
			Method: MethodDevice,
			UserID: u.ID,
			Email:  u.Email,
		})
		resp := map[string]any{
			"access_token": token,
			"token_type":   "DPoP",
			"method":       string(MethodDevice),
			"user_id":      u.ID,
		}
		if sess.ExpiresAt != nil {
			resp["expires_in"] = int(time.Until(*sess.ExpiresAt).Seconds())
		}
		WriteJSON(w, http.StatusOK, resp)
	}
}

// Nonce lets devices fetch a nonce before their first proof.
func (h *DeviceFlow) Nonce(w http.ResponseWriter, r *http.Request) {
	h.svc.AdvertiseDPoPNonce(r.Context(), w.Header())
	w.WriteHeader(http.StatusNoContent)
}

func (h *DeviceFlow) deviceBinding(ctx context.Context, r *http.Request) (string, error) {
	proof, err := DPoPProof(r.Header)
	if err != nil {
		return "", err
	}
	if proof == "" {
		return "", ErrDPoPNonce
	}
	return h.svc.DPoP.Verify(proof, "", r.Method, baseURL(ctx)+r.URL.Path, "")
}

// tooFast reports a poll inside the interval. Each one widens it, the way RFC 8628 asks of slow_down. A note that
// fails lets the poll through.
func (h *DeviceFlow) tooFast(ctx context.Context, g *db.DeviceGrant) bool {
	now := h.svc.now()
	required := deviceInterval + time.Duration(g.Violations)*slowDownPenalty
	note := &db.NoteDeviceGrantPollParams{DeviceCodeHash: g.DeviceCodeHash, PolledAt: &now, Violations: g.Violations}
	fast := g.PolledAt != nil && now.Sub(*g.PolledAt) < required
	if fast {
		note.PolledAt, note.Violations = g.PolledAt, g.Violations+1
	}
	if err := h.svc.conn.Tenant().NoteDeviceGrantPoll(ctx, note); err != nil {
		slog.Warn("failed to note a device poll", "error", err)
	}
	return fast
}

// randomUserCode is a correlation handle, not a secret, approval needs a session. The charset avoids 0/O/1/I.
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
