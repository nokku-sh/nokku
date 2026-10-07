package api

import (
	"context"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/daemon"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/realip"
)

const (
	wsReadLimit = 64 * 1024
	wsTimeout   = 15 * time.Second
	wsPingEvery = 20 * time.Second
	// Tells the browser the shell ended on its own (exit, Ctrl+D), so it drops
	// the tab. Timeouts and dropped daemons close normally and keep it.
	wsShellExited websocket.StatusCode = 4000

	// The browser opens the socket right after CreateSession.
	sessionTicketTTL = 30 * time.Second
	sessionIdle      = 30 * time.Minute

	// sshclient chunks at 32 KB, below the burst, so WaitN is valid.
	webStdoutRate  = 512 << 10
	webStdoutBurst = 64 << 10
)

// sessionTicket is what CreateSession authorized, kept in the cache until the
// websocket trades it in.
type sessionTicket struct {
	WorkspaceID string `json:"workspace_id"`
	DaemonID    string `json:"daemon_id"`
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
}

func putSessionTicket(ctx context.Context, c *cache.Memory, sessionID string, t sessionTicket) error {
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return c.Set(ctx, "websession:"+sessionID, b, sessionTicketTTL)
}

type terminalHandler struct {
	cfg *config.Config
}

func newTerminalHandler(cfg *config.Config) *terminalHandler {
	return &terminalHandler{cfg: cfg}
}

// handleWebSocket runs one shell for as long as the socket is open. A reload
// or a dropped connection ends it.
func (t *terminalHandler) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "session_id is required")
		return
	}

	// GetDel makes the ticket single use.
	var ticket sessionTicket
	raw, err := t.cfg.Cache.GetDel(r.Context(), "websession:"+sessionID)
	if err != nil || json.Unmarshal(raw, &ticket) != nil {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}
	if caller, _ := actor.PrincipalFromContext(r.Context()); caller.ID != ticket.UserID {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}

	ctx := r.Context()
	if ticket.WorkspaceID != actor.WorkspaceIDFromContext(ctx) || !callerRole(ctx).AtLeast(db.RoleMember) {
		writeJSONError(w, http.StatusForbidden, "permission denied")
		return
	}
	var ca *db.CertificateAuthority
	var targetID string
	if err := t.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		ca, err = q.GetCAByDaemonID(ctx, &ticket.DaemonID)
		if err != nil {
			return err
		}
		target, err := q.GetTargetByDaemon(ctx, &ticket.DaemonID)
		if err != nil {
			return err
		}
		targetID = target.ID
		return nil
	}); err != nil {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{t.cfg.FullURL()},
	})
	if err != nil {
		slog.Error("websocket upgrade failed", "error", err)
		return
	}
	defer func() { _ = conn.CloseNow() }()
	conn.SetReadLimit(wsReadLimit)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	logger := slog.With("session_id", sessionID, "daemon_id", ticket.DaemonID)

	// The dial runs after the upgrade so the browser can show why it failed.
	sess, err := t.cfg.Pool.StartSession(ctx, daemon.SessionConfig{
		DaemonID:      ticket.DaemonID,
		SessionID:     sessionID,
		Username:      ticket.Username,
		UserID:        ticket.UserID,
		CA:            ca,
		HostPrincipal: targetID,
		ClientAddr:    realip.Client(r.Header, r.RemoteAddr),
	})
	if err != nil {
		logger.Warn("web session failed to start", "error", err)
		reason := "could not reach the server"
		switch {
		case errors.Is(err, daemon.ErrRelayLimit):
			reason = "too many concurrent sessions"
		case errors.Is(err, daemon.ErrCAInactive):
			reason = "certificate authority is not active"
		}
		_ = conn.Close(websocket.StatusInternalError, reason)
		return
	}
	defer sess.Close()

	idle := time.AfterFunc(sessionIdle, sess.Close)
	defer idle.Stop()

	// Reads have no timeout since an idle terminal sends nothing. Pings prove
	// the browser is still there.
	go func() {
		ticker := time.NewTicker(wsPingEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			pctx, pcancel := context.WithTimeout(ctx, wsTimeout)
			err := conn.Ping(pctx)
			pcancel()
			if err != nil {
				cancel()
				return
			}
		}
	}()

	// Throttled so a chatty shell cannot flood the websocket. Stdout closing
	// is the session's end.
	go func() {
		limiter := rate.NewLimiter(webStdoutRate, webStdoutBurst)
		for data := range sess.Stdout() {
			if err := limiter.WaitN(ctx, len(data)); err != nil {
				return
			}
			idle.Reset(sessionIdle)
			wctx, wcancel := context.WithTimeout(ctx, wsTimeout)
			err := conn.Write(wctx, websocket.MessageBinary, data)
			wcancel()
			if err != nil {
				cancel()
				return
			}
		}
		code, reason := websocket.StatusNormalClosure, "session ended"
		if sess.Exited() {
			code, reason = wsShellExited, "shell exited"
		}
		_ = conn.Close(code, reason)
	}()

	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		switch typ {
		case websocket.MessageBinary:
			idle.Reset(sessionIdle)
			if err := sess.Write(data); err != nil {
				return
			}
		case websocket.MessageText:
			var msg struct {
				Type string `json:"type"`
				Cols uint32 `json:"cols"`
				Rows uint32 `json:"rows"`
			}
			if err := json.Unmarshal(data, &msg); err != nil {
				logger.Debug("invalid control message", "error", err)
				continue
			}
			if msg.Type == "resize" {
				_ = sess.Resize(msg.Cols, msg.Rows)
			}
		}
	}
}
