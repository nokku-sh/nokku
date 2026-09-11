package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/daemon"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

const wsReadLimit = 64 * 1024

type TerminalHandler struct {
	cfg *config.Config
}

func NewTerminalHandler(cfg *config.Config) *TerminalHandler {
	return &TerminalHandler{cfg: cfg}
}

func (t *TerminalHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	daemonID := r.URL.Query().Get("daemon_id")
	sessionID := r.URL.Query().Get("session_id")

	if daemonID == "" || sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "daemon_id and session_id are required")
		return
	}

	sess := t.cfg.Pool.GetSession(sessionID)
	if sess == nil {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}

	// Attaching means full stdin/stdout access to a live PTY. Without this
	// check any authenticated principal who learned a session id could
	// watch and drive any workspace's sessions.
	if !t.authorizeAttach(w, r, sess) {
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: t.cfg.WSOrigins(),
	})
	if err != nil {
		slog.Error("websocket upgrade failed", "error", err)
		return
	}
	defer func() { _ = conn.CloseNow() }()
	conn.SetReadLimit(wsReadLimit)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Bound each read/write so a half-dead client that stops reading and
	// sending can't pin the handler or its pump goroutine forever.
	wsTimeout := 15 * time.Second

	logger := slog.With("session_id", sessionID, "daemon_id", daemonID)

	// Snapshot replay and live channel atomically. No screen clear: replay
	// sequences assume the default (1,1) cursor. The snapshot drains chunks
	// already queued on the live channel, so nothing renders twice.
	replay, live := sess.SnapshotForAttach()
	if len(replay) > 0 {
		wctx, wcancel := context.WithTimeout(ctx, wsTimeout)
		err := conn.Write(wctx, websocket.MessageBinary, replay)
		wcancel()
		if err != nil {
			logger.Debug("replay write failed", "error", err)
		}
	}

	// Goroutine: live session stdout -> WebSocket.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case data, ok := <-live:
				if !ok {
					_ = conn.Close(websocket.StatusNormalClosure, "session ended")
					return
				}
				wctx, wcancel := context.WithTimeout(ctx, wsTimeout)
				err := conn.Write(wctx, websocket.MessageBinary, data)
				wcancel()
				if err != nil {
					return
				}
			}
		}
	}()

	// Session exit -> close WebSocket. Exited is closed exactly once by the
	// session handler (or UnregisterAgent).
	go func() {
		select {
		case <-ctx.Done():
		case <-sess.ExitedChan():
			_ = conn.Close(websocket.StatusNormalClosure, "session ended")
		}
	}()

	// Read loop: WebSocket -> session stdin/resize.
	for {
		rctx, rcancel := context.WithTimeout(ctx, wsTimeout)
		typ, data, err := conn.Read(rctx)
		rcancel()
		if err != nil {
			break
		}

		switch typ {
		case websocket.MessageBinary:
			sess.SendStdin(data)
		case websocket.MessageText:
			t.handleControlMessage(logger, sess, data)
		}
	}
}

// authorizeAttach allows the session's initiator always, and any other
// principal who holds daemons.edit in the daemon's workspace (every daemon
// is enrolled into a workspace). It runs before the WebSocket upgrade so
// rejections stay plain HTTP responses.
func (t *TerminalHandler) authorizeAttach(
	w http.ResponseWriter,
	r *http.Request,
	sess *daemon.Session,
) bool {
	actor, ok := iam.PrincipalFromContext(r.Context())
	if !ok || actor.ID == "" {
		writeJSONError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	if actor.Kind == iam.KindUser && sess.UserID() == actor.ID {
		return true
	}

	// Pre-authorization lookup: the daemon's workspace cannot be pinned before
	// the request is authorized, so it runs on the admin pool.
	var workspaceID string
	err := t.cfg.Conn.AdminPool.QueryRow(
		r.Context(),
		`SELECT workspace_id FROM daemons WHERE id = $1`,
		sess.DaemonID(),
	).Scan(&workspaceID)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "permission denied")
		return false
	}

	// Same role resolution the RPC authorization interceptor uses.
	role, err := actorRole(r.Context(), t.cfg.Conn.AdminPool, workspaceID, actor.ID)
	if err != nil || !db.HasPermission(role, db.PermDaemonsEdit) {
		writeJSONError(w, http.StatusForbidden, "permission denied")
		return false
	}
	return true
}

func (t *TerminalHandler) handleControlMessage(
	logger *slog.Logger,
	sess *daemon.Session,
	data []byte,
) {
	var msg struct {
		Type string `json:"type"`
		Cols uint32 `json:"cols"`
		Rows uint32 `json:"rows"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		logger.Debug("invalid control message", "error", err)
		return
	}
	if msg.Type == "resize" {
		sess.SendResize(msg.Cols, msg.Rows)
	}
}
