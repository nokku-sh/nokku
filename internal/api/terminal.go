package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/daemon"
	"github.com/nokku-sh/nokku/internal/db"
)

const wsReadLimit = 64 * 1024

type terminalHandler struct {
	cfg *config.Config
}

func newTerminalHandler(cfg *config.Config) *terminalHandler {
	return &terminalHandler{cfg: cfg}
}

func (t *terminalHandler) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	daemonID := r.URL.Query().Get("daemon_id")
	sessionID := r.URL.Query().Get("session_id")

	if daemonID == "" || sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "daemon_id and session_id are required")
		return
	}

	sess := t.cfg.Pool.GetSession(sessionID)
	if sess == nil || sess.DaemonID() != daemonID {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}
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

	// Reads have no timeout since an idle terminal sends nothing. Pings prove
	// the browser is still there.
	const wsTimeout = 15 * time.Second
	const wsPingEvery = 20 * time.Second
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

	logger := slog.With("session_id", sessionID, "daemon_id", daemonID)

	// No screen clear, replay sequences assume the default (1,1) cursor.
	replay, live := sess.SnapshotForAttach()
	if len(replay) > 0 {
		wctx, wcancel := context.WithTimeout(ctx, wsTimeout)
		err := conn.Write(wctx, websocket.MessageBinary, replay)
		wcancel()
		if err != nil {
			logger.Debug("replay write failed", "error", err)
		}
	}

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

	go func() {
		select {
		case <-ctx.Done():
		case <-sess.Exited():
			_ = conn.Close(websocket.StatusNormalClosure, "session ended")
		}
	}()

	for {
		typ, data, err := conn.Read(ctx)
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

// authorizeAttach allows the session's initiator and editors of the daemon's
// workspace. It runs before the upgrade so rejections stay plain HTTP.
func (t *terminalHandler) authorizeAttach(
	w http.ResponseWriter,
	r *http.Request,
	sess *daemon.Session,
) bool {
	caller, ok := actor.PrincipalFromContext(r.Context())
	if !ok || caller.ID == "" {
		writeJSONError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	if caller.Kind == actor.KindUser && sess.UserID() == caller.ID {
		return true
	}

	// The workspace can't be pinned before authorization, so use Sys.
	d, err := t.cfg.Conn.Sys().GetDaemon(r.Context(), sess.DaemonID())
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "permission denied")
		return false
	}
	role, err := t.cfg.Conn.Sys().GetActorRole(r.Context(), &db.GetActorRoleParams{
		WorkspaceID: d.WorkspaceID,
		ActorID:     caller.ID,
	})
	if err != nil || !db.Role(role).AtLeast(db.RoleEditor) {
		writeJSONError(w, http.StatusForbidden, "permission denied")
		return false
	}
	return true
}

func (t *terminalHandler) handleControlMessage(
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
