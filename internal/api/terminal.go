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
