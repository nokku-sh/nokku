package audit

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/realip"
)

// Record is the only audit trail for the /auth routes, so it carries the
// transport facts too.
func (s *Service) Record(ctx context.Context, e iam.Event) {
	event := eventFromIAM(e)
	event.WorkspaceID = actor.WorkspaceIDFromContext(ctx)
	if event.WorkspaceID == "" {
		return
	}
	if meta, ok := iam.RequestMetaFromContext(ctx); ok {
		event.IP = strings.ToValidUTF8(realip.Bucket(meta.Header, meta.RemoteAddr), "")
		event.UserAgent = cut(strings.ToValidUTF8(meta.Header.Get("User-Agent"), ""), maxUserAgent)
	}

	// Detached so a slow DB cannot stall a login.
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	go func() {
		defer cancel()
		if err := s.Append(actx, event); err != nil {
			slog.Warn("failed to write auth audit log", "action", e.Action, "error", err)
		}
	}()
}

func eventFromIAM(e iam.Event) *Event {
	details := map[string]any{}
	if e.Method != "" {
		details["method"] = string(e.Method)
	}
	if e.Detail != "" {
		details["detail"] = e.Detail
	}
	return &Event{
		Timestamp: time.Now().UTC(),
		Action:    string(e.Action),
		ActorID:   e.UserID,
		ActorKind: string(e.Kind),
		ActorName: e.Email,
		OK:        e.Action != iam.ActionLoginDenied,
		Details:   details,
	}
}
