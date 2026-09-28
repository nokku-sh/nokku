package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/util"
)

// Record satisfies iam.Sink: it converts an iam authentication event into a
// generic audit Event and appends it to the log. Auth events are the only
// audit trail for the /auth routes (the HTTP access-log writer skips them),
// so they carry the transport facts too: IP and user agent come from the
// request metadata the iam middleware planted.
func (s *Service) Record(ctx context.Context, e iam.Event) {
	event := eventFromIAM(e)
	if meta, ok := iam.RequestMetaFromContext(ctx); ok {
		event.IP = util.SanitizeUTF8(util.GetRemoteIP(meta.Header, meta.RemoteAddr))
		event.UserAgent = util.SanitizeUTF8(meta.Header.Get("User-Agent"))
	}

	// Never block the auth flow: the insert runs detached from the request
	// context so a slow DB cannot stall a login. cancel moves into the
	// goroutine: calling it on return from Record would cancel the context
	// out from under the insert.
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	go func() {
		defer cancel()
		if err := s.Append(actx, event); err != nil {
			slog.Warn("failed to write auth audit log", "action", e.Action, "error", err)
		}
	}()
}

// eventFromIAM maps an iam auth event to a generic audit Event. Actor
// fields are written verbatim: events that resolved no account stay empty.
func eventFromIAM(e iam.Event) *Event {
	details := map[string]any{}
	if e.Method != "" {
		details["method"] = string(e.Method)
	}
	if e.Detail != "" {
		details["detail"] = e.Detail
	}
	return &Event{
		Timestamp:   time.Now().UTC(),
		WorkspaceID: e.WorkspaceID,
		Action:      string(e.Action),
		ActorID:     e.UserID,
		ActorKind:   string(e.Kind),
		ActorName:   e.Email,
		OK:          e.Action != iam.ActionLoginDenied,
		Details:     details,
	}
}
