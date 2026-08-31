package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/util"
)

// Record satisfies kagi.Sink: it converts a kagi authentication event into a
// generic audit Event and appends it to the log. Auth events are the only
// audit trail for the kagi routes (the HTTP access-log writer skips them), so
// they carry the transport facts too: IP and user agent come from the request
// identity the middleware planted.
func (s *Service) Record(ctx context.Context, e kagi.Event) {
	event := eventFromKagi(e)
	if id, ok := kagi.IdentityFromContext(ctx); ok && id.Meta != nil {
		event.IPAddress = util.SanitizeUTF8(util.GetRemoteIP(id.Meta.Header, id.Meta.RemoteAddr))
		event.UserAgent = util.SanitizeUTF8(id.Meta.Header.Get("User-Agent"))
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

// eventFromKagi maps a kagi auth event to a generic audit Event. Actor
// fields are written verbatim: events that resolved no account stay empty.
func eventFromKagi(e kagi.Event) *Event {
	details := map[string]any{}
	if e.Method != "" {
		details["method"] = string(e.Method)
	}
	if e.Provider != "" {
		details["provider"] = e.Provider
	}
	if e.Detail != "" {
		details["detail"] = e.Detail
	}

	ts := e.Time
	if ts.IsZero() {
		ts = time.Now()
	}

	// The status column is what the UI keys on to render success vs failure.
	// Success actions are "OK" to match the RPC convention; a denied login is
	// the notable failure and carries "denied".
	statusCode := "OK"
	if e.Action == kagi.ActionLoginDenied {
		statusCode = "denied"
	}

	return &Event{
		Timestamp:   ts.UTC(),
		WorkspaceID: string(e.TenantID),
		Action:      string(e.Action),
		ActorID:     e.UserID,
		ActorType:   string(e.Kind),
		ActorEmail:  e.Email,
		StatusCode:  statusCode,
		Details:     details,
	}
}
