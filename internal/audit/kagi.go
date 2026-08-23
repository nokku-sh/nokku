package audit

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/mizuchilabs/kagi"
)

// Record satisfies kagi.Sink: it converts a kagi authentication event into a
// generic audit Event and appends it to the log. Auth events are always
// user-scoped and their tenant is the workspace the SSO flow resolved (empty
// for plain global logins). They carry no HTTP metadata, so the IP/user-agent/
// status fields are left empty; the semantic action (login_success, etc.) is
// what makes them a security trail.
func (s *Service) Record(ctx context.Context, e kagi.Event) {
	// Attribute the HTTP access-log row on this request context as well, not
	// just the semantic event. The handler resolves the user during the flow
	// (passkey/SSO/device), after the audit state was created, so mutating the
	// shared state here lets the async access-log writer see the actor. Login
	// denials without a known user stay anonymous.
	if e.UserID != "" {
		SetUserID(ctx, e.UserID)
	}

	event := eventFromKagi(e)

	// Never block the auth flow: the insert runs detached from the request
	// context so a slow DB cannot stall a login.
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	go func() {
		if err := s.Append(actx, event); err != nil {
			slog.Warn("failed to write auth audit log",
				"action", e.Action, "error_type", fmt.Sprintf("%T", err))
		}
	}()
}

// eventFromKagi maps a kagi auth event to a generic audit Event.
func eventFromKagi(e kagi.Event) *Event {
	actorID := e.UserID
	actorType := "user"
	if actorID == "" {
		actorID = anonActorID
		actorType = "anonymous"
	}

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
		ActorID:     actorID,
		ActorType:   actorType,
		StatusCode:  statusCode,
		Details:     details,
	}
}
