package audit

import (
	"context"
	"encoding/json"

	"github.com/nokku-sh/nokku/internal/db"
)

// Sink is where audit events land. The service fans every event out to each
// configured sink, so a new destination is one implementation of this
// interface and nothing else changes. PostgresSink is the durable record,
// WebhookSink streams a copy to a per-workspace destination.
//
// A sink that talks to the network must run with its own queue and retry off
// the request path, and never fail the caller, because a slow or dead
// destination must not stall a login. Event is already the wire format, one
// JSON object per event, the same shape the workspace activity feed shows.
type Sink interface {
	Append(ctx context.Context, event *Event) error
}

// PostgresSink writes events to audit.audit_logs as the app role. The table is
// append-only by grant and by trigger, so this insert is the only write path
// that exists.
type PostgresSink struct {
	q db.Querier
}

var _ Sink = (*PostgresSink)(nil)

func NewPostgresSink(conn *db.Connection) *PostgresSink {
	return &PostgresSink{q: conn.Sys()}
}

// Append inserts one event. It is a dumb pipe: it marshals whatever it is
// handed and inserts it as nokku_system. The app role has no insert policy,
// so tenant transactions cannot write audit rows.
func (s *PostgresSink) Append(ctx context.Context, event *Event) error {
	if event == nil {
		return nil
	}

	details, err := json.Marshal(event.Details)
	if err != nil {
		return err
	}
	// marshal(nil) yields "null", the column wants an object.
	if string(details) == "null" {
		details = []byte("{}")
	}

	var workspaceID *string
	if event.WorkspaceID != "" {
		workspaceID = &event.WorkspaceID
	}
	return s.q.InsertAuditLog(ctx, &db.InsertAuditLogParams{
		WorkspaceID: workspaceID,
		ActorID:     event.ActorID,
		ActorKind:   event.ActorKind,
		ActorName:   event.ActorName,
		Action:      event.Action,
		Target:      event.Target,
		Ok:          event.OK,
		Ip:          event.IP,
		UserAgent:   event.UserAgent,
		Details:     details,
	})
}
