package audit

import (
	"context"
	"encoding/json"

	"github.com/nokku-sh/nokku/internal/db"
)

// Sink implementations that talk to the network must queue and retry off the
// request path, a dead destination must not stall a login.
type Sink interface {
	Append(ctx context.Context, event *Event) error
}

// PostgresSink is the durable record.
type PostgresSink struct {
	q db.Querier
}

var _ Sink = (*PostgresSink)(nil)

func NewPostgresSink(conn *db.Connection) *PostgresSink {
	return &PostgresSink{q: conn.Sys()}
}

// Append runs as nokku_system, tenant transactions cannot write audit rows.
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
