package audit

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/nokku-sh/nokku/internal/db"
)

// sink implementations that talk to the network must queue and retry off the
// request path, a dead destination must not stall a login.
type sink interface {
	Append(ctx context.Context, event *Event) error
}

// postgresSink is the durable record.
type postgresSink struct {
	q *db.Queries
}

var _ sink = (*postgresSink)(nil)

func newPostgresSink(conn *db.Connection) *postgresSink {
	return &postgresSink{q: conn.Sys()}
}

// Append runs as nokku_system, tenant transactions cannot write audit rows.
func (s *postgresSink) Append(ctx context.Context, event *Event) error {
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

	if event.WorkspaceID == "" {
		return errors.New("audit event without a workspace")
	}
	return s.q.InsertAuditLog(ctx, &db.InsertAuditLogParams{
		WorkspaceID: event.WorkspaceID,
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
