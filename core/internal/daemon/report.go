package daemon

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
	"uuid"

	"golang.org/x/time/rate"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

const (
	// One daemon's connection events are stored this fast. Past the burst the daemon waits for its ack, so a flood
	// from one server fills that server's spool and not the audit log.
	reportRate  = 20
	reportBurst = 200
	// A daemon may send any length, the log keeps this much of a field.
	maxReportField = 256
	// Well inside the ten seconds the audit stream waits for rows that are stamped but not yet committed.
	reportStoreTimeout = 5 * time.Second

	actionConnectionOpen  = "ConnectionOpen"
	actionConnectionClose = "ConnectionClose"
	actionReportsDropped  = "ConnectionReportsDropped"
)

// reportLimit outlives the stream, or every reconnect would be a new burst.
func (p *Pool) reportLimit(daemonID string) *rate.Limiter {
	p.reportMu.Lock()
	defer p.reportMu.Unlock()
	l := p.reportLimits[daemonID]
	if l == nil {
		l = rate.NewLimiter(reportRate, reportBurst)
		p.reportLimits[daemonID] = l
	}
	return l
}

// storeReport writes a daemon's connection events into the audit log, all or none. The daemon is the actor, as the
// one who says so, and the event is about the subject in the principal. Root on a server can make its daemon say
// anything, so such a row must never read like something the core saw itself.
func (p *Pool) storeReport(ctx context.Context, daemon *db.GetDaemonRow, report *nokkuv1.ConnectionReport) error {
	reported := report.GetEvents()
	if len(reported) == 0 {
		return nil
	}
	if err := p.reportLimit(daemon.Daemon.ID).WaitN(ctx, len(reported)); err != nil {
		return err
	}

	event := func(kind, connectionID, action, target string, details map[string]any) *audit.Event {
		e := &audit.Event{
			ID:          reportID(daemon.Daemon.ID, kind, connectionID),
			WorkspaceID: daemon.Daemon.WorkspaceID,
			ActorID:     daemon.Daemon.ID,
			ActorKind:   string(actor.KindDaemon),
			ActorName:   daemon.Name,
			Action:      action,
			Target:      target,
			OK:          true,
			Details:     details,
		}
		if meta, ok := actor.RequestMetaFromContext(ctx); ok {
			e.IP, e.UserAgent = meta.ClientIP(), meta.UserAgent()
		}
		return e
	}

	var subjects []string
	events := make([]*audit.Event, 0, len(reported)+1)
	for _, r := range reported {
		details := map[string]any{
			"connection_id": r.GetConnectionId(),
			"target":        daemon.Name,
			"key_id":        cutField(r.GetKeyId()),
			"remote":        cutField(r.GetRemoteAddr()),
			"client":        cutField(r.GetClientVersion()),
		}
		if r.GetRelayed() {
			details["relayed"] = true
		}
		// The row's own time is when the core stored it. A daemon that was cut off reports late.
		if r.GetTime() != nil {
			details["at"] = r.GetTime().AsTime()
		}
		kind, action := "open", actionConnectionOpen
		if r.GetClosed() {
			kind, action = "close", actionConnectionClose
		}
		parts, ok := login.ParsePrincipal(r.GetPrincipal())
		if ok {
			details["username"] = parts.Username
			subjects = append(subjects, parts.SubjectID)
		} else {
			// The core signs no such principal. Kept as sent, so it can be looked into.
			details["principal"] = cutField(r.GetPrincipal())
		}
		events = append(events, event(kind, r.GetConnectionId(), action, parts.SubjectID, details))
	}
	if n := report.GetDropped(); n > 0 {
		events = append(events, event("dropped", reported[0].GetConnectionId(), actionReportsDropped,
			daemon.Daemon.ID, map[string]any{"name": daemon.Name, "count": n}))
	}

	ctx, cancel := context.WithTimeout(ctx, reportStoreTimeout)
	defer cancel()
	return p.conn.TenantTx(ctx, func(q *db.Queries) error {
		// The name as of now. An id that names nobody here stays without one.
		names, err := q.GetNames(ctx, subjects)
		if err != nil {
			return err
		}
		named := make(map[string]string, len(subjects))
		for i, id := range subjects {
			named[id] = names[i]
		}
		for _, e := range events {
			if name := named[e.Target]; name != "" {
				e.Details["subject"] = name
			}
			if err := audit.Insert(ctx, q, e); err != nil {
				return err
			}
		}
		return nil
	})
}

// reportID gives an event the same row id every time it is reported, so a report that comes twice is stored once.
// The core makes the id, a daemon cannot pick the row it writes.
func reportID(daemonID, kind, connectionID string) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "connection report\n%s\n%s\n%s", daemonID, kind, connectionID))
	id := uuid.UUID(sum[:16])
	// Version 8 and the RFC 9562 variant, an id of the application's own making.
	id[6] = id[6]&0x0f | 0x80
	id[8] = id[8]&0x3f | 0x80
	return id.String()
}

func cutField(s string) string {
	if len(s) > maxReportField {
		s = s[:maxReportField]
	}
	return strings.ToValidUTF8(s, "")
}
