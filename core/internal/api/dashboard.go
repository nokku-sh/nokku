package api

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
)

const dashboardChangesCap = 8

// routineActions happen on every login or session, drowning the real changes.
var routineActions = []string{
	"Login",
	"SessionIssued",
	"SignSSHCertificate",
	"CreateSession",
	"RelayOpen",
	"RelayClose",
	"UploadRecording",
	"GetRecording",
}

type dashboardService struct {
	cfg *config.Config
}

func (s *dashboardService) GetDashboard(
	ctx context.Context,
	_ *nokkuv1.GetDashboardRequest,
) (*nokkuv1.GetDashboardResponse, error) {
	wsID := actor.WorkspaceIDFromContext(ctx)
	now := time.Now()
	connected := s.cfg.Pool.ConnectedIn(wsID)
	since := now.Truncate(time.Hour).Add(-23 * time.Hour)

	var (
		counts     *db.DashboardCountsRow
		pending    []*db.ListPendingDaemonsRow
		offline    []*nokkuv1.Target
		terminals  []*db.GetDaemonsByIDsRow
		recordings []*db.ListOpenRecordingsRow
		hours      []*db.AuditActivityByHourRow
		ending     []*db.ListEndingGrantsRow
		usedBytes  int64
	)
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if counts, err = q.DashboardCounts(ctx, connected); err != nil {
			return err
		}
		if pending, err = q.ListPendingDaemons(ctx); err != nil {
			return err
		}
		rows, err := q.ListOfflineTargets(ctx, connected)
		if err != nil {
			return err
		}
		for _, r := range rows {
			offline = append(offline, r.Target.ToProto())
		}
		if err = withDaemons(ctx, q, s.cfg.Pool, offline); err != nil {
			return err
		}
		// The pool spans all workspaces, the query keeps this one's daemons.
		if ids := s.cfg.Pool.SessionDaemons(); len(ids) > 0 {
			if terminals, err = q.GetDaemonsByIDs(ctx, ids); err != nil {
				return err
			}
		}
		if recordings, err = q.ListOpenRecordings(ctx, connected); err != nil {
			return err
		}
		if hours, err = q.AuditActivityByHour(ctx, since); err != nil {
			return err
		}
		if ending, err = q.ListEndingGrants(ctx); err != nil {
			return err
		}
		usedBytes, err = q.SumRecordingBytes(ctx)
		return err
	}); err != nil {
		return nil, err
	}

	res := &nokkuv1.GetDashboardResponse{
		Targets:             &counts.Targets,
		TargetsOnline:       &counts.TargetsOnline,
		TargetsManual:       &counts.TargetsManual,
		Users:               &counts.Users,
		Daemons:             &counts.Daemons,
		DaemonsOnline:       &counts.DaemonsOnline,
		DaemonsBehind:       new(s.cfg.Pool.BehindIn(wsID)),
		RecordingBytes:      &usedBytes,
		RecordingQuotaBytes: new(s.cfg.Entitlements.Resolve(ctx, wsID).RecordingStorageBytes),
		Activity:            make([]int32, 24),
		Failures:            make([]int32, 24),
	}
	for _, d := range pending {
		res.PendingDaemons = append(res.PendingDaemons, d.Daemon.ToProto(d.Name, s.cfg.Pool.IsConnected(d.Daemon.ID)))
	}
	res.OfflineServers = offline

	for _, h := range hours {
		i := int(h.Hour.Sub(since) / time.Hour)
		if i < 0 || i >= 24 {
			continue
		}
		res.Activity[i], res.Failures[i] = h.Events, h.Failures
	}

	for _, g := range ending {
		res.EndingGrantsTotal = &g.Total
		res.EndingGrants = append(res.EndingGrants, endingGrant(g))
	}

	res.LiveSessions = s.liveSessions(terminals, recordings)
	res.RecentChanges = s.recentChanges(ctx, wsID, now.Add(-24*time.Hour))
	return res, nil
}

func endingGrant(g *db.ListEndingGrantsRow) *nokkuv1.EndingGrant {
	out := &nokkuv1.EndingGrant{
		SubjectKind: new(subjectKinds[g.SubjectKind]),
		SubjectId:   &g.SubjectID,
		SubjectName: &g.SubjectName,
		Username:    &g.Username,
		ExpiresAt:   timestamppb.New(g.ExpiresAt),
		TargetCount: &g.TargetCount,
	}
	for i, id := range g.TargetIds {
		out.Targets = append(out.Targets, &nokkuv1.EndingGrant_Target{Id: &id, Name: &g.TargetNames[i]})
	}
	return out
}

// liveSessions merges terminals and recordings, marking recorded terminals.
func (s *dashboardService) liveSessions(
	terminals []*db.GetDaemonsByIDsRow,
	recordings []*db.ListOpenRecordingsRow,
) []*nokkuv1.LiveSession {
	var live []*nokkuv1.LiveSession
	for _, d := range terminals {
		for _, ws := range s.cfg.Pool.ListSessions(d.Daemon.ID) {
			live = append(live, &nokkuv1.LiveSession{
				Id:         ws.SessionId,
				DaemonId:   &d.Daemon.ID,
				DaemonName: &d.Name,
				Username:   ws.Username,
				UserId:     ws.UserId,
				Web:        new(true),
			})
		}
	}

	for _, r := range recordings {
		i := slices.IndexFunc(live, func(l *nokkuv1.LiveSession) bool {
			return l.GetWeb() && !l.GetRecording() &&
				l.GetDaemonId() == r.DaemonID && l.GetUsername() == r.Username
		})
		if i >= 0 {
			live[i].Recording = new(true)
			live[i].StartedAt = timestamppb.New(r.StartedAt)
			continue
		}
		live = append(live, &nokkuv1.LiveSession{
			Id:         &r.ID,
			DaemonId:   &r.DaemonID,
			DaemonName: new(r.DaemonName),
			Username:   &r.Username,
			StartedAt:  timestamppb.New(r.StartedAt),
			Recording:  new(true),
		})
	}
	return live
}

// recentChanges is best effort, the dashboard still loads without it.
func (s *dashboardService) recentChanges(
	ctx context.Context,
	wsID string,
	since time.Time,
) []*nokkuv1.EventLog {
	events, _, err := s.cfg.Audit.List(ctx, &db.ListAuditLogsParams{
		ExcludedActions: routineActions,
		Outcome:         new("succeeded"),
		StartDate:       &since,
		Limit:           dashboardChangesCap,
	})
	if err != nil {
		slog.Error("dashboard recent changes", "workspace_id", wsID, "error", err)
		return nil
	}
	return eventLogs(events)
}
