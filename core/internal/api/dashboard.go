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

// routineActions happen on every login or session, they would drown the changes an operator wants to see.
var routineActions = []string{
	"Login",
	"SessionIssued",
	"SignSSHCertificate",
	"CreateSession",
	"CloseSession",
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
	seenAfter := now.Add(-db.DaemonOnlineWindow)
	since := now.Truncate(time.Hour).Add(-23 * time.Hour)

	var (
		counts     *db.DashboardCountsRow
		pending    []*db.Daemon
		offline    []*db.Daemon
		terminals  []*db.GetDaemonsByIDsRow
		recordings []*db.ListOpenRecordingsRow
		hours      []*db.AuditActivityByHourRow
		usedBytes  int64
	)
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		if counts, err = q.DashboardCounts(ctx, seenAfter); err != nil {
			return err
		}
		if pending, err = q.ListPendingDaemons(ctx); err != nil {
			return err
		}
		if offline, err = q.ListOfflineDaemons(ctx, seenAfter); err != nil {
			return err
		}
		// The pool holds the terminals of every workspace, the query keeps the daemons of this one.
		if ids := s.cfg.Pool.SessionDaemons(); len(ids) > 0 {
			if terminals, err = q.GetDaemonsByIDs(ctx, ids); err != nil {
				return err
			}
		}
		if recordings, err = q.ListOpenRecordings(ctx, seenAfter); err != nil {
			return err
		}
		if hours, err = q.AuditActivityByHour(ctx, since); err != nil {
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
		RecordingBytes:      &usedBytes,
		RecordingQuotaBytes: new(s.cfg.Entitlements.Resolve(ctx, wsID).RecordingStorageBytes),
		Activity:            make([]int32, 24),
		Failures:            make([]int32, 24),
	}
	for _, d := range pending {
		res.PendingDaemons = append(res.PendingDaemons, d.ToProto())
	}
	for _, d := range offline {
		res.OfflineDaemons = append(res.OfflineDaemons, d.ToProto())
	}

	for _, h := range hours {
		i := int(h.Hour.Sub(since) / time.Hour)
		if i < 0 || i >= 24 {
			continue
		}
		res.Activity[i], res.Failures[i] = h.Events, h.Failures
	}

	res.LiveSessions = s.liveSessions(terminals, recordings)
	res.RecentChanges = s.recentChanges(ctx, wsID, now.Add(-24*time.Hour))
	return res, nil
}

// liveSessions merges browser terminals with open recordings. A recorded terminal is in both, the recording marks it.
func (s *dashboardService) liveSessions(
	terminals []*db.GetDaemonsByIDsRow,
	recordings []*db.ListOpenRecordingsRow,
) []*nokkuv1.LiveSession {
	var live []*nokkuv1.LiveSession
	for _, d := range terminals {
		for _, ws := range s.cfg.Pool.ListSessions(d.ID) {
			live = append(live, &nokkuv1.LiveSession{
				Id:         ws.SessionId,
				DaemonId:   &d.ID,
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
