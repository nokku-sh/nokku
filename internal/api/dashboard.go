package api

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
)

const (
	dashboardListCap    = 5
	dashboardChangesCap = 8
)

// routineActions happen on every login or session, they would drown the
// changes an operator actually wants to see.
var routineActions = []string{
	"SignSSHCertificate",
	"SignX509Certificate",
	"CreateSession",
	"CloseSession",
	"UploadRecording",
	"SyncTargetUsers",
}

type DashboardService struct {
	cfg *config.Config
}

func NewDashboardService(cfg *config.Config) *DashboardService {
	return &DashboardService{cfg: cfg}
}

func (s *DashboardService) GetDashboard(
	ctx context.Context,
	req *nokkuv1.GetDashboardRequest,
) (*nokkuv1.GetDashboardResponse, error) {
	wsID := req.GetWorkspaceId()
	now := time.Now()
	seenAfter := now.Add(-db.DaemonOnlineWindow)
	since := now.Truncate(time.Hour).Add(-23 * time.Hour)

	var (
		counts     *db.DashboardCountsRow
		daemons    []*db.ListDaemonsRow
		cas        []*db.CertificateAuthority
		recordings []*db.ListOpenRecordingsRow
		hours      []*db.AuditActivityByHourRow
		usedBytes  int64
	)
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		if counts, err = q.DashboardCounts(ctx, &db.DashboardCountsParams{
			WorkspaceID: wsID,
			SeenAfter:   seenAfter,
		}); err != nil {
			return err
		}
		if daemons, err = q.ListDaemons(ctx, &db.ListDaemonsParams{
			WorkspaceID: wsID,
			SeenAfter:   seenAfter,
		}); err != nil {
			return err
		}
		if cas, err = q.ListSoonestCAs(ctx, wsID); err != nil {
			return err
		}
		if recordings, err = q.ListOpenRecordings(ctx, &db.ListOpenRecordingsParams{
			WorkspaceID: wsID,
			SeenAfter:   seenAfter,
		}); err != nil {
			return err
		}
		if hours, err = q.AuditActivityByHour(ctx, &db.AuditActivityByHourParams{
			WorkspaceID: &wsID,
			Since:       since,
		}); err != nil {
			return err
		}
		usedBytes, err = q.SumRecordingBytes(ctx, wsID)
		return err
	}); err != nil {
		return nil, err
	}

	res := &nokkuv1.GetDashboardResponse{
		Targets:             &counts.Targets,
		TargetsOnline:       &counts.TargetsOnline,
		TargetsManual:       &counts.TargetsManual,
		Members:             &counts.Members,
		Daemons:             new(int32(len(daemons))), //nolint:gosec // a workspace has far fewer daemons
		RecordingBytes:      &usedBytes,
		RecordingQuotaBytes: new(s.cfg.Entitlements.RecordingStorageBytes(ctx, wsID)),
		SoonestCas:          db.CAsToProto(cas),
		Activity:            make([]int32, 24),
		Failures:            make([]int32, 24),
	}

	var online int32
	for _, row := range daemons {
		d := &row.Daemon
		switch {
		case d.Status == nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING:
			res.PendingDaemons = append(res.PendingDaemons, d.ToProto())
		case db.SeenRecently(d.LastSeenAt):
			online++
		case d.Status == nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED:
			res.OfflineDaemons = append(res.OfflineDaemons, d.ToProto())
		}
	}
	res.DaemonsOnline = &online
	// ListDaemons sorts by uuidv7 id, so the newest pending daemons are last.
	slices.Reverse(res.GetPendingDaemons())
	res.PendingDaemons = res.GetPendingDaemons()[:min(len(res.GetPendingDaemons()), dashboardListCap)]
	res.OfflineDaemons = res.GetOfflineDaemons()[:min(len(res.GetOfflineDaemons()), dashboardListCap)]

	for _, h := range hours {
		i := int(h.Hour.Sub(since) / time.Hour)
		if i < 0 || i >= 24 {
			continue
		}
		res.Activity[i], res.Failures[i] = h.Events, h.Failures
	}

	res.LiveSessions = s.liveSessions(daemons, recordings)
	res.RecentChanges = s.recentChanges(ctx, wsID, now.Add(-24*time.Hour))
	return res, nil
}

// liveSessions merges browser terminals with open recordings. A recorded
// browser terminal shows up in both, so the recording marks it instead.
func (s *DashboardService) liveSessions(
	daemons []*db.ListDaemonsRow,
	recordings []*db.ListOpenRecordingsRow,
) []*nokkuv1.LiveSession {
	names := make(map[string]string, len(daemons))
	var live []*nokkuv1.LiveSession
	for _, row := range daemons {
		names[row.Daemon.ID] = row.Daemon.Name
		for _, ws := range s.cfg.Pool.ListSessions(row.Daemon.ID) {
			live = append(live, &nokkuv1.LiveSession{
				Id:         ws.SessionId,
				DaemonId:   &row.Daemon.ID,
				DaemonName: &row.Daemon.Name,
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
func (s *DashboardService) recentChanges(
	ctx context.Context,
	wsID string,
	since time.Time,
) []*nokkuv1.EventLog {
	events, _, err := s.cfg.Audit.List(ctx, &db.ListAuditLogsParams{
		WorkspaceID: &wsID,
		Outcome:     new("succeeded"),
		StartDate:   &since,
		Limit:       50,
	})
	if err != nil {
		slog.Error("dashboard recent changes", "workspace_id", wsID, "error", err)
		return nil
	}
	var logs []*nokkuv1.EventLog
	for _, e := range events {
		if slices.Contains(routineActions, e.Action) {
			continue
		}
		logs = append(logs, e.ToProto())
		if len(logs) == dashboardChangesCap {
			break
		}
	}
	return logs
}
