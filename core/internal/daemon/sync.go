package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/core/internal/db"
)

type SyncInput struct {
	DaemonID    string
	Version     string
	ReqMetadata map[string]string
	Users       []string
	PrivateIPs  []string
}

type Synced struct {
	Version     int64
	Status      *nokkuv1.DaemonStatus
	Config      *nokkuv1.DaemonConfig
	Principals  []*nokkuv1.AccountPrincipals
	CAPublicKey string
	RetiredCAs  []*nokkuv1.RetiredCAKey
	// HostCAPublicKey is the key the daemon's host certificate has to come from.
	HostCAPublicKey string
}

// Sync answers a server with what it may trust, then saves what the server reported about itself. The save runs on
// its own, a failed one never keeps a server from its principal list.
func Sync(ctx context.Context, conn connection, in SyncInput) (*Synced, error) {
	res := &Synced{}
	var targetID string
	err := conn.TenantTx(ctx, func(q *db.Queries) error {
		daemon, err := q.GetDaemon(ctx, in.DaemonID)
		if err != nil {
			return err
		}
		res.Status = &daemon.Status
		res.Config = daemon.EffectiveConfig()

		// Pending daemons keep retrying, rejected ones are told to stop.
		if daemon.Status != nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
			return nil
		}

		workspace, err := q.GetWorkspace(ctx)
		if err != nil {
			return err
		}
		// Zero is off, which is what an unset field says too.
		if idle := workspace.Settings.GetSessionIdleTimeout(); idle.AsDuration() > 0 {
			res.Config.IdleTimeout = idle
		}

		// Read the version first, so a change in between costs one extra sync instead of a stale daemon.
		res.Version, err = q.GetWorkspaceStateVersion(ctx, daemon.WorkspaceID)
		if err != nil {
			return err
		}

		target, err := q.GetTargetByDaemon(ctx, &daemon.ID)
		if err != nil {
			return err
		}
		targetID = target.ID

		ca, err := q.GetDaemonCAKeys(ctx, &daemon.ID)
		if err != nil {
			return err
		}
		res.CAPublicKey = ca.PublicKey
		res.HostCAPublicKey = ca.HostPublicKey
		if ca.PreviousPublicKey != nil && ca.PreviousTrustedUntil != nil &&
			time.Now().Before(*ca.PreviousTrustedUntil) {
			res.RetiredCAs = []*nokkuv1.RetiredCAKey{{
				PublicKey:    ca.PreviousPublicKey,
				TrustedUntil: timestamppb.New(*ca.PreviousTrustedUntil),
			}}
		}

		result, err := q.ListAccountSubjectsForTarget(ctx, target.ID)
		if err != nil {
			return err
		}
		// The host compares these as they are, see login.Principal.
		for _, p := range result {
			principals := make([]string, 0, len(p.Ids))
			for _, id := range p.Ids {
				principals = append(principals, login.Principal(id, target.ID, p.Username))
			}
			res.Principals = append(res.Principals, &nokkuv1.AccountPrincipals{
				Username:       &p.Username,
				CertPrincipals: principals,
			})
		}

		return nil
	})
	// A deleted daemon still serves its cached principals. REJECTED makes the host drop them.
	if errors.Is(err, pgx.ErrNoRows) {
		if err := conn.TenantTx(ctx, func(q *db.Queries) error {
			_, err := q.DeleteSubjectTokens(ctx, in.DaemonID)
			return err
		}); err != nil {
			return nil, err
		}
		return &Synced{Status: new(nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED)}, nil
	}
	if err != nil {
		return nil, err
	}
	if targetID != "" {
		if err := saveReport(ctx, conn, in, targetID); err != nil {
			slog.Warn("server report not saved", "daemon_id", in.DaemonID, "error", err)
		}
	}
	return res, nil
}

// saveReport keeps what the host said about itself. An account it adds has no grants yet, so the principal list
// read before never misses one.
func saveReport(ctx context.Context, conn connection, in SyncInput, targetID string) error {
	targetMeta, err := json.Marshal(in.ReqMetadata)
	if err != nil {
		return err
	}
	return conn.TenantTx(ctx, func(q *db.Queries) error {
		// Never write status here, the combined update would clobber an admin's accept or reject.
		if err := q.UpdateDaemonVersion(ctx, &db.UpdateDaemonVersionParams{
			DaemonID: in.DaemonID,
			Version:  in.Version,
		}); err != nil {
			return err
		}
		if err := q.UpdateTargetReport(ctx, &db.UpdateTargetReportParams{
			TargetID:  targetID,
			Metadata:  targetMeta,
			Endpoints: validEndpoints(in.PrivateIPs),
		}); err != nil {
			return err
		}
		// Never deletes, a host that cannot enumerate users must not change who has access.
		return q.InsertTargetAccounts(ctx, &db.InsertTargetAccountsParams{
			TargetID:    targetID,
			Usernames:   ValidUsers(in.Users),
			MaxAccounts: db.MaxTargetAccounts,
		})
	})
}

// ValidUsers drops per entry, a host with one odd account must still sync.
func ValidUsers(names []string) []string {
	return slices.DeleteFunc(slices.Clone(names), func(name string) bool {
		return !login.ValidUsername(name)
	})
}

// validEndpoints keeps what a daemon can listen on, an ip:port. Nil keeps the stored endpoints.
func validEndpoints(endpoints []string) []string {
	valid := slices.DeleteFunc(slices.Clone(endpoints), func(ep string) bool {
		_, err := netip.ParseAddrPort(ep)
		return err != nil
	})
	if len(valid) == 0 {
		return nil
	}
	return valid
}
