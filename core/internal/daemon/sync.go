package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

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

// Sync saves the report on its own, a failure never costs the principal list.
func Sync(ctx context.Context, conn connection, in SyncInput) (*nokkuv1.SyncDaemonResponse, error) {
	var res *nokkuv1.SyncDaemonResponse
	var targetID string
	err := conn.TenantTx(ctx, func(q *db.Queries) error {
		row, err := q.GetDaemon(ctx, in.DaemonID)
		// A deleted daemon still serves its cached principals, REJECTED makes
		// the host drop them. Its token stays until it expires, so a lost
		// answer comes again, and nothing else takes it.
		if errors.Is(err, pgx.ErrNoRows) {
			res, err = answer(nil, nil, nil, nil)
			return err
		}
		if err != nil {
			return err
		}
		daemon := &row.Daemon
		// Pending daemons keep retrying, rejected ones are told to stop.
		if daemon.Status != nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
			res, err = answer(daemon, nil, nil, nil)
			return err
		}

		workspace, err := q.GetWorkspace(ctx)
		if err != nil {
			return err
		}
		target, err := q.GetTargetByDaemon(ctx, &daemon.ID)
		if err != nil {
			return err
		}
		targetID = target.ID
		ca, err := q.GetWorkspaceCA(ctx)
		if err != nil {
			return err
		}
		accounts, err := q.ListAccountSubjectsForTarget(ctx, target.ID)
		if err != nil {
			return err
		}
		principals := make([]*nokkuv1.AccountPrincipals, 0, len(accounts))
		for _, a := range accounts {
			principals = append(principals, accountPrincipals(target.ID, a.Username, a.Ids))
		}
		res, err = answer(daemon, workspace.Settings, ca, principals)
		return err
	})
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

// Hashes is the pass over a workspace: the hash of what each of its daemons would be told right now, by id. One
// transaction, and every answer built the way Sync builds it.
func Hashes(ctx context.Context, conn connection) (map[string][]byte, error) {
	hashes := map[string][]byte{}
	err := conn.TenantTx(ctx, func(q *db.Queries) error {
		workspace, err := q.GetWorkspace(ctx)
		if err != nil {
			return err
		}
		ca, err := q.GetWorkspaceCA(ctx)
		if err != nil {
			return err
		}
		daemons, err := q.ListDaemonsForSync(ctx)
		if err != nil {
			return err
		}
		accounts, err := q.ListAccountSubjects(ctx)
		if err != nil {
			return err
		}
		principals := map[string][]*nokkuv1.AccountPrincipals{}
		for _, a := range accounts {
			principals[a.TargetID] = append(principals[a.TargetID], accountPrincipals(a.TargetID, a.Username, a.Ids))
		}
		for _, d := range daemons {
			res, err := answer(&d.Daemon, workspace.Settings, ca, principals[d.TargetID])
			if err != nil {
				return err
			}
			hashes[d.Daemon.ID] = res.GetStateHash()
		}
		return nil
	})
	return hashes, err
}

// answer is what one daemon is told to enforce, with its hash. A daemon that is gone is nil, and one that is not
// accepted gets no CA and nobody to let in.
func answer(
	daemon *db.Daemon,
	settings *nokkuv1.WorkspaceSettings,
	ca *db.SSHCA,
	principals []*nokkuv1.AccountPrincipals,
) (*nokkuv1.SyncDaemonResponse, error) {
	res := &nokkuv1.SyncDaemonResponse{Status: new(nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED)}
	if daemon != nil {
		res.Status = &daemon.Status
		res.Config = daemon.EffectiveConfig()
	}
	if daemon != nil && daemon.Status == nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
		// Zero is off, which is what an unset field says too.
		if idle := settings.GetSessionIdleTimeout(); idle.AsDuration() > 0 {
			res.Config.IdleTimeout = idle
		}
		res.CaPublicKey = &ca.PublicKey
		res.HostCaPublicKey = &ca.HostPublicKey
		res.Principals = principals
	}
	// Deterministic for one build of the core. A new build may hash the same answer anew, which costs one sync.
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(res)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(wire)
	res.StateHash = sum[:]
	return res, nil
}

// The host compares these as they are, see login.Principal.
func accountPrincipals(targetID, username string, subjects []string) *nokkuv1.AccountPrincipals {
	principals := make([]string, 0, len(subjects))
	for _, id := range subjects {
		principals = append(principals, login.Principal(id, targetID, username))
	}
	return &nokkuv1.AccountPrincipals{Username: &username, CertPrincipals: principals}
}

// An account saved here has no grants yet, so the list read before misses none.
func saveReport(ctx context.Context, conn connection, in SyncInput, targetID string) error {
	targetMeta, err := json.Marshal(in.ReqMetadata)
	if err != nil {
		return err
	}
	return conn.TenantTx(ctx, func(q *db.Queries) error {
		// Never write status here, that would clobber an admin's decision.
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
		// Never deletes, a host that can't list users must not change access.
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

// validEndpoints keeps only ip:port. Nil keeps the stored endpoints.
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
