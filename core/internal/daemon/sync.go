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
	var accepted bool
	err := conn.TenantTx(ctx, func(q *db.Queries) error {
		row, err := q.GetDaemon(ctx, in.DaemonID)
		// A deleted daemon still serves its cached principals, the removed answer
		// makes the host drop them. Its token stays until it expires, so a lost
		// answer comes again, and nothing else takes it.
		if errors.Is(err, pgx.ErrNoRows) {
			res, err = answer(nil, nil, nil, nil)
			return err
		}
		if err != nil {
			return err
		}
		daemon := &row.Daemon
		// A pending daemon keeps retrying.
		if !daemon.Accepted {
			res, err = answer(daemon, nil, nil, nil)
			return err
		}

		workspace, err := q.GetWorkspace(ctx)
		if err != nil {
			return err
		}
		accepted = true
		ca, err := q.GetWorkspaceCA(ctx)
		if err != nil {
			return err
		}
		accounts, err := q.ListAccountSubjectsForTarget(ctx, daemon.TargetID)
		if err != nil {
			return err
		}
		principals := make([]*nokkuv1.AccountPrincipals, 0, len(accounts))
		for _, a := range accounts {
			principals = append(principals, accountPrincipals(daemon.TargetID, a.Username, a.Ids))
		}
		res, err = answer(daemon, workspace.Settings, ca, principals)
		return err
	})
	if err != nil {
		return nil, err
	}
	if accepted {
		if err := saveReport(ctx, conn, in); err != nil {
			slog.Warn("server report not saved", "daemon_id", in.DaemonID, "error", err)
		}
	}
	return res, nil
}

// Answers is what every daemon of the workspace is told, by id.
func Answers(ctx context.Context, conn connection) (map[string]*nokkuv1.SyncDaemonResponse, error) {
	answers := map[string]*nokkuv1.SyncDaemonResponse{}
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
			res, err := answer(d, workspace.Settings, ca, principals[d.TargetID])
			if err != nil {
				return err
			}
			answers[d.TargetID] = res
		}
		return nil
	})
	return answers, err
}

// answer is what one daemon is told to enforce, with its hash. A daemon that is gone is nil, and one that is not
// accepted gets no CA and nobody to let in.
func answer(
	daemon *db.Daemon,
	settings *nokkuv1.WorkspaceSettings,
	ca *db.SSHCA,
	principals []*nokkuv1.AccountPrincipals,
) (*nokkuv1.SyncDaemonResponse, error) {
	res := &nokkuv1.SyncDaemonResponse{}
	if daemon == nil {
		res.Removed = new(true)
	} else {
		res.Config = daemon.EffectiveConfig()
	}
	if daemon != nil && daemon.Accepted {
		// Zero is off, which is what an unset field says too.
		if idle := settings.GetSessionIdleTimeout(); idle.AsDuration() > 0 {
			res.IdleTimeout = idle
		}
		res.UserCaPublicKey = &ca.UserPublicKey
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
func saveReport(ctx context.Context, conn connection, in SyncInput) error {
	targetMeta, err := json.Marshal(in.ReqMetadata)
	if err != nil {
		return err
	}
	return conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := q.UpdateDaemonVersion(ctx, &db.UpdateDaemonVersionParams{
			TargetID: in.DaemonID,
			Version:  in.Version,
		}); err != nil {
			return err
		}
		if err := q.UpdateTargetReport(ctx, &db.UpdateTargetReportParams{
			TargetID:  in.DaemonID,
			Metadata:  targetMeta,
			Endpoints: validEndpoints(in.PrivateIPs),
		}); err != nil {
			return err
		}
		// Never deletes, a host that can't list users must not change access.
		return q.InsertTargetAccounts(ctx, &db.InsertTargetAccountsParams{
			TargetID:    in.DaemonID,
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
