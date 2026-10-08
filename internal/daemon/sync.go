package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/internal/db"
	nokkussh "github.com/nokku-sh/nokku/internal/ssh"
)

type SyncInput struct {
	DaemonID    string
	Metadata    []byte
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
}

func Sync(ctx context.Context, conn connection, in SyncInput) (*Synced, error) {
	res := &Synced{}
	err := conn.TenantTx(ctx, func(q *db.Queries) error {
		daemon, err := q.GetDaemon(ctx, in.DaemonID)
		if err != nil {
			return err
		}
		res.Status = &daemon.Status
		res.Config = db.ResolveDaemonConfig(daemon.Config)

		// Pending daemons keep retrying, rejected ones are told to stop.
		if daemon.Status != nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
			return nil
		}

		// Read the version first, so a change in between costs one extra
		// sync instead of a stale daemon.
		res.Version, err = q.GetWorkspaceStateVersion(ctx, daemon.WorkspaceID)
		if err != nil {
			return err
		}

		// Never write status here, the combined update would clobber an
		// admin's accept or reject with a zero value.
		if err := q.UpdateDaemonMetadata(ctx, &db.UpdateDaemonMetadataParams{
			DaemonID: daemon.ID,
			Metadata: in.Metadata,
		}); err != nil {
			return err
		}

		target, err := q.GetTargetByDaemon(ctx, &daemon.ID)
		if err != nil {
			return err
		}

		// The daemon trusts exactly what it gets here, so only a target
		// without a CA may answer empty. Any other failure fails the sync.
		ca, err := q.GetDaemonCAKeys(ctx, &daemon.ID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			res.CAPublicKey = ca.PublicKey
			if ca.PreviousPublicKey != nil && ca.PreviousTrustedUntil != nil &&
				time.Now().Before(*ca.PreviousTrustedUntil) {
				res.RetiredCAs = []*nokkuv1.RetiredCAKey{{
					PublicKey:    ca.PreviousPublicKey,
					TrustedUntil: timestamppb.New(*ca.PreviousTrustedUntil),
				}}
			}
		}

		targetMeta, err := json.Marshal(in.ReqMetadata)
		if err != nil {
			return err
		}
		if err := q.UpdateTargetReport(ctx, &db.UpdateTargetReportParams{
			TargetID:  target.ID,
			Metadata:  targetMeta,
			Endpoints: validEndpoints(in.PrivateIPs),
		}); err != nil {
			return err
		}

		// Never deletes, a host that cannot enumerate users must not change
		// who has access.
		if err := q.InsertTargetAccounts(ctx, &db.InsertTargetAccountsParams{
			TargetID:    target.ID,
			Usernames:   validUsers(in.Users),
			MaxAccounts: db.MaxTargetAccounts,
		}); err != nil {
			return err
		}

		result, err := q.ListAccountSubjectsForTarget(ctx, target.ID)
		if err != nil {
			return err
		}
		// The host compares these as they are, see ssh.LoginPrincipal.
		for _, p := range result {
			principals := make([]string, 0, len(p.Ids))
			for _, id := range p.Ids {
				principals = append(principals, nokkussh.LoginPrincipal(id, target.ID, p.Username))
			}
			res.Principals = append(res.Principals, &nokkuv1.AccountPrincipals{
				Username:       &p.Username,
				CertPrincipals: principals,
			})
		}

		return nil
	})
	// A deleted daemon still serves its cached principals. REJECTED makes
	// the host drop them, and its session is spent with that answer.
	if errors.Is(err, pgx.ErrNoRows) {
		if err := conn.TenantTx(ctx, func(q *db.Queries) error {
			_, err := q.DeleteSubjectSessions(ctx, in.DaemonID)
			return err
		}); err != nil {
			return nil, err
		}
		return &Synced{Status: new(nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED)}, nil
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

// usernameRE is the username pattern of the protos, keep them in sync.
var usernameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]*\$?$`)

// validUsers drops the names nokkud would refuse as a login anyway. The
// report is dropped per entry, a host with one odd account must still sync.
func validUsers(names []string) []string {
	return slices.DeleteFunc(slices.Clone(names), func(name string) bool {
		return len(name) > 32 || !usernameRE.MatchString(name)
	})
}

// validEndpoints keeps what a daemon can listen on, an ip:port. Nil keeps
// the stored endpoints.
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
