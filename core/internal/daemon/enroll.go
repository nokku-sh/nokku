package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/namegen"
)

const maxNameAttempts = 5

// ErrEnrollToken never says which way the token was invalid.
var ErrEnrollToken = errors.New("invalid or expired enrollment token")

type EnrollInput struct {
	Token string
	// Binding is the DPoP key thumbprint.
	Binding  string
	Metadata []byte
	// ReqMetadata is the host's own report. Its hostname may become the daemon's name.
	ReqMetadata map[string]string
	// CanCreate only runs for new machines, so re-enrolling works at the cap.
	CanCreate func(ctx context.Context, workspaceID string) error
}

type Enrolled struct {
	DaemonID string
	Name     string
	TargetID string
	Status   nokkuv1.DaemonStatus
	Config   *nokkuv1.DaemonConfig
}

// Enroll checks the quota between its two transactions. Nested, parallel enrollments could exhaust the pool.
func Enroll(ctx context.Context, conn connection, in EnrollInput) (*Enrolled, error) {
	parsed, err := crypto.Parse(in.Token)
	if err != nil || parsed.ID == "" {
		return nil, ErrEnrollToken
	}
	hash := crypto.HashToken(in.Token)

	var (
		token     *db.JoinToken
		workspace *db.Workspace
		out       *Enrolled
	)
	err = conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		token, err = q.GetLiveJoinToken(ctx, &db.GetLiveJoinTokenParams{
			ID:        parsed.ID,
			Kind:      nokkuv1.JoinTokenKind_JOIN_TOKEN_KIND_ENROLL,
			TokenHash: hash,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrEnrollToken
		}
		if err != nil {
			return err
		}
		workspace, err = q.GetWorkspace(ctx)
		if err != nil {
			return err
		}
		out, err = enrolledDaemon(ctx, q, in.Binding)
		return err
	})
	if err != nil || out != nil {
		return out, err
	}

	// An ephemeral box that comes back under its name takes over from the one that went away. Before the
	// quota, since the old one frees what the new one takes.
	wanted, named := namegen.FromHostname(in.ReqMetadata["hostname"])
	if token.RetireAfter != nil && named {
		if err := replaceOffline(ctx, conn, token.ID, wanted); err != nil {
			return nil, err
		}
	}

	if in.CanCreate != nil {
		if err := in.CanCreate(ctx, token.WorkspaceID); err != nil {
			return nil, err
		}
	}

	status := nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING
	if token.AutoApprove {
		status = nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED
	}
	config := db.ResolveDaemonConfig(workspace.Settings.GetDefaultDaemonConfig())
	// The row carries it, see db.Daemon.EffectiveConfig.
	config.Ephemeral = nil
	report, err := json.Marshal(in.ReqMetadata)
	if err != nil {
		return nil, err
	}

	err = conn.TenantTx(ctx, func(q *db.Queries) error {
		for attempt := range maxNameAttempts {
			// A racing enrollment of the same key makes the insert a no-op.
			if out, err = enrolledDaemon(ctx, q, in.Binding); err != nil || out != nil {
				return err
			}
			// The hostname gets one try, a taken name returns no row and the generator takes over.
			name := namegen.Generate()
			if attempt == 0 && named {
				name = wanted
			}
			created, err := q.CreateDaemon(ctx, &db.CreateDaemonParams{
				Name:          name,
				Metadata:      in.Metadata,
				Status:        status,
				Config:        config,
				KeyThumbprint: &in.Binding,
				JoinTokenID:   &token.ID,
				RetireAfter:   token.RetireAfter,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			// A token that ran out meanwhile rolls the new daemon back.
			if _, err := q.RedeemJoinToken(ctx, &db.RedeemJoinTokenParams{
				ID:        parsed.ID,
				Kind:      nokkuv1.JoinTokenKind_JOIN_TOKEN_KIND_ENROLL,
				TokenHash: hash,
			}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrEnrollToken
				}
				return err
			}
			// A NULL CA falls back to the workspace default.
			if _, err := q.UpdateTargetCA(ctx, &db.UpdateTargetCAParams{
				DaemonID: &created.ID,
				CaID:     token.CaID,
			}); err != nil {
				return err
			}
			if err := seedTarget(ctx, q, token, created.TargetID, report); err != nil {
				return err
			}
			cfg := db.ResolveDaemonConfig(config)
			cfg.Ephemeral = new(token.RetireAfter != nil)
			out = &Enrolled{
				DaemonID: created.ID,
				Name:     created.Name,
				TargetID: created.TargetID,
				Status:   status,
				Config:   cfg,
			}
			return nil
		}
		return errors.New("could not find a free daemon name")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// seedTarget is the only place a token's tags and grants reach a target. A re-enroll never gets here.
func seedTarget(ctx context.Context, q *db.Queries, token *db.JoinToken, targetID string, report []byte) error {
	if err := q.UpdateTargetReport(ctx, &db.UpdateTargetReportParams{
		TargetID: targetID,
		Metadata: report,
	}); err != nil {
		return err
	}
	if len(token.Tags) > 0 {
		if _, err := q.UpdateTarget(ctx, &db.UpdateTargetParams{TargetID: targetID, Tags: token.Tags}); err != nil {
			return err
		}
	}
	return q.SeedTargetAccountsFromToken(ctx, &db.SeedTargetAccountsFromTokenParams{
		TokenID:  token.ID,
		TargetID: targetID,
	})
}

// replaceOffline deletes the daemon an ephemeral token enrolled under this name, if it is gone. A live one
// keeps its name and the newcomer gets a generated one.
func replaceOffline(ctx context.Context, conn connection, tokenID, name string) error {
	return conn.TenantTx(ctx, func(q *db.Queries) error {
		old, err := q.GetOfflineDaemonByTokenAndName(ctx, &db.GetOfflineDaemonByTokenAndNameParams{
			JoinTokenID: &tokenID,
			Name:        name,
			SeenBefore:  time.Now().Add(-db.DaemonOnlineWindow),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = q.DeleteDaemon(ctx, old.ID)
		return err
	})
}

// enrolledDaemon returns nil for an unknown key. The key is the machine's identity.
func enrolledDaemon(ctx context.Context, q *db.Queries, binding string) (*Enrolled, error) {
	d, err := q.GetDaemonByKeyThumbprint(ctx, &binding)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	target, err := q.GetTargetByDaemon(ctx, &d.ID)
	if err != nil {
		return nil, err
	}
	return &Enrolled{
		DaemonID: d.ID,
		Name:     d.Name,
		TargetID: target.ID,
		Status:   d.Status,
		Config:   d.EffectiveConfig(),
	}, nil
}
