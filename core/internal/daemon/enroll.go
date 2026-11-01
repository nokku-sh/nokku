package daemon

import (
	"context"
	"encoding/json"
	"errors"

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
	Binding string
	Version string
	// ReqMetadata is the host's own report, its hostname may name the daemon.
	ReqMetadata map[string]string
	// CanCreate only runs for new machines, so re-enrolling works at the cap.
	CanCreate func(ctx context.Context, workspaceID string) error
	// An ephemeral enrollment never takes the name of a Connected daemon.
	Connected []string
}

type Enrolled struct {
	DaemonID string
	Name     string
	TargetID string
	Status   nokkuv1.DaemonStatus
	Config   *nokkuv1.DaemonConfig
}

// Enroll checks quota outside its transactions, nesting can exhaust the pool.
func Enroll(ctx context.Context, conn connection, in EnrollInput) (*Enrolled, error) {
	hash, ok := crypto.TokenHash(in.Token, crypto.TokenEnroll)
	if !ok {
		return nil, ErrEnrollToken
	}

	var (
		token     *db.JoinToken
		workspace *db.Workspace
		out       *Enrolled
	)
	err := conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		token, err = q.GetLiveJoinToken(ctx, hash)
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

	// A spent token still finds its daemons, it makes and replaces nothing.
	if token.MaxUses != nil && token.Uses >= *token.MaxUses {
		return nil, ErrEnrollToken
	}

	// A returning ephemeral box replaces its old self, which frees quota first.
	wanted, named := namegen.FromHostname(in.ReqMetadata["hostname"])
	if token.RetireAfter != nil && named {
		if err := replaceOffline(ctx, conn, token.ID, wanted, in.Connected); err != nil {
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
		if err := q.QuietStateChange(ctx); err != nil {
			return err
		}
		for attempt := range maxNameAttempts {
			// A racing enrollment of the same key makes the insert a no-op.
			if out, err = enrolledDaemon(ctx, q, in.Binding); err != nil || out != nil {
				return err
			}
			// A taken name returns no row, then the generator takes over.
			name := namegen.Generate()
			if attempt == 0 && named {
				name = wanted
			}
			created, err := q.CreateDaemon(ctx, &db.CreateDaemonParams{
				Name:          name,
				Version:       in.Version,
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
			if _, err := q.RedeemJoinToken(ctx, hash); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrEnrollToken
				}
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

// A token's tags and grants only reach a target here, never on a re-enroll.
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

// A live daemon keeps its name, the newcomer then gets a generated one.
func replaceOffline(ctx context.Context, conn connection, tokenID, name string, connected []string) error {
	return conn.TenantTx(ctx, func(q *db.Queries) error {
		if err := q.QuietStateChange(ctx); err != nil {
			return err
		}
		old, err := q.GetOfflineDaemonByTokenAndName(ctx, &db.GetOfflineDaemonByTokenAndNameParams{
			JoinTokenID: &tokenID,
			Name:        name,
			Connected:   connected,
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

// enrolledDaemon returns nil for an unknown key, the machine's identity.
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
