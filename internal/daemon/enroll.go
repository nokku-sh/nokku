package daemon

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/namegen"
)

const maxNameAttempts = 5

// ErrEnrollToken never says which way the token was invalid.
var ErrEnrollToken = errors.New("invalid or expired enrollment token")

type EnrollInput struct {
	Token string
	// Binding is the DPoP key thumbprint.
	Binding  string
	Metadata []byte
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

// Enroll runs pinned to the workspace of the host the daemon dialed, so a
// token of another workspace is never found. Only a new daemon spends a use.
// The quota check runs between the two transactions since nesting its own
// reads would let parallel enrollments exhaust the pool.
func Enroll(ctx context.Context, conn connection, in EnrollInput) (*Enrolled, error) {
	parsed, err := crypto.Parse(in.Token)
	if err != nil || parsed.ID == "" {
		return nil, ErrEnrollToken
	}
	hash := crypto.HashToken(in.Token)

	var (
		token     *db.WorkspaceToken
		workspace *db.Workspace
		out       *Enrolled
	)
	err = conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		token, err = q.GetLiveToken(ctx, &db.GetLiveTokenParams{
			ID:        parsed.ID,
			Kind:      nokkuv1.TokenKind_TOKEN_KIND_ENROLL,
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

	err = conn.WithWorkspace(ctx, func(q *db.Queries) error {
		for range maxNameAttempts {
			// A racing enrollment of the same key makes the insert a no-op.
			if out, err = enrolledDaemon(ctx, q, in.Binding); err != nil || out != nil {
				return err
			}
			// A taken name returns no row.
			created, err := q.CreateDaemon(ctx, &db.CreateDaemonParams{
				Name:          namegen.Generate(),
				Metadata:      in.Metadata,
				Status:        status,
				Config:        config,
				KeyThumbprint: &in.Binding,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			// A token that ran out meanwhile rolls the new daemon back.
			if _, err := q.RedeemToken(ctx, &db.RedeemTokenParams{
				ID:        parsed.ID,
				Kind:      nokkuv1.TokenKind_TOKEN_KIND_ENROLL,
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
			out = &Enrolled{
				DaemonID: created.ID,
				Name:     created.Name,
				TargetID: created.TargetID,
				Status:   status,
				Config:   config,
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
		Config:   db.ResolveDaemonConfig(d.Config),
	}, nil
}
