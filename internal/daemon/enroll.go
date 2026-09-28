package daemon

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/namegen"
)

// ErrEnrollToken covers unknown, revoked, expired, and used-up tokens alike,
// so a caller learns nothing about which it hit.
var ErrEnrollToken = errors.New("invalid or expired enrollment token")

// EnrollInput carries what the transport layer gleans from the request: the
// raw enroll token, the DPoP key thumbprint, and marshaled transport
// metadata. CanCreate runs only when the machine is new, so re-enrolling
// works even at the plan cap.
type EnrollInput struct {
	Token     string
	Binding   string
	Metadata  []byte
	CanCreate func(ctx context.Context, workspaceID string) error
}

// Enrolled is the enrollment outcome the response is built from.
type Enrolled struct {
	WorkspaceID string
	DaemonID    string
	Name        string
	TargetID    string
	Status      nokkuv1.DaemonStatus
	Config      *nokkuv1.DaemonConfig
}

// maxNameAttempts bounds retries on a generated name that is already taken.
const maxNameAttempts = 5

// Enroll verifies the enroll token and returns the daemon bound to the DPoP
// key thumbprint, provisioning it on first contact. The token authorizes this
// otherwise unauthenticated request, so it runs as the system role. Only a
// new daemon spends a use of the token. The quota check runs between the two
// transactions: it reads the database itself, and nesting it would let
// parallel enrollments exhaust the pool.
func Enroll(ctx context.Context, conn connection, in EnrollInput) (*Enrolled, error) {
	parsed, err := crypto.Parse(in.Token)
	if err != nil || parsed.ID == "" {
		return nil, ErrEnrollToken
	}
	hash, err := crypto.HashToken(in.Token)
	if err != nil {
		return nil, ErrEnrollToken
	}

	var (
		token     *db.WorkspaceToken
		workspace *db.Workspace
		out       *Enrolled
	)
	err = conn.WithTx(ctx, func(q *db.Queries) (err error) {
		token, err = q.GetLiveToken(ctx, &db.GetLiveTokenParams{
			ID:        parsed.ID,
			Kind:      nokkuv1.TokenKind_TOKEN_KIND_ENROLL,
			TokenHash: hash,
		})
		if err != nil {
			return ErrEnrollToken
		}
		workspace, err = q.GetWorkspace(ctx, token.WorkspaceID)
		if err != nil {
			return err
		}
		out, err = enrolledDaemon(ctx, q, token.WorkspaceID, in.Binding)
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
	config := workspace.Settings.GetDefaultDaemonConfig()

	err = conn.WithTx(ctx, func(q *db.Queries) error {
		for range maxNameAttempts {
			// A racing enrollment of the same key turns the insert below
			// into a no-op, so look again every round.
			if out, err = enrolledDaemon(ctx, q, token.WorkspaceID, in.Binding); err != nil || out != nil {
				return err
			}
			// Names are generated server-side so a workspace never shows a
			// duplicate label. A taken name returns no row and we try again.
			created, err := q.CreateDaemon(ctx, &db.CreateDaemonParams{
				WorkspaceID:   token.WorkspaceID,
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
			// Spending the use in the same transaction means a token that
			// ran out meanwhile rolls the new daemon back.
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
				WorkspaceID: token.WorkspaceID,
				DaemonID:    created.ID,
				Name:        created.Name,
				TargetID:    created.TargetID,
				Status:      status,
				Config:      config,
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

// enrolledDaemon returns the daemon already bound to the enrolling key, or
// nil. The key is the machine's identity, so re-enrolling reuses it.
func enrolledDaemon(ctx context.Context, q *db.Queries, workspaceID, binding string) (*Enrolled, error) {
	d, err := q.GetDaemonByKeyThumbprint(ctx, &db.GetDaemonByKeyThumbprintParams{
		WorkspaceID:   workspaceID,
		KeyThumbprint: &binding,
	})
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
		WorkspaceID: workspaceID,
		DaemonID:    d.ID,
		Name:        d.Name,
		TargetID:    target.ID,
		Status:      d.Status,
		Config:      d.Config,
	}, nil
}
