package daemon

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/namegen"
)

var (
	ErrEnrollExpired = errors.New("enrollment token has expired")
	ErrEnrollToken   = errors.New("invalid enrollment token")
)

// EnrollInput carries what the transport layer gleans from the request: the
// parsed token's workspace, the raw enroll token, the DPoP key thumbprint,
// marshaled transport metadata, and the caller-picked CA.
type EnrollInput struct {
	WorkspaceID string
	Token       string
	Binding     string
	Metadata    []byte
	CaID        *string
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

// Enroll verifies the enroll token against the workspace and returns the
// existing daemon bound to the DPoP key thumbprint, or provisions a new one.
func Enroll(ctx context.Context, conn connection, in EnrollInput) (*Enrolled, error) {
	// The enrollment token (verified below against its stored hash)
	// authorizes this otherwise unauthenticated request, so the daemon
	// provisioning runs as a system transaction without an actor.
	var workspace *db.Workspace
	if err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
		workspace, err = q.GetWorkspace(ctx, in.WorkspaceID)
		return err
	}); err != nil {
		return nil, err
	}
	if workspace.EnrollExpiresAt != nil && workspace.EnrollExpiresAt.Before(time.Now()) {
		return nil, ErrEnrollExpired
	}
	if !workspace.EnrollTokenHash.Verify(in.Token) {
		return nil, ErrEnrollToken
	}

	status := nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING
	if workspace.Settings.GetEnrollAutoApprove() {
		status = nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED
	}

	// New daemons inherit the workspace's adjustable default config, so a
	// freshly deployed daemon picks up the current SSH server policy.
	config := workspace.Settings.GetDefaultDaemonConfig()

	// Re-enrolling the same machine must not create a second daemon. The
	// DPoP key thumbprint (binding) is the daemon's stable identity, so look
	// for an existing daemon bound to this workspace and key and reuse it.
	var (
		daemonID   string
		daemonName string
		targetID   string
		statusNow  = status
	)
	var existing *db.Daemon
	if err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
		existing, err = q.GetDaemonByKeyThumbprint(ctx, &db.GetDaemonByKeyThumbprintParams{
			WorkspaceID:   in.WorkspaceID,
			KeyThumbprint: &in.Binding,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			// sqlc :one hands back a non-nil zero row with ErrNoRows, clear it
			// or the create path below never runs.
			existing = nil
			return nil
		}
		if err != nil {
			return err
		}
		target, err := q.GetTargetByDaemon(ctx, &existing.ID)
		if err != nil {
			return err
		}
		targetID = target.ID
		return nil
	}); err != nil {
		return nil, err
	}

	if existing != nil {
		daemonID = existing.ID
		daemonName = existing.Name
		statusNow = existing.Status
		config = existing.Config
	} else {
		// First enrollment: generate a name and insert. Names are generated
		// server-side so a workspace never shows a duplicate label. A
		// collision is a unique violation on (workspace_id, name), retried
		// with a numeric suffix before giving up.
		var name strings.Builder
		name.WriteString(namegen.Generate())
		for attempt := 0; ; attempt++ {
			if attempt > 0 {
				name.WriteString(strconv.Itoa(attempt + 1))
			}

			var created *db.CreateDaemonRow
			err := conn.WithTx(ctx, func(q *db.Queries) (err error) {
				created, err = q.CreateDaemon(ctx, &db.CreateDaemonParams{
					WorkspaceID:   in.WorkspaceID,
					Name:          name.String(),
					Metadata:      in.Metadata,
					Status:        status,
					Config:        config,
					KeyThumbprint: &in.Binding,
				})
				if err != nil {
					return err
				}

				// Assign the CA the caller picked, or fall back to the
				// workspace default when none was given. A daemon without
				// a CA cannot get host certs signed, so this must always run.
				caID := in.CaID
				if caID != nil && *caID == "" {
					caID = nil
				}
				_, err = q.UpdateTargetCA(ctx, &db.UpdateTargetCAParams{
					DaemonID: &created.ID,
					CaID:     caID,
				})
				return err
			})
			if err == nil {
				daemonID = created.ID
				daemonName = created.Name
				targetID = created.TargetID
				break
			}
			if !db.IsUniqueViolation(err) || attempt >= 4 {
				return nil, err
			}
		}
	}

	return &Enrolled{
		WorkspaceID: in.WorkspaceID,
		DaemonID:    daemonID,
		Name:        daemonName,
		TargetID:    targetID,
		Status:      statusNow,
		Config:      config,
	}, nil
}
