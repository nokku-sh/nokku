package daemon

import (
	"context"
	"encoding/json"

	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

// SyncInput is one daemon heartbeat: transport metadata for the daemon row,
// the daemon-reported target facts, and the users its sshd sees.
type SyncInput struct {
	DaemonID    string
	Metadata    []byte
	ReqMetadata map[string]string
	Users       []string
	PrivateIPs  []string
}

// Synced is the state a daemon's next heartbeat runs against.
type Synced struct {
	WorkspaceID string
	Status      *nokkuv1.DaemonStatus
	Config      *nokkuv1.DaemonConfig
	Principals  []*nokkuv1.PrincipalUsers
	CAPublicKey string
}

// Sync records a daemon heartbeat and returns the state the daemon should
// run with: status, config, synced principals, and the signing CA.
func Sync(ctx context.Context, conn connection, in SyncInput) (*Synced, error) {
	res := &Synced{}
	if err := conn.WithWorkspace(ctx, func(q *db.Queries) error {
		daemon, err := q.GetDaemon(ctx, in.DaemonID)
		if err != nil {
			return err
		}
		res.WorkspaceID = daemon.WorkspaceID
		res.Status = &daemon.Status
		res.Config = daemon.Config

		// A non-accepted daemon learns its status from the response instead
		// of an error: pending daemons keep retrying, rejected ones get
		// told to stop.
		if daemon.Status != nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
			return nil
		}

		// Only the heartbeat metadata is touched: the combined update's
		// COALESCE cannot protect status from a zero value, so a sync must
		// never write it (an admin's accept/reject must not be clobbered).
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

		// The signing CA goes into the response so the daemon can detect a
		// rollover by comparing it against its cached copy. A daemon without
		// a CA cannot renew host certs anyway. Leave the field empty then.
		if ca, caErr := q.GetCAByDaemonID(ctx, &daemon.ID); caErr == nil {
			res.CAPublicKey = ca.PublicKey
		}

		targetMeta, err := json.Marshal(in.ReqMetadata)
		if err != nil {
			return err
		}
		if _, err := q.UpdateTarget(ctx, &db.UpdateTargetParams{
			TargetID:  target.ID,
			Metadata:  targetMeta,
			Endpoints: in.PrivateIPs,
		}); err != nil {
			return err
		}

		if err := q.SyncPrincipals(ctx, &db.SyncPrincipalsParams{
			TargetID:  target.ID,
			Usernames: in.Users,
		}); err != nil {
			return err
		}

		result, err := q.ListPrincipalsForDaemon(ctx, &daemon.ID)
		if err != nil {
			return err
		}
		for _, p := range result {
			res.Principals = append(res.Principals, &nokkuv1.PrincipalUsers{
				Username: &p.Username,
				Ids:      p.Ids,
			})
		}

		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}
