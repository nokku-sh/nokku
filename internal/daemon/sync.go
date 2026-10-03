package daemon

import (
	"context"
	"encoding/json"
	"errors"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/db"
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
	Principals  []*nokkuv1.PrincipalUsers
	CAPublicKey string
}

func Sync(ctx context.Context, conn connection, in SyncInput) (*Synced, error) {
	res := &Synced{}
	err := conn.WithWorkspace(ctx, func(q *db.Queries) error {
		daemon, err := q.GetDaemon(ctx, in.DaemonID)
		if err != nil {
			return err
		}
		res.Status = &daemon.Status
		res.Config = daemon.Config

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

		// Lets the daemon detect a CA rollover. Without a CA it stays empty.
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

		// Never deletes, a host that cannot enumerate users must not change
		// who has access.
		if err := q.InsertTargetPrincipals(ctx, &db.InsertTargetPrincipalsParams{
			TargetID:  target.ID,
			Usernames: in.Users,
		}); err != nil {
			return err
		}

		result, err := q.ListPrincipalsForTarget(ctx, target.ID)
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
	})
	// A deleted daemon still serves its cached principals. REJECTED makes
	// the host drop them, and its session is spent with that answer.
	if errors.Is(err, db.ErrWorkspaceNotAccessible) {
		if err := conn.WithTx(ctx, func(q *db.Queries) error {
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
