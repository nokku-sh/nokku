package api

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"uuid"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/realip"

	"connectrpc.com/connect/v2"

	"google.golang.org/protobuf/types/known/timestamppb"

	nokkudaemon "github.com/nokku-sh/nokku/core/internal/daemon"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/cache"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
)

type daemonService struct {
	cfg     *config.Config
	tickets *cache.TTL[string, sessionTicket]
}

func (s *daemonService) GetDaemon(
	ctx context.Context,
	req *nokkuv1.GetDaemonRequest,
) (*nokkuv1.GetDaemonResponse, error) {
	result, err := s.cfg.Conn.Tenant().GetDaemon(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	return &nokkuv1.GetDaemonResponse{
		Daemon: liveDaemon(s.cfg.Pool, &result.Daemon, result.Name),
	}, nil
}

// liveDaemon adds what only the pool knows: online and since when it is behind.
func liveDaemon(pool *nokkudaemon.Pool, d *db.Daemon, name string) *nokkuv1.Daemon {
	return withBehind(pool, d.ToProto(name, pool.IsConnected(d.ID)))
}

func withBehind(pool *nokkudaemon.Pool, d *nokkuv1.Daemon) *nokkuv1.Daemon {
	if since := pool.BehindSince(d.GetId()); !since.IsZero() {
		d.BehindSince = timestamppb.New(since)
	}
	return d
}

func (s *daemonService) UpdateDaemon(
	ctx context.Context,
	req *nokkuv1.UpdateDaemonRequest,
) (*nokkuv1.UpdateDaemonResponse, error) {
	if _, err := applyMask(req, req.GetUpdateMask()); err != nil {
		return nil, err
	}
	// The row lock stops two updates writing each other's old config back.
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		var config *nokkuv1.DaemonConfig
		if req.GetConfig() != nil {
			stored, err := q.GetDaemonConfigForUpdate(ctx, req.GetId())
			if err != nil {
				return err
			}
			config = cmp.Or(stored, &nokkuv1.DaemonConfig{})
			mergeSet(config.ProtoReflect(), req.GetConfig().ProtoReflect())
		}
		name, err := q.UpdateDaemon(ctx, &db.UpdateDaemonParams{
			DaemonID: req.GetId(),
			Status:   req.GetStatus(),
			Config:   config,
		})
		if err != nil {
			return err
		}
		audit.Set(ctx, "name", name)
		//nolint:exhaustive // other statuses stay an UpdateDaemon
		switch req.GetStatus() {
		case nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED:
			audit.SetAction(ctx, "ApproveDaemon")
		case nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED:
			audit.SetAction(ctx, "RejectDaemon")
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.UpdateDaemonResponse{}, nil
}

func (s *daemonService) ListDaemons(
	ctx context.Context,
	req *nokkuv1.ListDaemonsRequest,
) (*nokkuv1.ListDaemonsResponse, error) {
	result, err := s.cfg.Conn.Tenant().ListDaemons(ctx, &db.ListDaemonsParams{
		Query:     req.Query,
		Status:    req.GetStatus(),
		Online:    req.Online,
		Connected: s.cfg.Pool.ConnectedIn(actor.WorkspaceIDFromContext(ctx)),
		Limit:     req.Limit,
		Offset:    req.Offset,
	})
	if err != nil {
		return nil, err
	}
	count := int32(0)
	if len(result) > 0 {
		count = result[0].TotalCount
	}

	daemons := db.DaemonsToProto(result, s.cfg.Pool.IsConnected)
	for _, d := range daemons {
		withBehind(s.cfg.Pool, d)
	}
	return &nokkuv1.ListDaemonsResponse{Daemons: daemons, Total: &count}, nil
}

func (s *daemonService) DeleteDaemon(
	ctx context.Context,
	req *nokkuv1.DeleteDaemonRequest,
) (*nokkuv1.DeleteDaemonResponse, error) {
	name, err := s.cfg.Conn.Tenant().DeleteDaemon(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	audit.Set(ctx, "name", name)

	return &nokkuv1.DeleteDaemonResponse{}, nil
}

// CreateSession only hands out a ticket, the terminal websocket runs the shell.
func (s *daemonService) CreateSession(
	ctx context.Context,
	req *nokkuv1.CreateSessionRequest,
) (*nokkuv1.CreateSessionResponse, error) {
	// People only, so there is a person's id for the cert principal.
	userID := actor.UserIDFromContext(ctx)

	var daemon *db.GetDaemonRow
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		daemon, err = q.GetDaemon(ctx, req.GetDaemonId())
		if err != nil {
			return err
		}
		// Same grant sshd asks for, so no ticket for an account they can't use.
		accounts, err := grantedAccounts(ctx, q, daemon.Daemon.ID, userID)
		if err != nil {
			return err
		}
		if !slices.Contains(accounts, req.GetUsername()) {
			return db.ErrPermissionDenied
		}
		return q.TouchAccessUsageByDaemon(ctx, &db.TouchAccessUsageByDaemonParams{
			DaemonID:  &daemon.Daemon.ID,
			SubjectID: userID,
		})
	}); err != nil {
		return nil, err
	}

	sessionID := uuid.NewV7().String()
	username := req.GetUsername()
	s.tickets.Set(sessionID, sessionTicket{
		WorkspaceID: daemon.Daemon.WorkspaceID,
		DaemonID:    daemon.Daemon.ID,
		UserID:      userID,
		Username:    username,
	})
	return &nokkuv1.CreateSessionResponse{
		Session: &nokkuv1.DaemonSession{
			SessionId: &sessionID,
			UserId:    &userID,
			Username:  &username,
		},
		DaemonName: &daemon.Name,
	}, nil
}

// grantedAccounts lists the accounts sshd would let subject log in to today.
func grantedAccounts(ctx context.Context, q *db.Queries, daemonID, subject string) ([]string, error) {
	target, err := q.GetTargetByDaemon(ctx, &daemonID)
	if err != nil {
		return nil, err
	}
	rows, err := q.ListSubjectUsernamesForTargets(ctx, &db.ListSubjectUsernamesForTargetsParams{
		TargetIds: []string{target.ID},
		SubjectID: subject,
	})
	if err != nil {
		return nil, err
	}
	accounts := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.UserOk && r.DaemonOk {
			accounts = append(accounts, r.Username)
		}
	}
	return accounts, nil
}

// Relay bridges a raw byte stream to the daemon's sshd.
func (s *daemonService) Relay(
	ctx context.Context,
	stream nokkuv1connect.DaemonServiceRelayServerStream,
) error {
	msg, err := stream.Receive()
	if err != nil {
		return err
	}
	start, ok := msg.GetMsg().(*nokkuv1.RelayRequest_Start)
	if !ok || start.Start == nil {
		return connect.NewError(
			connect.CodeInvalidArgument,
			"first message must be RelayStart",
		)
	}
	daemonID := start.Start.GetDaemonId()
	if daemonID == "" {
		return connect.NewError(connect.CodeInvalidArgument, "daemon_id required")
	}

	// This pipe passes NAT and holds a pre-auth slot, so it needs a grant too.
	caller, _ := actor.PrincipalFromContext(ctx)
	var d *db.Daemon
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) error {
		row, err := q.GetDaemon(ctx, daemonID)
		if err != nil {
			return err
		}
		d = &row.Daemon
		accounts, err := grantedAccounts(ctx, q, d.ID, caller.ID)
		if err != nil {
			return err
		}
		if len(accounts) == 0 {
			return db.ErrPermissionDenied
		}
		return nil
	}); err != nil {
		return err
	}

	relayID := uuid.NewV7().String()
	relay, err := s.cfg.Pool.RequestRelay(ctx, d.ID, relayID, caller.ID, clientAddr(ctx))
	if err != nil {
		if errors.Is(err, nokkudaemon.ErrRelayLimit) {
			return connect.NewError(connect.CodeResourceExhausted, "too many concurrent relays")
		}
		return connect.NewError(connect.CodeUnavailable, "daemon did not accept relay")
	}
	defer s.cfg.Pool.UnregisterRelay(relayID)

	s.cfg.Audit.Log(ctx, &audit.Event{
		Action: "RelayOpen", Target: d.ID, Details: map[string]any{"relay_id": relayID},
	})
	defer s.cfg.Audit.Log(ctx, &audit.Event{
		Action: "RelayClose", Target: d.ID, Details: map[string]any{"relay_id": relayID},
	})

	if err := stream.Send(&nokkuv1.RelayResponse{
		Msg: &nokkuv1.RelayResponse_Ready{Ready: &nokkuv1.RelayReady{RelayId: &relayID}},
	}); err != nil {
		return err
	}
	return nokkudaemon.BridgeRelay(ctx, stream, relay)
}

// clientAddr is exact, a cert's source-address option is matched against it.
func clientAddr(ctx context.Context) string {
	meta, ok := actor.RequestMetaFromContext(ctx)
	if !ok {
		return ""
	}
	return realip.Client(meta.Header, meta.RemoteAddr)
}
