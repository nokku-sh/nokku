package api

import (
	"context"
	"errors"
	"slices"
	"time"
	"uuid"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/audit"

	"connectrpc.com/connect"

	nokkudaemon "github.com/nokku-sh/nokku/internal/daemon"
	"github.com/nokku-sh/nokku/internal/iam"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/util"
)

type daemonService struct {
	cfg *config.Config
}

func newDaemonService(cfg *config.Config) *daemonService {
	return &daemonService{cfg: cfg}
}

func (s *daemonService) GetDaemon(
	ctx context.Context,
	req *nokkuv1.GetDaemonRequest,
) (*nokkuv1.GetDaemonResponse, error) {
	var result *db.Daemon
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.GetDaemon(ctx, req.GetId())
		return err
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.GetDaemonResponse{
		Daemon: result.ToProto(),
	}, nil
}

func (s *daemonService) UpdateDaemon(
	ctx context.Context,
	req *nokkuv1.UpdateDaemonRequest,
) (*nokkuv1.UpdateDaemonResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		base, err := q.GetDaemon(ctx, req.GetId())
		if err != nil {
			return err
		}
		// A config replaces the stored one wholesale, since proto.Merge cannot
		// turn a scalar off. The UI always sends the full config.
		config := req.GetConfig()
		if config == nil {
			config = base.Config
		}
		_, err = q.UpdateDaemon(ctx, &db.UpdateDaemonParams{
			DaemonID: req.GetId(),
			Status:   req.GetStatus(),
			Config:   config,
		})
		return err
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.UpdateDaemonResponse{}, nil
}

func (s *daemonService) ListDaemons(
	ctx context.Context,
	req *nokkuv1.ListDaemonsRequest,
) (*nokkuv1.ListDaemonsResponse, error) {
	var result []*db.ListDaemonsRow
	count := int32(0)
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		var status *int32
		if req.GetStatus() != 0 {
			status = new(int32(req.GetStatus()))
		}

		result, err = q.ListDaemons(ctx, &db.ListDaemonsParams{
			WorkspaceID: req.GetWorkspaceId(),
			Query:       req.Query,
			Status:      status,
			Online:      req.Online,
			SeenAfter:   time.Now().Add(-db.DaemonOnlineWindow),
			Limit:       req.Limit,
			Offset:      req.Offset,
		})
		return err
	}); err != nil {
		return nil, err
	}
	if len(result) > 0 {
		count = result[0].TotalCount
	}

	return &nokkuv1.ListDaemonsResponse{
		Daemons: db.DaemonsToProto(result),
		Total:   &count,
	}, nil
}

func (s *daemonService) DeleteDaemon(
	ctx context.Context,
	req *nokkuv1.DeleteDaemonRequest,
) (*nokkuv1.DeleteDaemonResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		_, err = q.DeleteDaemon(ctx, req.GetId())
		return err
	}); err != nil {
		return nil, err
	}

	return &nokkuv1.DeleteDaemonResponse{}, nil
}

// CreateSession only hands out a ticket. The shell starts when the browser
// opens the terminal websocket with it, and ends with that socket.
func (s *daemonService) CreateSession(
	ctx context.Context,
	req *nokkuv1.CreateSessionRequest,
) (*nokkuv1.CreateSessionResponse, error) {
	// The cert principal is the actor id, sshd would refuse any non-user.
	userID := actor.UserIDFromContext(ctx)
	if userID == "" {
		return nil, newError(connect.CodePermissionDenied, "web sessions require a user principal")
	}

	var daemon *db.Daemon
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		daemon, err = q.GetDaemon(ctx, req.GetDaemonId())
		if err != nil {
			return err
		}
		// sshd only trusts the CA synced to it.
		ca, err := q.GetCAByDaemonID(ctx, &daemon.ID)
		if err != nil {
			return err
		}
		if !ca.IsActive {
			return newError(connect.CodeFailedPrecondition, "certificate authority is not active")
		}
		// The same grant sshd will ask for, so nobody gets a shell ticket
		// for an account they cannot use.
		accounts, err := grantedAccounts(ctx, q, daemon.ID, userID)
		if err != nil {
			return err
		}
		if !slices.Contains(accounts, req.GetUsername()) {
			return db.ErrPermissionDenied
		}
		return nil
	}); err != nil {
		return nil, err
	}

	sessionID := uuid.NewV7().String()
	username := req.GetUsername()
	if err := putSessionTicket(ctx, s.cfg.Cache, sessionID, sessionTicket{
		WorkspaceID: daemon.WorkspaceID,
		DaemonID:    daemon.ID,
		UserID:      userID,
		Username:    username,
	}); err != nil {
		return nil, err
	}
	return &nokkuv1.CreateSessionResponse{
		Session: &nokkuv1.DaemonSession{
			SessionId: &sessionID,
			UserId:    &userID,
			Username:  &username,
		},
		DaemonName: &daemon.Name,
	}, nil
}

// grantedAccounts lists the accounts on the daemon's host that subject may
// log in to, directly or through a team.
func grantedAccounts(ctx context.Context, q *db.Queries, daemonID, subject string) ([]string, error) {
	target, err := q.GetTargetByDaemon(ctx, &daemonID)
	if err != nil {
		return nil, err
	}
	rows, err := q.ListSubjectUsernamesForTargets(ctx, &db.ListSubjectUsernamesForTargetsParams{
		TargetIds: []string{target.ID},
		SubjectID: &subject,
	})
	if err != nil {
		return nil, err
	}
	accounts := make([]string, 0, len(rows))
	for _, r := range rows {
		accounts = append(accounts, r.Username)
	}
	return accounts, nil
}

func (s *daemonService) ListSessions(
	ctx context.Context,
	req *nokkuv1.ListSessionsRequest,
) (*nokkuv1.ListSessionsResponse, error) {
	var daemon *db.Daemon
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		daemon, err = q.GetDaemon(ctx, req.GetDaemonId())
		return err
	}); err != nil {
		return nil, err
	}

	sessions := s.cfg.Pool.ListSessions(daemon.ID)
	return &nokkuv1.ListSessionsResponse{
		Sessions:   sessions,
		DaemonName: &daemon.Name,
	}, nil
}

func (s *daemonService) CloseSession(
	ctx context.Context,
	req *nokkuv1.CloseSessionRequest,
) (*nokkuv1.CloseSessionResponse, error) {
	// The pool is shared across tenants, so the daemon must resolve in the
	// pinned workspace first.
	sess := s.cfg.Pool.GetSession(req.GetSessionId())
	if sess == nil || sess.DaemonID() != req.GetDaemonId() {
		return nil, errNotFound
	}
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		_, err := q.GetDaemon(ctx, sess.DaemonID())
		return err
	}); err != nil {
		return nil, err
	}
	s.cfg.Pool.CloseSession(req.GetSessionId())
	return &nokkuv1.CloseSessionResponse{}, nil
}

// Relay bridges a raw byte stream to the daemon's sshd. The workspace is only
// known from the first message, so the role check runs here.
func (s *daemonService) Relay(
	ctx context.Context,
	stream *connect.BidiStream[nokkuv1.RelayRequest, nokkuv1.RelayResponse],
) error {
	msg, err := stream.Receive()
	if err != nil {
		return err
	}
	start, ok := msg.GetMsg().(*nokkuv1.RelayRequest_Start)
	if !ok || start.Start == nil {
		return connect.NewError(
			connect.CodeInvalidArgument,
			errors.New("first message must be RelayStart"),
		)
	}
	workspaceID := start.Start.GetWorkspaceId()
	daemonID := start.Start.GetDaemonId()
	if workspaceID == "" || daemonID == "" {
		return connect.NewError(
			connect.CodeInvalidArgument,
			errors.New("workspace_id and daemon_id required"),
		)
	}

	ctx = actor.AnnotateTenant(ctx, workspaceID)
	ctx, err = actorHasRole(ctx, s.cfg.Conn, db.RoleMember)
	if err != nil {
		return err
	}

	// sshd is the real gate, but the pipe itself reaches hosts behind NAT
	// and holds a pre-auth slot there. It needs a grant on the target.
	caller, _ := actor.PrincipalFromContext(ctx)
	var d *db.Daemon
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		if d, err = q.GetDaemon(ctx, daemonID); err != nil {
			return err
		}
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
			return newError(connect.CodeResourceExhausted, "too many concurrent relays")
		}
		return newError(connect.CodeUnavailable, "daemon did not accept relay")
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

// clientAddr is the caller's address as a relayed connection reports it to
// the daemon's sshd. It is the exact address, a source-address option on the
// certificate is matched against it.
func clientAddr(ctx context.Context) string {
	meta, ok := iam.RequestMetaFromContext(ctx)
	if !ok {
		return ""
	}
	return util.ClientIP(meta.Header, meta.RemoteAddr)
}
