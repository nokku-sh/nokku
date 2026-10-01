package api

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
	"uuid"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/audit"

	"connectrpc.com/connect"

	nokkudaemon "github.com/nokku-sh/nokku/internal/daemon"
	"github.com/nokku-sh/nokku/internal/iam"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
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
	// A daemon can only delete itself, whatever id it sends.
	id := cmp.Or(actor.DaemonIDFromContext(ctx), req.GetId())
	if id == "" {
		return nil, errInvalidInput
	}
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		_, err = q.DeleteDaemon(ctx, id)
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
	// Member is enough, the relay is only transport. sshd is the real gate.
	ctx, err = actorHasRole(ctx, s.cfg.Conn, db.RoleMember)
	if err != nil {
		return err
	}

	var d *db.Daemon
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		d, err = q.GetDaemon(ctx, daemonID)
		return err
	}); err != nil {
		return err
	}

	relayID := uuid.NewV7().String()
	caller, _ := actor.PrincipalFromContext(ctx)
	relay, err := s.cfg.Pool.RequestRelay(ctx, d.ID, relayID, caller.ID)
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

func (s *daemonService) EnrollDaemon(
	ctx context.Context,
	req *nokkuv1.EnrollDaemonRequest,
) (*nokkuv1.EnrollDaemonResponse, error) {
	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return nil, errInternal
	}
	// The session is bound to the daemon's DPoP key, so a stolen token is
	// useless without it.
	binding, err := s.enrollBinding(ctx, ci)
	if err != nil {
		return nil, err
	}

	out, err := nokkudaemon.Enroll(ctx, s.cfg.Conn, nokkudaemon.EnrollInput{
		Token:    req.GetToken(),
		Binding:  binding,
		Metadata: requestMetadata(ci.RequestHeader()),
		// The workspace is only known once the token verified, so the
		// resource cap is checked here instead of in the guard.
		CanCreate: func(ctx context.Context, workspaceID string) error {
			return s.cfg.Entitlements.CheckResources(ctx, workspaceID)
		},
	})
	if errors.Is(err, nokkudaemon.ErrEnrollToken) {
		return nil, newError(connect.CodeFailedPrecondition, err.Error())
	}
	if err != nil {
		return nil, err
	}
	workspaceID := out.WorkspaceID
	ctx = actor.AnnotateTenant(ctx, workspaceID)

	// Never expires, deleting the daemon cascades to the session.
	token, err := s.cfg.IAM.IssueDaemonSession(ctx, workspaceID, out.DaemonID, binding)
	if err != nil {
		return nil, errInternal
	}

	return &nokkuv1.EnrollDaemonResponse{
		Id:          &out.DaemonID,
		WorkspaceId: &workspaceID,
		TargetId:    &out.TargetID,
		Status:      &out.Status,
		Config:      out.Config,
		AccessToken: &token,
	}, nil
}

func (s *daemonService) SyncDaemon(
	ctx context.Context,
	req *nokkuv1.SyncDaemonRequest,
) (*nokkuv1.SyncDaemonResponse, error) {
	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return nil, errInternal
	}

	res, err := nokkudaemon.Sync(ctx, s.cfg.Conn, nokkudaemon.SyncInput{
		DaemonID:    actor.DaemonIDFromContext(ctx),
		Metadata:    requestMetadata(ci.RequestHeader()),
		ReqMetadata: req.GetMetadata(),
		Users:       req.GetUsers(),
		PrivateIPs:  req.GetPrivateIps(),
	})
	if err != nil {
		return nil, err
	}
	return &nokkuv1.SyncDaemonResponse{
		Status:       res.Status,
		Config:       res.Config,
		Principals:   res.Principals,
		CaPublicKey:  &res.CAPublicKey,
		StateVersion: &res.Version,
	}, nil
}

// enrollBinding returns the DPoP key thumbprint. A missing proof is an error,
// daemons must enroll key-bound.
func (s *daemonService) enrollBinding(ctx context.Context, ci connect.CallInfo) (string, error) {
	svc := s.cfg.IAM
	if svc.DPoP == nil {
		return "", newError(connect.CodeUnimplemented, "DPoP is not configured")
	}

	binding, err := svc.DPoP.Verify(
		ctx,
		ci.RequestHeader().Get("DPoP"),
		"",
		http.MethodPost,
		s.cfg.FullURL()+"/"+nokkuv1connect.DaemonServiceEnrollDaemonProcedure,
	)
	if err != nil {
		if errors.Is(err, iam.ErrDPoPNonce) {
			svc.AdvertiseDPoPNonce(ci.ResponseHeader())
			return "", newError(connect.CodeUnauthenticated, "stale DPoP nonce")
		}
		return "", newError(connect.CodeInvalidArgument, "invalid DPoP proof")
	}
	return binding, nil
}

func requestMetadata(h http.Header) []byte {
	metadata, _ := json.Marshal(map[string]string{
		"user-agent": h.Get("User-Agent"),
		"host":       h.Get("Host"),
	})
	return metadata
}
