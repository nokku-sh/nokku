package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
	"uuid"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkudaemon "github.com/nokku-sh/nokku/internal/daemon"
	"github.com/nokku-sh/nokku/internal/iam"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
)

type DaemonService struct {
	cfg *config.Config
}

func NewDaemonService(cfg *config.Config) *DaemonService {
	return &DaemonService{cfg: cfg}
}

func daemonEventPayload(daemonID, name string) string {
	return fmt.Sprintf(`{"daemon_id":%q,"daemon_name":%q}`, daemonID, name)
}

func (s *DaemonService) GetDaemon(
	ctx context.Context,
	req *nokkuv1.GetDaemonRequest,
) (*nokkuv1.GetDaemonResponse, error) {
	var result *db.Daemon
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.GetDaemon(ctx, req.GetId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if result == nil {
		return nil, ErrNotFound
	}

	return &nokkuv1.GetDaemonResponse{
		Daemon: result.ToProto(),
	}, nil
}

func (s *DaemonService) UpdateDaemon(
	ctx context.Context,
	req *nokkuv1.UpdateDaemonRequest,
) (*nokkuv1.UpdateDaemonResponse, error) {
	var result *db.Daemon
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		base, err := q.GetDaemon(ctx, req.GetId())
		if err != nil {
			return err
		}
		// A provided config replaces the stored one wholesale: a partial merge
		// cannot express turning a scalar off (false/0 are "unpopulated" to
		// proto.Merge). The UI always sends the complete config it received.
		config := req.GetConfig()
		if config == nil {
			config = base.Config
		}
		result, err = q.UpdateDaemon(ctx, &db.UpdateDaemonParams{
			DaemonID: req.GetId(),
			Status:   req.GetStatus(),
			Config:   config,
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	// A status change (accept/reject) is a workspace state change: connected
	// daemons re-sync and discover their own status from the sync response.
	s.cfg.Pool.NotifyChange(result.WorkspaceID)

	if req.GetStatus() == nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
		s.cfg.Pool.PublishWorkspaceEvent(
			result.WorkspaceID,
			"daemon.accepted",
			daemonEventPayload(result.ID, result.Name),
		)
	}
	return &nokkuv1.UpdateDaemonResponse{}, nil
}

func (s *DaemonService) ListDaemons(
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
			Limit:       req.Limit,
			Offset:      req.Offset,
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if len(result) > 0 {
		count = result[0].TotalCount
	}

	return &nokkuv1.ListDaemonsResponse{
		Daemons: db.DaemonsToProto(result),
		Total:   &count,
	}, nil
}

func (s *DaemonService) DeleteDaemon(
	ctx context.Context,
	req *nokkuv1.DeleteDaemonRequest,
) (*nokkuv1.DeleteDaemonResponse, error) {
	// A daemon can delete itself via the challenge-auth context. Either way
	// one identifier is required.
	id := req.GetId()
	if id == "" {
		id = iam.DaemonIDFromContext(ctx)
		if id == "" {
			return nil, ErrInvalidInput
		}
	}
	var result *db.Daemon
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		result, err = q.DeleteDaemon(ctx, id)
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	// A deleted daemon discovers its removal on the next sync (not found).
	s.cfg.Pool.NotifyChange(result.WorkspaceID)

	s.cfg.Pool.PublishWorkspaceEvent(
		result.WorkspaceID,
		"daemon.removed",
		daemonEventPayload(result.ID, result.Name),
	)
	return &nokkuv1.DeleteDaemonResponse{}, nil
}

func (s *DaemonService) RefreshEnrollToken(
	ctx context.Context,
	req *nokkuv1.RefreshEnrollTokenRequest,
) (*nokkuv1.RefreshEnrollTokenResponse, error) {
	token, err := crypto.NewToken(crypto.WithID(req.GetWorkspaceId()))
	if err != nil {
		return nil, ErrInternal
	}
	expiresAt := time.Now().Add(24 * time.Hour)
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.UpdateEnrollToken(ctx, &db.UpdateEnrollTokenParams{
			WorkspaceID:     req.GetWorkspaceId(),
			EnrollTokenHash: token.Hash,
			EnrollExpiresAt: &expiresAt,
		})
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.RefreshEnrollTokenResponse{
		Token:     &token.Plaintext,
		ExpiresAt: timestamppb.New(expiresAt),
	}, nil
}

func (s *DaemonService) RevokeEnrollToken(
	ctx context.Context,
	req *nokkuv1.RevokeEnrollTokenRequest,
) (*nokkuv1.RevokeEnrollTokenResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.UpdateEnrollToken(ctx, &db.UpdateEnrollTokenParams{
			WorkspaceID:     req.GetWorkspaceId(),
			EnrollTokenHash: "",
			EnrollExpiresAt: &time.Time{},
		})
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.RevokeEnrollTokenResponse{}, nil
}

// Session endpoints ----------------------------------------------------------

// CreateSession opens a web terminal session as a real SSH session: it
// mints an ephemeral user certificate, opens a relay to the daemon, and has
// the pool dial the daemon's sshd over it. The browser protocol is
// unchanged, only the transport behind the Session swapped.
func (s *DaemonService) CreateSession(
	ctx context.Context,
	req *nokkuv1.CreateSessionRequest,
) (*nokkuv1.CreateSessionResponse, error) {
	// The session certificate's principal is the actor id, so a non-user
	// actor could only mint a cert sshd will always refuse.
	userID := iam.UserIDFromContext(ctx)
	if userID == "" {
		return nil, NewError(connect.CodePermissionDenied, "web sessions require a user principal")
	}

	var daemon *db.Daemon
	var ca *db.CertificateAuthority
	var targetID string
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		daemon, err = q.GetDaemon(ctx, req.GetDaemonId())
		if err != nil {
			return err
		}
		// The daemon's sshd trusts exactly the CA whose public key is synced
		// to it, so the session certificate must come from that CA.
		ca, err = q.GetCAByDaemonID(ctx, &daemon.ID)
		if err != nil {
			return err
		}
		target, err := q.GetTargetByDaemon(ctx, &daemon.ID)
		if err != nil {
			return err
		}
		targetID = target.ID
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	sessionID := uuid.NewV7().String()
	username := req.GetUsername()

	if _, err := s.cfg.Pool.StartSession(ctx, nokkudaemon.SessionConfig{
		DaemonID:      daemon.ID,
		SessionID:     sessionID,
		Username:      username,
		UserID:        userID,
		CA:            ca,
		HostPrincipal: targetID,
	}); err != nil {
		if errors.Is(err, nokkudaemon.ErrCAInactive) {
			return nil, NewError(connect.CodeFailedPrecondition, "certificate authority is not active")
		}
		if errors.Is(err, nokkudaemon.ErrRelayLimit) {
			return nil, NewError(connect.CodeResourceExhausted, "too many concurrent sessions")
		}
		return nil, NewError(connect.CodeUnavailable, err.Error())
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

func (s *DaemonService) ListSessions(
	ctx context.Context,
	req *nokkuv1.ListSessionsRequest,
) (*nokkuv1.ListSessionsResponse, error) {
	var daemon *db.Daemon
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		daemon, err = q.GetDaemon(ctx, req.GetDaemonId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	sessions := s.cfg.Pool.ListSessions(daemon.ID)
	return &nokkuv1.ListSessionsResponse{
		Sessions:   sessions,
		DaemonName: &daemon.Name,
	}, nil
}

func (s *DaemonService) CloseSession(
	_ context.Context,
	req *nokkuv1.CloseSessionRequest,
) (*nokkuv1.CloseSessionResponse, error) {
	s.cfg.Pool.CloseSession(req.GetSessionId())
	return &nokkuv1.CloseSessionResponse{}, nil
}

// Relay bridges a user's raw byte stream to the daemon's own sshd. Streaming
// handlers bypass the unary interceptor's permission gate, so the same check
// CreateSession gets from ProcedurePermissions runs here.
func (s *DaemonService) Relay(
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

	// Streaming handlers get no tenant from the auth interceptor, so pin the
	// workspace from the start message before resolving membership.
	ctx = iam.AnnotateTenant(ctx, workspaceID)
	// View is deliberate: CreateSession already grants web sessions on view,
	// so relay transport demands no more. The real SSH gate is the daemon's
	// synced principal list plus certificate auth inside sshd.
	if err := actorHasPermission(ctx, s.cfg.Conn, db.PermDaemonsView); err != nil {
		return DBError(err)
	}

	var d *db.Daemon
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		d, err = q.GetDaemon(ctx, daemonID)
		return err
	}); err != nil {
		return DBError(err)
	}

	relayID := uuid.NewV7().String()
	actor, _ := iam.PrincipalFromContext(ctx)
	relay, err := s.cfg.Pool.RequestRelay(ctx, d.ID, relayID, actor.ID)
	if err != nil {
		if errors.Is(err, nokkudaemon.ErrRelayLimit) {
			return NewError(connect.CodeResourceExhausted, "too many concurrent relays")
		}
		return NewError(connect.CodeUnavailable, "daemon did not accept relay")
	}
	defer s.cfg.Pool.UnregisterRelay(relayID)

	s.logRelayEvent(ctx, "relay.open", workspaceID, d.ID, relayID, actor)
	defer s.logRelayEvent(ctx, "relay.close", workspaceID, d.ID, relayID, actor)

	if err := stream.Send(&nokkuv1.RelayResponse{
		Msg: &nokkuv1.RelayResponse_Ready{Ready: &nokkuv1.RelayReady{RelayId: &relayID}},
	}); err != nil {
		return err
	}
	return nokkudaemon.BridgeRelay(ctx, stream, relay)
}

// logRelayEvent records the semantic relay.open and relay.close events. The
// audit interceptor skips Relay (it only logs procedures matching its
// mutating prefixes), so the handler emits them directly, with the same
// transport facts the interceptor rows carry. WithoutCancel keeps the row
// when the peer hangs up and the request context dies first.
func (s *DaemonService) logRelayEvent(
	ctx context.Context,
	action, workspaceID, daemonID, relayID string,
	actor iam.Principal,
) {
	appendAuditRow(ctx, s.cfg.Audit, action, workspaceID, actor,
		map[string]any{"relay_id": relayID, "daemon_id": daemonID})
}

// Daemon endpoints ------------------------------------------------------------

func (s *DaemonService) EnrollDaemon(
	ctx context.Context,
	req *nokkuv1.EnrollDaemonRequest,
) (*nokkuv1.EnrollDaemonResponse, error) {
	enrollToken, err := crypto.Parse(req.GetToken())
	if err != nil {
		return nil, NewError(connect.CodeInvalidArgument, "invalid token")
	}
	workspaceID := enrollToken.ID
	ctx = iam.AnnotateTenant(ctx, workspaceID)

	// Resource cap check lives here, not in the guard: enrollment is a
	// public endpoint whose workspace comes from the enroll token, so the
	// interceptor cannot see it pinned in the request context. Mirrors the
	// seat check in invitation.go.
	if err := s.cfg.Entitlements.CheckResources(ctx, workspaceID); err != nil {
		return nil, err
	}

	// The daemon proves possession of its TPM/software key with a DPoP proof
	// bound to this enrollment request; the issued session is bound to that
	// key (jkt), so a stolen token is useless without the key. The proof is
	// the only machine credential: nothing secret is stored on the daemon.
	binding, err := s.enrollBinding(ctx)
	if err != nil {
		return nil, err
	}
	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return nil, ErrInternal
	}
	h := ci.RequestHeader()
	metadata, _ := json.Marshal(map[string]string{
		"user-agent": h.Get("User-Agent"),
		"host":       h.Get("Host"),
	})

	out, err := nokkudaemon.Enroll(ctx, s.cfg.Conn, nokkudaemon.EnrollInput{
		WorkspaceID: workspaceID,
		Token:       req.GetToken(),
		Binding:     binding,
		Metadata:    metadata,
		CaID:        req.CaId,
	})
	if err != nil {
		if errors.Is(err, nokkudaemon.ErrEnrollExpired) ||
			errors.Is(err, nokkudaemon.ErrEnrollToken) {
			return nil, NewError(connect.CodeFailedPrecondition, err.Error())
		}
		return nil, DBError(err)
	}

	// The daemon's control-plane token never expires; it is revoked by
	// deleting the daemon (the session cascades), not by a clock.
	token, err := s.cfg.IAM.IssueDaemonSession(ctx, workspaceID, out.DaemonID, binding)
	if err != nil {
		return nil, ErrInternal
	}

	eventType := "daemon.pending"
	if out.Status == nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
		eventType = "daemon.accepted"
	}
	s.cfg.Pool.PublishWorkspaceEvent(
		workspaceID,
		eventType,
		daemonEventPayload(out.DaemonID, out.Name),
	)

	return &nokkuv1.EnrollDaemonResponse{
		Id:          &out.DaemonID,
		WorkspaceId: &workspaceID,
		TargetId:    &out.TargetID,
		Status:      &out.Status,
		Config:      out.Config,
		AccessToken: &token,
	}, nil
}

func (s *DaemonService) SyncDaemon(
	ctx context.Context,
	req *nokkuv1.SyncDaemonRequest,
) (*nokkuv1.SyncDaemonResponse, error) {
	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return nil, ErrInternal
	}
	h := ci.RequestHeader()
	metadata, _ := json.Marshal(map[string]string{
		"user-agent": h.Get("User-Agent"),
		"host":       h.Get("Host"),
	})

	res, err := nokkudaemon.Sync(ctx, s.cfg.Conn, nokkudaemon.SyncInput{
		DaemonID:    iam.DaemonIDFromContext(ctx),
		Metadata:    metadata,
		ReqMetadata: req.GetMetadata(),
		Users:       req.GetUsers(),
		PrivateIPs:  req.GetPrivateIps(),
	})
	if err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.SyncDaemonResponse{
		Status:            res.Status,
		Config:            res.Config,
		Principals:        res.Principals,
		CaPublicKey:       &res.CAPublicKey,
		StateVersion:      new(s.cfg.Pool.Version(res.WorkspaceID)),
		RevokedPrincipals: res.Revocations,
	}, nil
}

// enrollBinding verifies the DPoP proof presented with the enrollment request
// and returns its key thumbprint (jkt). It advertises a fresh nonce on
// stale-nonce failures so the daemon can retry. A missing proof is an error:
// daemons must enroll key-bound.
func (s *DaemonService) enrollBinding(ctx context.Context) (string, error) {
	svc := s.cfg.IAM
	if svc.DPoP == nil {
		return "", NewError(connect.CodeUnimplemented, "DPoP is not configured")
	}
	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return "", ErrInternal
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
			return "", NewError(connect.CodeUnauthenticated, "stale DPoP nonce")
		}
		return "", NewError(connect.CodeInvalidArgument, "invalid DPoP proof")
	}
	return binding, nil
}
