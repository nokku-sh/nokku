package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/internal/authn"
	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
)

type DaemonService struct {
	cfg *config.Config
}

func NewDaemonService(cfg *config.Config) *DaemonService {
	return &DaemonService{cfg: cfg}
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
		result, err = q.UpdateDaemon(ctx, &db.UpdateDaemonParams{
			DaemonID: req.GetId(),
			Status:   req.GetStatus(),
			Config:   req.GetConfig(),
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	s.cfg.Pool.Broadcast(result.WorkspaceID, &nokkuv1.Notification{
		EventType: nokkuv1.Notification_EVENT_TYPE_STATUS.Enum(),
		DaemonId:  &result.ID,
		Status:    &result.Status,
	})

	if req.GetStatus() == nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
		s.cfg.Pool.PublishWorkspaceEvent(
			result.WorkspaceID,
			"daemon.accepted",
			fmt.Sprintf(`{"daemon_id":%q,"daemon_name":%q}`, result.ID, result.Name),
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
	// A daemon can delete itself via the challenge-auth context; either way
	// one identifier is required.
	if req.GetId() == "" && meta.DaemonIDFromContext(ctx) == "" {
		return nil, ErrInvalidInput
	}
	var result *db.Daemon
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		if req.GetId() != "" {
			result, err = q.DeleteDaemon(ctx, req.GetId())
			if err != nil {
				return err
			}
		} else {
			result, err = q.DeleteDaemon(ctx, meta.DaemonIDFromContext(ctx))
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	status := nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED
	s.cfg.Pool.Broadcast(result.WorkspaceID, &nokkuv1.Notification{
		EventType: nokkuv1.Notification_EVENT_TYPE_STATUS.Enum(),
		DaemonId:  &result.ID,
		Status:    &status,
	})

	s.cfg.Pool.PublishWorkspaceEvent(
		result.WorkspaceID,
		"daemon.removed",
		fmt.Sprintf(`{"daemon_id":%q,"daemon_name":%q}`, result.ID, result.Name),
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
		_, err := q.UpdateWorkspaceSettings(ctx, &db.UpdateWorkspaceSettingsParams{
			WorkspaceID:     req.GetWorkspaceId(),
			EnrollTokenHash: token.Hash,
			EnrollExpiresAt: &expiresAt,
		})
		if err != nil {
			return err
		}
		return nil
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
		_, err := q.UpdateWorkspaceSettings(ctx, &db.UpdateWorkspaceSettingsParams{
			WorkspaceID:     req.GetWorkspaceId(),
			EnrollTokenHash: "",
			EnrollExpiresAt: &time.Time{},
		})
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.RevokeEnrollTokenResponse{}, nil
}

// Session endpoints ----------------------------------------------------------

func (s *DaemonService) CreateSession(
	ctx context.Context,
	req *nokkuv1.CreateSessionRequest,
) (*nokkuv1.CreateSessionResponse, error) {
	var daemon *db.Daemon
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		daemon, err = q.GetDaemon(ctx, req.GetDaemonId())
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	sessionID := uuid.New().String()
	userID := meta.UserIDFromContext(ctx)
	username := req.GetUsername()

	if err := s.cfg.Pool.RequestSession(ctx, daemon.ID, sessionID, username, userID); err != nil {
		return nil, NewError(connect.CodeResourceExhausted, "daemon did not accept session")
	}
	return &nokkuv1.CreateSessionResponse{
		Session: &nokkuv1.Session{
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
	meta.SetAuditWorkspaceID(ctx, workspaceID)

	if err := s.cfg.Billing.Check(ctx, workspaceID, billing.ResourceTargets); err != nil {
		return nil, err
	}

	// The enrollment token (verified below against its stored hash)
	// authorizes this otherwise unauthenticated request, so the daemon
	// provisioning runs as a system transaction without an actor.
	var settings *db.WorkspaceSetting
	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
		settings, err = q.GetWorkspaceSettings(ctx, workspaceID)
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if settings.EnrollExpiresAt != nil && settings.EnrollExpiresAt.Before(time.Now()) {
		return nil, NewError(connect.CodeFailedPrecondition, "enrollment token has expired")
	}
	if !settings.EnrollTokenHash.Verify(req.GetToken()) {
		return nil, NewError(connect.CodeFailedPrecondition, "invalid enrollment token")
	}

	status := nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING
	if settings.EnrollAutoApprove {
		status = nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED
	}

	// Every daemon authenticates with signed request challenges against
	// its registered public key, so nothing secret is stored on the
	// machine.
	authMethod := req.GetAuthMethod()
	authPubkey := req.GetAuthPubkey()
	if authPubkey == "" {
		return nil, NewError(connect.CodeInvalidArgument, "auth_pubkey required")
	}
	if authMethod != "tpm" && authMethod != "soft" {
		return nil, NewError(connect.CodeInvalidArgument, "unsupported auth_method")
	}
	if _, err := authn.ParseAuthPubkey([]byte(authPubkey)); err != nil {
		return nil, NewError(connect.CodeInvalidArgument, "invalid auth_pubkey")
	}

	fingerprint := getHeader(ctx, "Nokku-Daemon-Fingerprint")
	hostname := getHeader(ctx, "Nokku-Daemon-Hostname")
	metadata := daemonMetadata(ctx)

	if strings.TrimSpace(hostname) == "" {
		hostname = "daemon"
	}

	var suffix string
	if fingerprint != "" && len(fingerprint) >= 6 {
		suffix = fingerprint[:6] // Use a chunk of the fingerprint for deterministic naming
	} else {
		suffix = crypto.RandomSuffix(6) // Fallback to a random 6-character hex string
	}

	uniqueName := fmt.Sprintf("%s-%s", hostname, suffix)
	var daemon *db.CreateDaemonRow
	var target *db.Target
	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
		daemon, err = q.CreateDaemon(ctx, &db.CreateDaemonParams{
			ID:          uuid.New().String(),
			WorkspaceID: workspaceID,
			Name:        uniqueName,
			Metadata:    metadata,
			Status:      status,
			Config:      &nokkuv1.DaemonConfig{RecordSessions: new(true)},
			AuthMethod:  authMethod,
			AuthPubkey:  authPubkey,
		})
		if err != nil {
			return err
		}

		tp := &db.UpdateTargetCAParams{DaemonID: &daemon.ID}
		if req.GetCaId() != "" {
			tp.CaID = req.CaId
		}
		target, err = q.UpdateTargetCA(ctx, tp)
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	eventType := "daemon.pending"
	if status == nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
		eventType = "daemon.accepted"
	}
	s.cfg.Pool.PublishWorkspaceEvent(
		daemon.WorkspaceID,
		eventType,
		fmt.Sprintf(`{"daemon_id":%q,"daemon_name":%q}`, daemon.ID, daemon.Name),
	)

	return &nokkuv1.EnrollDaemonResponse{
		Id:          &daemon.ID,
		WorkspaceId: &daemon.WorkspaceID,
		TargetId:    &target.ID,
		Status:      &status,
	}, nil
}

func (s *DaemonService) SyncDaemon(
	ctx context.Context,
	req *nokkuv1.SyncDaemonRequest,
) (*nokkuv1.SyncDaemonResponse, error) {
	metadata := daemonMetadata(ctx)

	var status *nokkuv1.DaemonStatus
	var config *nokkuv1.DaemonConfig
	var principals []*nokkuv1.PrincipalUsers
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		daemon, err := q.GetDaemon(ctx, meta.DaemonIDFromContext(ctx))
		if err != nil {
			return err
		}
		// Stop heartbeat if over quota and on free plan
		if err := s.cfg.Billing.Check(
			ctx,
			daemon.WorkspaceID,
			billing.ResourceTargets,
		); err != nil {
			return err
		}

		status = &daemon.Status
		config = daemon.Config

		if daemon.Status != nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED {
			return errors.New("denied")
		}

		if _, err := q.UpdateDaemon(ctx, &db.UpdateDaemonParams{
			DaemonID: daemon.ID,
			Metadata: metadata,
		}); err != nil {
			return err
		}

		target, err := q.GetTargetByDaemon(ctx, &daemon.ID)
		if err != nil {
			return err
		}

		targetMeta, err := json.Marshal(req.GetMetadata())
		if err != nil {
			return err
		}
		if _, err := q.UpdateTarget(ctx, &db.UpdateTargetParams{
			TargetID:  target.ID,
			Metadata:  targetMeta,
			Endpoints: req.GetPrivateIps(),
		}); err != nil {
			return err
		}

		if err := q.SyncPrincipals(ctx, &db.SyncPrincipalsParams{
			TargetID:  target.ID,
			Usernames: req.GetUsers(),
		}); err != nil {
			return err
		}

		result, err := q.ListPrincipalsForDaemon(ctx, &daemon.ID)
		if err != nil {
			return err
		}
		for _, p := range result {
			principals = append(principals, &nokkuv1.PrincipalUsers{
				Username: &p.Username,
				Ids:      p.Ids,
			})
		}

		return nil
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.SyncDaemonResponse{
		Status:     status,
		Config:     config,
		Principals: principals,
	}, nil
}
