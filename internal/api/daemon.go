package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/mizuchilabs/kagi"
	"github.com/mizuchilabs/kagi/dpop"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/meta"
	"github.com/nokku-sh/nokku/internal/namegen"
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
	// A daemon can delete itself via the challenge-auth context. Either way
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

	// A deleted daemon discovers its removal on the next sync (not found).
	s.cfg.Pool.NotifyChange(result.WorkspaceID)

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
	var workspace *db.Workspace
	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
		workspace, err = q.GetWorkspace(ctx, workspaceID)
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if workspace.EnrollExpiresAt != nil && workspace.EnrollExpiresAt.Before(time.Now()) {
		return nil, NewError(connect.CodeFailedPrecondition, "enrollment token has expired")
	}
	if !workspace.EnrollTokenHash.Verify(req.GetToken()) {
		return nil, NewError(connect.CodeFailedPrecondition, "invalid enrollment token")
	}

	status := nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING
	if workspace.Settings.GetEnrollAutoApprove() {
		status = nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED
	}

	// The daemon proves possession of its TPM/software key with a DPoP proof
	// bound to this enrollment request; the issued session is bound to that
	// key (jkt), so a stolen token is useless without the key. The proof is
	// the only machine credential: nothing secret is stored on the daemon.
	binding, err := s.enrollBinding(ctx)
	if err != nil {
		return nil, err
	}

	// New daemons inherit the workspace's adjustable default config, so a
	// freshly deployed daemon picks up the current SSH server policy.
	config := workspace.Settings.GetDefaultDaemonConfig()

	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return nil, ErrInternal
	}
	h := ci.RequestHeader()
	metadata, _ := json.Marshal(map[string]string{
		"user-agent": h.Get("User-Agent"),
		"host":       h.Get("Host"),
	})

	// Names are generated server-side so a workspace never shows a duplicate
	// label. A collision is a unique violation on (workspace_id, name); we
	// retry with a numeric suffix before giving up.
	var daemon *db.CreateDaemonRow
	var target *db.Target
	base := namegen.Generate()
	name := base
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			name = base + "-" + strconv.Itoa(attempt+1)
		}

		err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
			daemon, err = q.CreateDaemon(ctx, &db.CreateDaemonParams{
				WorkspaceID: workspaceID,
				Name:        name,
				Metadata:    metadata,
				Status:      status,
				Config:      config,
			})
			if err != nil {
				return err
			}

			if req.GetCaId() != "" {
				target, err = q.UpdateTargetCA(ctx, &db.UpdateTargetCAParams{
					DaemonID: &daemon.ID,
					CaID:     req.CaId,
				})
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err == nil {
			break
		}
		if !isUniqueViolation(err) || attempt >= 4 {
			return nil, DBError(err)
		}
	}

	// The daemon's control-plane token never expires; it is revoked by
	// deleting the daemon (the session cascades), not by a clock.
	sess, err := s.cfg.Auth.Kagi.Sessions.IssueSession(ctx, kagi.SessionParams{
		TenantID:  kagi.TenantID(workspaceID),
		SubjectID: daemon.ID,
		Kind:      auth.KindDaemon,
		Method:    kagi.MethodDevice,
		Binding:   binding,
	})
	if err != nil {
		return nil, ErrInternal
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
		Config:      config,
		AccessToken: &sess.Token,
	}, nil
}

// enrollBinding verifies the DPoP proof presented with the enrollment request
// and returns its key thumbprint (jkt). It advertises a fresh nonce on
// stale-nonce failures so the daemon can retry. A missing proof is an error:
// daemons must enroll key-bound.
func (s *DaemonService) enrollBinding(ctx context.Context) (string, error) {
	verifier := s.cfg.Auth.DPoP()
	if verifier == nil {
		return "", NewError(connect.CodeUnimplemented, "DPoP is not configured")
	}
	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return "", ErrInternal
	}

	binding, err := verifier.VerifyRequest(
		ctx,
		ci.RequestHeader(),
		nokkuv1connect.DaemonServiceEnrollDaemonProcedure,
		s.cfg.FullURL(),
	)
	if err != nil {
		if errors.Is(err, dpop.ErrStaleNonce) {
			ci.ResponseHeader().Set("DPoP-Nonce", verifier.CurrentNonce())
			return "", NewError(connect.CodeUnauthenticated, "stale DPoP nonce")
		}
		return "", NewError(connect.CodeInvalidArgument, "invalid DPoP proof")
	}
	return binding, nil
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

	var workspaceID string
	var status *nokkuv1.DaemonStatus
	var config *nokkuv1.DaemonConfig
	var principals []*nokkuv1.PrincipalUsers
	var caPublicKey string
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

		// The workspace recording key rides along so the daemon seals
		// recordings with the current key and detects regenerations.
		workspace, err := q.GetWorkspace(ctx, daemon.WorkspaceID)
		if err != nil {
			return err
		}
		config.RecordingPublicKey = workspace.Settings.RecordingPublicKey

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
			Metadata: metadata,
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
			caPublicKey = ca.PublicKey
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
		Status:       status,
		Config:       config,
		Principals:   principals,
		CaPublicKey:  &caPublicKey,
		StateVersion: new(s.cfg.Pool.Version(workspaceID)),
	}, nil
}
