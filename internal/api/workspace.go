package api

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/nokku-sh/nokku/internal/iam"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/ssh"
)

func defaultWorkspaceSettings() *nokkuv1.WorkspaceSettings {
	return &nokkuv1.WorkspaceSettings{
		DefaultDaemonConfig: &nokkuv1.DaemonConfig{
			RecordSessions:       new(true),
			AllowForwarding:      new(true),
			AllowAgentForwarding: new(true),
			GatewayPorts:         new(false),
			DropRetiredCa:        new(false),
		},
	}
}

type WorkspaceService struct {
	cfg *config.Config
}

func NewWorkspaceService(cfg *config.Config) *WorkspaceService {
	return &WorkspaceService{cfg: cfg}
}

func (s *WorkspaceService) GetWorkspace(
	ctx context.Context,
	req *nokkuv1.GetWorkspaceRequest,
) (*nokkuv1.GetWorkspaceResponse, error) {
	var workspace *db.Workspace
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		workspace, err = q.GetWorkspace(ctx, req.GetWorkspaceId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.GetWorkspaceResponse{
		Workspace: workspace.ToProto(),
	}, nil
}

func (s *WorkspaceService) CreateWorkspace(
	ctx context.Context,
	req *nokkuv1.CreateWorkspaceRequest,
) (*nokkuv1.CreateWorkspaceResponse, error) {
	user, err := s.cfg.IAM.GetUser(ctx)
	if err != nil {
		return nil, DBError(err)
	}

	var count int32
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		count, err = q.CountWorkspacesByOwner(ctx, user.ID)
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if count >= 5 {
		return nil, NewError(connect.CodeResourceExhausted, "maximum number of workspaces reached")
	}

	workspace, err := s.initializeWorkspace(ctx, &db.CreateWorkspaceParams{
		Name:        req.GetName(),
		Description: req.Description,
		CreatedBy:   user.ID,
		Settings:    defaultWorkspaceSettings(),
	})
	if err != nil {
		return nil, DBError(err)
	}
	if workspace == nil {
		return nil, ErrInternal
	}

	return &nokkuv1.CreateWorkspaceResponse{
		Workspace: workspace,
	}, nil
}

func (s *WorkspaceService) UpdateWorkspace(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceRequest,
) (*nokkuv1.UpdateWorkspaceResponse, error) {
	var workspace *db.Workspace
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		base, err := q.GetWorkspace(ctx, req.GetWorkspaceId())
		if err != nil {
			return err
		}

		proto.Merge(base.Settings, req.GetSettings())
		workspace, err = q.UpdateWorkspace(ctx, &db.UpdateWorkspaceParams{
			WorkspaceID: req.GetWorkspaceId(),
			Name:        req.Name,
			Description: req.Description,
			Settings:    base.Settings,
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	if workspace == nil {
		return nil, ErrNotFound
	}

	return &nokkuv1.UpdateWorkspaceResponse{
		Workspace: workspace.ToProto(),
	}, nil
}

func (s *WorkspaceService) DeleteWorkspace(
	ctx context.Context,
	req *nokkuv1.DeleteWorkspaceRequest,
) (*nokkuv1.DeleteWorkspaceResponse, error) {
	if s.cfg.Billing.Enabled() {
		if err := s.cfg.Billing.Cancel(ctx, req.GetWorkspaceId(), true, ""); err != nil {
			return nil, ErrInternal
		}
	}

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteWorkspace(ctx, req.GetWorkspaceId())
	}); err != nil {
		return nil, DBError(err)
	}
	// SSO provider and domain rows cascade through the workspace FK.
	return &nokkuv1.DeleteWorkspaceResponse{}, nil
}

func (s *WorkspaceService) ListWorkspaces(
	ctx context.Context,
	_ *nokkuv1.ListWorkspacesRequest,
) (*nokkuv1.ListWorkspacesResponse, error) {
	var workspaces []*db.Workspace
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		workspaces, err = q.ListWorkspaces(ctx)
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.ListWorkspacesResponse{
		Workspaces: db.WorkspacesToProto(workspaces),
	}, nil
}

func (s *WorkspaceService) GetWorkspaceMember(
	ctx context.Context,
	req *nokkuv1.GetWorkspaceMemberRequest,
) (*nokkuv1.GetWorkspaceMemberResponse, error) {
	if req.GetWorkspaceId() == "" {
		return nil, ErrInvalidInput
	}

	var member *db.WorkspaceMember
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		member, err = q.GetWorkspaceMember(ctx, &db.GetWorkspaceMemberParams{
			WorkspaceID: req.GetWorkspaceId(),
			UserID:      req.GetUserId(),
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}
	result := member.ToProto()

	user, err := s.cfg.IAM.GetUser(ctx)
	if err != nil {
		return nil, DBError(err)
	}
	result.Picture = user.Picture
	result.Email = &user.Email
	result.EmailVerified = &user.EmailVerified
	return &nokkuv1.GetWorkspaceMemberResponse{
		Member: result,
	}, nil
}

func (s *WorkspaceService) UpdateWorkspaceMember(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceMemberRequest,
) (*nokkuv1.UpdateWorkspaceMemberResponse, error) {
	// Ownership moves only through UpdateWorkspaceOwner.
	if !db.IsUserRole(req.GetRoleName()) {
		return nil, NewError(connect.CodeInvalidArgument, "role cannot be assigned to a member")
	}
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.UpdateWorkspaceMember(ctx, &db.UpdateWorkspaceMemberParams{
			WorkspaceID: req.GetWorkspaceId(),
			UserID:      req.GetUserId(),
			RoleName:    req.GetRoleName(),
		})
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.UpdateWorkspaceMemberResponse{}, nil
}

func (s *WorkspaceService) ListWorkspaceMembers(
	ctx context.Context,
	req *nokkuv1.ListWorkspaceMembersRequest,
) (*nokkuv1.ListWorkspaceMembersResponse, error) {
	var members []*db.ListWorkspaceMembersRow
	var count int32
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		count, err = q.CountWorkspaceMembers(ctx, &db.CountWorkspaceMembersParams{
			WorkspaceID: req.GetWorkspaceId(),
			Query:       req.Query,
			RoleName:    req.RoleName,
		})
		if err != nil {
			return err
		}
		members, err = q.ListWorkspaceMembers(ctx, &db.ListWorkspaceMembersParams{
			WorkspaceID: req.GetWorkspaceId(),
			Query:       req.Query,
			RoleName:    req.RoleName,
			Limit:       req.Limit,
			Offset:      req.Offset,
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	protos := make([]*nokkuv1.WorkspaceMember, 0, len(members))
	for _, m := range members {
		protos = append(protos, &nokkuv1.WorkspaceMember{
			Id:            &m.UserID,
			WorkspaceId:   &m.WorkspaceID,
			Name:          &m.Name,
			Email:         &m.Email,
			EmailVerified: &m.EmailVerified,
			Picture:       m.Picture,
			RoleName:      &m.RoleName,
			CreatedAt:     db.SafeTimestamp(&m.CreatedAt),
			UpdatedAt:     db.SafeTimestamp(&m.UpdatedAt),
		})
	}

	return &nokkuv1.ListWorkspaceMembersResponse{
		Members: protos,
		Total:   &count,
	}, nil
}

func (s *WorkspaceService) RemoveWorkspaceMember(
	ctx context.Context,
	req *nokkuv1.RemoveWorkspaceMemberRequest,
) (*nokkuv1.RemoveWorkspaceMemberResponse, error) {
	// Grants and team seats cascade from the membership, so a removed member
	// drops out of every synced principals map.
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.RemoveWorkspaceMember(ctx, &db.RemoveWorkspaceMemberParams{
			WorkspaceID: req.GetWorkspaceId(),
			UserID:      req.GetUserId(),
		})
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.RemoveWorkspaceMemberResponse{}, nil
}

// checkWorkspaceOwner reports whether the request actor owns the workspace.
// The lookup runs on the caller's querier so billing and workspace changes can
// fold it into the transaction that makes the change.
func checkWorkspaceOwner(ctx context.Context, q db.Querier, workspaceID string) error {
	ownerID, err := q.GetWorkspaceOwner(ctx, workspaceID)
	if err != nil {
		return err
	}
	if ownerID != iam.UserIDFromContext(ctx) {
		return ErrPermissionDenied
	}
	return nil
}

func (s *WorkspaceService) UpdateWorkspaceOwner(
	ctx context.Context,
	req *nokkuv1.UpdateWorkspaceOwnerRequest,
) (*nokkuv1.UpdateWorkspaceOwnerResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		if err := checkWorkspaceOwner(ctx, q, req.GetWorkspaceId()); err != nil {
			return err
		}
		_, err := q.UpdateWorkspaceOwner(ctx, &db.UpdateWorkspaceOwnerParams{
			WorkspaceID: req.GetWorkspaceId(),
			NewOwnerID:  req.GetNewOwner(),
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.UpdateWorkspaceOwnerResponse{}, nil
}

func (s *WorkspaceService) SubscribeWorkspaceEvents(
	ctx context.Context,
	req *nokkuv1.SubscribeWorkspaceEventsRequest,
	stream *connect.ServerStream[nokkuv1.SubscribeWorkspaceEventsResponse],
) error {
	workspaceID := req.GetWorkspaceId()
	// Streaming handlers bypass the unary interceptor's workspace promotion,
	// so pin the workspace here and let the scoped transaction verify
	// membership before events start flowing. AnnotateTenant returns a new
	// context; discarding it would leave the pin unset and the membership
	// check below would run against the fallback workspace instead.
	ctx = iam.AnnotateTenant(ctx, workspaceID)
	if err := s.cfg.Conn.WithWorkspace(ctx, func(_ *db.Queries) error {
		return nil
	}); err != nil {
		return DBError(err)
	}

	// Streaming RPCs bypass the unary permission interceptor. Every event
	// this stream carries is daemon lifecycle, so require the same gate the
	// daemon procedures use.
	if err := actorHasPermission(ctx, s.cfg.Conn, db.PermDaemonsView); err != nil {
		return DBError(err)
	}

	msgCh := s.cfg.Pool.SubscribeEvents(workspaceID, req.GetEventTypes())
	defer s.cfg.Pool.UnsubscribeEvents(workspaceID, msgCh)

	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-msgCh:
			if err := stream.Send(event); err != nil {
				return err
			}
		}
	}
}

// Helpers --------------------------------------------------------------------

// initializeWorkspace creates a workspace with all of its dependent records.
// This deliberately runs as a system transaction (bypassing RLS): the
// workspace does not exist yet, so no tenant context can be pinned for it.
func (s *WorkspaceService) initializeWorkspace(
	ctx context.Context,
	params *db.CreateWorkspaceParams,
) (*nokkuv1.Workspace, error) {
	var workspace *db.CreateWorkspaceRow
	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) (err error) {
		workspace, err = q.CreateWorkspace(ctx, params)
		if err != nil {
			return err
		}

		ca, err := ssh.NewCA(
			nokkuv1.CertificateKeyType_CERTIFICATE_KEY_TYPE_ED25519,
			0,
			0,
		)
		if err != nil {
			return err
		}

		if _, err = q.CreateCA(ctx, &db.CreateCAParams{
			WorkspaceID:  workspace.ID,
			Name:         "Default CA",
			Description:  new("Default CA for workspace " + workspace.Name),
			Certificate:  string(ca.Certificate),
			PrivateKey:   ca.PrivateKey,
			PublicKey:    ca.PublicKey,
			SerialNumber: ca.SerialNumber,
			Subject:      ca.Subject,
			IsDefault:    true,
			NotBefore:    ca.NotBefore,
			NotAfter:     ca.NotAfter,
			KeyType:      ca.KeyType,
			KeyBits:      ca.KeyBits,
		}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return workspace.ToProto(), nil
}
