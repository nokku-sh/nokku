package api

import (
	"cmp"
	"context"
	"errors"
	"time"

	"connectrpc.com/connect/v2"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/email"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

// invitationService is the only way an invite becomes an account.
type invitationService struct {
	cfg *config.Config
}

func (s *invitationService) GetInvitation(
	ctx context.Context,
	req *nokkuv1.GetInvitationRequest,
) (*nokkuv1.GetInvitationResponse, error) {
	inv, err := s.cfg.IAM.LookupInvite(ctx, req.GetToken())
	if err != nil {
		return nil, err
	}
	// Read from the row, so a rename shows at once.
	ws, err := s.cfg.Conn.Tenant().GetWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	return &nokkuv1.GetInvitationResponse{
		WorkspaceName: &ws.Name,
		Role:          inv.Role,
		ExpiresAt:     db.SafeTimestamp(&inv.ExpiresAt),
		Email:         &inv.Email,
	}, nil
}

// AcceptInvitation creates the account and signs it in, like ConsumeMagicLink.
func (s *invitationService) AcceptInvitation(
	ctx context.Context,
	req *nokkuv1.AcceptInvitationRequest,
) (*nokkuv1.AcceptInvitationResponse, error) {
	ci, err := callInfo(ctx)
	if err != nil {
		return nil, err
	}
	u, cookie, err := s.cfg.IAM.AcceptInvite(ctx, req.GetToken(), req.GetName())
	switch {
	case errors.Is(err, iam.ErrEmailTaken):
		return nil, connect.NewError(
			connect.CodeAlreadyExists,
			"an account with this email already exists, sign in instead",
		)
	case err != nil:
		return nil, err
	}
	audit.SetTarget(ctx, u.ID)
	setCookie(ci, cookie)
	meta, _ := actor.RequestMetaFromContext(ctx)
	if c := s.cfg.IAM.RememberDevice(ctx, meta.Header, meta.RemoteAddr, u); c != nil {
		setCookie(ci, c)
	}
	return &nokkuv1.AcceptInvitationResponse{User: u.ToProto()}, nil
}

// CreateInvitation replaces any old invite. With no mail it returns the link.
func (s *invitationService) CreateInvitation(
	ctx context.Context,
	req *nokkuv1.CreateInvitationRequest,
) (*nokkuv1.CreateInvitationResponse, error) {
	role := cmp.Or(req.GetRole(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	if !db.CanAssign(callerRole(ctx), role) {
		return nil, connect.NewError(connect.CodePermissionDenied, "role cannot be granted by you")
	}
	address := iam.NormalizeEmail(req.GetEmail())
	audit.SetTarget(ctx, address)
	audit.Set(ctx, "role", db.RoleLabel(role))
	now := time.Now()
	link, err := s.cfg.IAM.Invite(ctx, address, role)
	switch {
	case errors.Is(err, iam.ErrEmailTaken):
		return nil, connect.NewError(connect.CodeAlreadyExists, "this address already has an account here")
	case errors.Is(err, iam.ErrEmailRejected):
		return nil, connect.NewError(connect.CodeInvalidArgument, "this email address cannot receive mail")
	case errors.Is(err, email.ErrCooldown):
		return nil, connect.NewError(connect.CodeResourceExhausted,
			"an invite went to this address in the last 15 minutes, try again later")
	case errors.Is(err, iam.ErrMailNotSent):
		return nil, errMailNotSent
	case err != nil:
		return nil, err
	}
	out := &nokkuv1.CreateInvitationResponse{
		Invitation: &nokkuv1.Invitation{
			Email:     &address,
			Role:      &role,
			ExpiresAt: db.SafeTimestamp(new(now.Add(iam.InviteTTL))),
			CreatedAt: db.SafeTimestamp(&now),
		},
	}
	if link != "" {
		out.Link = &link
	}
	return out, nil
}

func (s *invitationService) ListInvitations(
	ctx context.Context,
	_ *nokkuv1.ListInvitationsRequest,
) (*nokkuv1.ListInvitationsResponse, error) {
	rows, err := s.cfg.Conn.Tenant().ListInvites(ctx)
	if err != nil {
		return nil, err
	}
	return &nokkuv1.ListInvitationsResponse{Invitations: db.InvitesToProto(rows)}, nil
}

func (s *invitationService) DeleteInvitation(
	ctx context.Context,
	req *nokkuv1.DeleteInvitationRequest,
) (*nokkuv1.DeleteInvitationResponse, error) {
	address := iam.NormalizeEmail(req.GetEmail())
	audit.SetTarget(ctx, address)
	n, err := s.cfg.Conn.Tenant().DeleteInvite(ctx, address)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, connect.NewError(connect.CodeNotFound, "no pending invite for this address")
	}
	return &nokkuv1.DeleteInvitationResponse{}, nil
}
