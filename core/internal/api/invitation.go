package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

// invitationService is the only way an invite becomes an account. The mailed link proves the address.
type invitationService struct {
	cfg *config.Config
}

func (s *invitationService) GetInvitation(
	ctx context.Context,
	req *nokkuv1.GetInvitationRequest,
) (*nokkuv1.GetInvitationResponse, error) {
	token, err := s.cfg.IAM.LookupInvite(ctx, req.GetToken())
	if errors.Is(err, iam.ErrInviteSpent) {
		return nil, errInviteInvalid
	}
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
		Role:          token.Role,
		ExpiresAt:     db.SafeTimestamp(token.ExpiresAt),
	}, nil
}

// AcceptInvitation mails a signup link. The account exists once it is used.
func (s *invitationService) AcceptInvitation(
	ctx context.Context,
	req *nokkuv1.AcceptInvitationRequest,
) (*nokkuv1.AcceptInvitationResponse, error) {
	if !s.cfg.Email.HasSMTP() {
		return nil, newError(connect.CodeUnimplemented, "this server sends no mail, so it takes no invitations")
	}
	err := s.cfg.IAM.RequestSignupLink(ctx, req.GetToken(), req.GetEmail(), req.GetName())
	switch {
	case errors.Is(err, iam.ErrInviteSpent):
		return nil, errInviteInvalid
	case errors.Is(err, iam.ErrEmailTaken):
		return nil, newError(connect.CodeAlreadyExists, "an account with this email already exists, sign in instead")
	case errors.Is(err, iam.ErrEmailRejected):
		return nil, newError(connect.CodeInvalidArgument, "please enter a valid email address")
	case errors.Is(err, iam.ErrMailNotSent):
		return nil, errMailNotSent
	case errors.Is(err, iam.ErrSSORequired):
		return nil, errSSORequired
	case err != nil:
		return nil, err
	}
	return &nokkuv1.AcceptInvitationResponse{}, nil
}
