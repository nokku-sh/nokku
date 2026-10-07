package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

// invitationService is the mailed way into a workspace. The passkey way
// goes through /passkey/signup with the same invite.
type invitationService struct {
	cfg *config.Config
}

func newInvitationService(cfg *config.Config) *invitationService {
	return &invitationService{cfg: cfg}
}

var errInviteInvalid = connect.NewError(
	connect.CodeFailedPrecondition,
	errors.New("invalid or expired invitation"),
)

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
	ws, _ := actor.WorkspaceFromContext(ctx)
	return &nokkuv1.GetInvitationResponse{
		WorkspaceName: &ws.Name,
		Role:          token.RoleName,
		ExpiresAt:     db.SafeTimestamp(token.ExpiresAt),
	}, nil
}

// AcceptInvitation mails a signup link. The account exists once it is used.
func (s *invitationService) AcceptInvitation(
	ctx context.Context,
	req *nokkuv1.AcceptInvitationRequest,
) (*nokkuv1.AcceptInvitationResponse, error) {
	if !s.cfg.Email.HasSMTP() {
		return nil, newError(connect.CodeUnimplemented, "this server sends no mail, sign up with a passkey")
	}
	err := s.cfg.IAM.RequestSignupLink(ctx, req.GetToken(), req.GetEmail(), req.GetName())
	switch {
	case errors.Is(err, iam.ErrInviteSpent):
		return nil, errInviteInvalid
	case errors.Is(err, iam.ErrEmailTaken):
		return nil, newError(connect.CodeAlreadyExists, "an account with this email already exists, sign in instead")
	case errors.Is(err, iam.ErrEmailRejected):
		return nil, newError(connect.CodeInvalidArgument, "please enter a valid email address")
	case err != nil:
		return nil, err
	}
	return &nokkuv1.AcceptInvitationResponse{}, nil
}
