package api

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/storage"
)

type accountService struct {
	cfg *config.Config
}

func newAccountService(cfg *config.Config) *accountService {
	return &accountService{cfg: cfg}
}

func (s *accountService) GetAccount(
	ctx context.Context,
	_ *nokkuv1.GetAccountRequest,
) (*nokkuv1.GetAccountResponse, error) {
	u, err := s.cfg.IAM.GetUser(ctx)
	if err != nil {
		return nil, errAccountNotFound
	}
	user := u.ToProto()
	if pending := s.cfg.IAM.PendingEmail(ctx, u.ID); pending != "" {
		user.PendingEmail = &pending
	}
	return &nokkuv1.GetAccountResponse{User: user}, nil
}

func (s *accountService) UpdateAccount(
	ctx context.Context,
	req *nokkuv1.UpdateAccountRequest,
) (*nokkuv1.UpdateAccountResponse, error) {
	u, err := s.cfg.IAM.UpdateSelf(ctx, req.Name, req.Picture)
	if err != nil {
		return nil, errInternal
	}
	return &nokkuv1.UpdateAccountResponse{User: u.ToProto()}, nil
}

// RequestEmailChange mails the confirm link to the new address and a notice
// with the cancel link to the current one.
func (s *accountService) RequestEmailChange(
	ctx context.Context,
	req *nokkuv1.RequestEmailChangeRequest,
) (*nokkuv1.RequestEmailChangeResponse, error) {
	u, err := s.cfg.IAM.GetUser(ctx)
	if err != nil {
		return nil, errAccountNotFound
	}
	if !s.cfg.Email.HasSMTP() {
		return nil, newError(connect.CodeUnimplemented, "this server sends no mail, ask your administrator")
	}
	confirm, cancel, err := s.cfg.IAM.RequestEmailChange(ctx, u, req.GetNewEmail())
	switch {
	case errors.Is(err, iam.ErrSameEmail):
		return nil, newError(connect.CodeInvalidArgument, "this is already your email address")
	case errors.Is(err, iam.ErrEmailTaken):
		return nil, newError(connect.CodeAlreadyExists, "an account with this email already exists")
	case errors.Is(err, iam.ErrEmailRejected):
		return nil, newError(connect.CodeInvalidArgument, "please enter a valid email address")
	case errors.Is(err, iam.ErrManagedAccount):
		return nil, errEmailManaged
	case err != nil:
		return nil, errInternal
	}

	ws, _ := actor.WorkspaceFromContext(ctx)
	base := ws.BaseURL + "/email-change?"
	newEmail := strings.ToLower(strings.TrimSpace(req.GetNewEmail()))
	err = s.cfg.Email.SendMagicLinkEmail(ctx, u.ID, newEmail, base+"token="+confirm, iam.EmailChangeTTL.String())
	if err == nil {
		err = s.cfg.Email.SendEmailChangeNotice(ctx, u.ID, u.Email, newEmail, base+"cancel=1&token="+cancel, "7 days")
	}
	if err != nil {
		// Without both mails the change must not stay pending.
		slog.Error("send email change mails", "error", err)
		_ = s.cfg.IAM.DropEmailChange(ctx, u.ID)
		return nil, newError(
			connect.CodeUnavailable,
			"the emails could not be sent, try again in a few minutes",
		)
	}
	return &nokkuv1.RequestEmailChangeResponse{}, nil
}

func (s *accountService) ListCredentials(
	ctx context.Context,
	_ *nokkuv1.ListCredentialsRequest,
) (*nokkuv1.ListCredentialsResponse, error) {
	creds, err := s.cfg.IAM.ListCredentials(ctx)
	if err != nil {
		return nil, errInternal
	}
	credentials := make([]*nokkuv1.AccountCredential, 0, len(creds))
	for _, c := range creds {
		// The SCIM link is the provider's, not something the user manages.
		if c.Type == string(iam.MethodSCIM) {
			continue
		}
		credentials = append(credentials, c.ToProto())
	}
	return &nokkuv1.ListCredentialsResponse{Credentials: credentials}, nil
}

func (s *accountService) RenameCredential(
	ctx context.Context,
	req *nokkuv1.RenameCredentialRequest,
) (*nokkuv1.RenameCredentialResponse, error) {
	if err := s.cfg.IAM.RenameCredential(ctx, req.GetId(), req.GetLabel()); err != nil {
		return nil, errInternal
	}
	return &nokkuv1.RenameCredentialResponse{}, nil
}

func (s *accountService) RemoveCredential(
	ctx context.Context,
	req *nokkuv1.RemoveCredentialRequest,
) (*nokkuv1.RemoveCredentialResponse, error) {
	err := s.cfg.IAM.DeleteCredential(ctx, req.GetId())
	switch {
	case errors.Is(err, iam.ErrNotFound):
		return nil, errNotFound
	case errors.Is(err, iam.ErrLastCredential):
		return nil, errLastLoginMethod
	case err != nil:
		return nil, errInternal
	}
	return &nokkuv1.RemoveCredentialResponse{}, nil
}

func (s *accountService) ListAccountSessions(
	ctx context.Context,
	_ *nokkuv1.ListAccountSessionsRequest,
) (*nokkuv1.ListAccountSessionsResponse, error) {
	current, _ := iam.CurrentSession(ctx)
	sessions, err := s.cfg.IAM.ListSessions(ctx)
	if err != nil {
		return nil, errInternal
	}
	out := make([]*nokkuv1.AccountSession, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, &nokkuv1.AccountSession{
			Id:         new(string(sess.TokenHash)),
			Kind:       new(sess.Kind),
			Method:     new(sess.Method),
			Binding:    new(sess.Binding),
			Current:    new(sess.TokenHash == current.TokenHash),
			ExpiresAt:  db.SafeTimestamp(sess.ExpiresAt),
			LastSeenAt: db.SafeTimestamp(sess.LastSeenAt),
			UserAgent:  new(sess.UserAgent),
			Ip:         new(sess.Ip),
		})
	}
	return &nokkuv1.ListAccountSessionsResponse{Sessions: out}, nil
}

func (s *accountService) RemoveSession(
	ctx context.Context,
	req *nokkuv1.RemoveSessionRequest,
) (*nokkuv1.RemoveSessionResponse, error) {
	current, _ := iam.CurrentSession(ctx)
	if req.GetId() == string(current.TokenHash) {
		return nil, errCurrentSession
	}
	if err := s.cfg.IAM.DeleteOwnSession(ctx, iam.SessionHash(req.GetId())); err != nil {
		return nil, errInternal
	}
	return &nokkuv1.RemoveSessionResponse{}, nil
}

// DeleteAccount is refused for the owner, who hands the workspace on first.
func (s *accountService) DeleteAccount(
	ctx context.Context,
	_ *nokkuv1.DeleteAccountRequest,
) (*nokkuv1.DeleteAccountResponse, error) {
	userID := actor.UserIDFromContext(ctx)
	err := s.cfg.IAM.DeleteSelf(ctx)
	switch {
	case errors.Is(err, iam.ErrOwner):
		return nil, errOwnerAccount
	case errors.Is(err, iam.ErrNotFound):
		return nil, errAccountNotFound
	case err != nil:
		return nil, errInternal
	}
	if err := s.cfg.Storage.Delete(ctx, storage.AvatarPath(userID)); err != nil {
		slog.Warn("failed to delete avatar", "error", err)
	}
	// The session cookie is HttpOnly, only a backend response can clear it.
	if ci, ok := connect.CallInfoForHandlerContext(ctx); ok {
		setCookie(ci, s.cfg.IAM.ClearSessionCookie())
	}
	return &nokkuv1.DeleteAccountResponse{}, nil
}
