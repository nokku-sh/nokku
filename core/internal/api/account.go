package api

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect/v2"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/app"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

type accountService struct {
	cfg *app.Config
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
	if _, err := applyMask(req, req.GetUpdateMask()); err != nil {
		return nil, err
	}
	u, err := s.cfg.IAM.UpdateSelf(ctx, req.Name)
	if err != nil {
		return nil, err
	}
	return &nokkuv1.UpdateAccountResponse{User: u.ToProto()}, nil
}

// RequestEmailChange mails the new address to confirm, the old one to cancel.
func (s *accountService) RequestEmailChange(
	ctx context.Context,
	req *nokkuv1.RequestEmailChangeRequest,
) (*nokkuv1.RequestEmailChangeResponse, error) {
	u, err := s.cfg.IAM.GetUser(ctx)
	if err != nil {
		return nil, errAccountNotFound
	}
	if !s.cfg.Email.HasSMTP() {
		return nil, connect.NewError(connect.CodeUnimplemented, "this server sends no mail, ask your administrator")
	}
	// Asked first, a refused request must not replace the pending change.
	if s.cfg.Email.EmailChangeOnCooldown(u.ID) {
		return nil, connect.NewError(
			connect.CodeResourceExhausted,
			"you asked for a change a moment ago, try again later",
		)
	}
	confirm, cancel, err := s.cfg.IAM.RequestEmailChange(ctx, u, req.GetNewEmail())
	switch {
	case errors.Is(err, iam.ErrSameEmail):
		return nil, connect.NewError(connect.CodeInvalidArgument, "this is already your email address")
	case errors.Is(err, iam.ErrEmailTaken):
		return nil, connect.NewError(connect.CodeAlreadyExists, "an account with this email already exists")
	case errors.Is(err, iam.ErrEmailRejected):
		return nil, connect.NewError(connect.CodeInvalidArgument, "please enter a valid email address")
	case errors.Is(err, iam.ErrManagedAccount):
		return nil, errEmailManaged
	case err != nil:
		return nil, err
	}

	ws, _ := actor.WorkspaceFromContext(ctx)
	base := ws.BaseURL + "/email-change?"
	newEmail := iam.NormalizeEmail(req.GetNewEmail())
	err = s.cfg.Email.SendEmailChangeConfirm(ctx, u.ID, newEmail, base+"token="+confirm, iam.EmailChangeTTL)
	if err == nil {
		err = s.cfg.Email.SendEmailChangeNotice(
			ctx,
			u.ID,
			u.Email,
			newEmail,
			base+"cancel=1&token="+cancel,
			iam.EmailRevertTTL,
		)
	}
	if err != nil {
		// Without both mails the change must not stay pending.
		slog.Error("send email change mails", "error", err)
		_ = s.cfg.IAM.DropEmailChange(ctx, u.ID)
		return nil, errMailNotSent
	}
	return &nokkuv1.RequestEmailChangeResponse{}, nil
}

func (s *accountService) ListCredentials(
	ctx context.Context,
	_ *nokkuv1.ListCredentialsRequest,
) (*nokkuv1.ListCredentialsResponse, error) {
	creds, err := s.cfg.IAM.ListCredentials(ctx)
	if err != nil {
		return nil, err
	}
	credentials := make([]*nokkuv1.AccountCredential, 0, len(creds))
	for _, c := range creds {
		credentials = append(credentials, c.ToProto())
	}
	return &nokkuv1.ListCredentialsResponse{Credentials: credentials}, nil
}

func (s *accountService) RenameCredential(
	ctx context.Context,
	req *nokkuv1.RenameCredentialRequest,
) (*nokkuv1.RenameCredentialResponse, error) {
	if err := s.cfg.IAM.RenameCredential(ctx, req.GetId(), req.GetLabel()); err != nil {
		return nil, err
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
		return nil, err
	}
	return &nokkuv1.RemoveCredentialResponse{}, nil
}

func (s *accountService) ListAccountSessions(
	ctx context.Context,
	_ *nokkuv1.ListAccountSessionsRequest,
) (*nokkuv1.ListAccountSessionsResponse, error) {
	current, _ := iam.CurrentToken(ctx)
	sessions, err := s.cfg.IAM.ListSessions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*nokkuv1.AccountSession, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, &nokkuv1.AccountSession{
			Id:         new(sess.ID),
			Kind:       new(sess.Kind),
			Method:     new(sess.Method),
			Binding:    new(sess.Binding),
			Current:    new(sess.ID == current.ID),
			ExpiresAt:  db.SafeTimestamp(sess.ExpiresAt),
			LastSeenAt: db.SafeTimestamp(sess.LastSeenAt),
			FreshFor:   durationpb.New(s.cfg.IAM.FreshFor(sess)),
			UserAgent:  new(sess.UserAgent),
			Ip:         new(sess.Ip),
		})
	}
	// Remembered devices are listed too, those rows are no sessions.
	devices, err := s.cfg.IAM.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range devices {
		out = append(out, &nokkuv1.AccountSession{
			Id:         new(d.ID),
			Kind:       new("device"),
			Method:     new(string(iam.MethodDevice)),
			Binding:    new(""),
			Current:    new(false),
			ExpiresAt:  timestamppb.New(d.ExpiresAt),
			LastSeenAt: timestamppb.New(d.LastSeenAt),
			UserAgent:  new(d.UserAgent),
			Ip:         new(d.Ip),
		})
	}
	return &nokkuv1.ListAccountSessionsResponse{Sessions: out}, nil
}

func (s *accountService) RemoveSession(
	ctx context.Context,
	req *nokkuv1.RemoveSessionRequest,
) (*nokkuv1.RemoveSessionResponse, error) {
	current, _ := iam.CurrentToken(ctx)
	if req.GetId() == current.ID {
		return nil, errCurrentSession
	}
	// The id names a session or a remembered device, the list mixes both.
	if err := s.cfg.IAM.DeleteOwnSession(ctx, req.GetId()); err != nil {
		return nil, err
	}
	if err := s.cfg.IAM.ForgetDevice(ctx, req.GetId()); err != nil {
		return nil, err
	}
	return &nokkuv1.RemoveSessionResponse{}, nil
}

func (s *accountService) DeleteAccount(
	ctx context.Context,
	_ *nokkuv1.DeleteAccountRequest,
) (*nokkuv1.DeleteAccountResponse, error) {
	err := s.cfg.IAM.DeleteSelf(ctx)
	switch {
	case errors.Is(err, iam.ErrOwner):
		return nil, errOwnerAccount
	case errors.Is(err, iam.ErrNotFound):
		return nil, errAccountNotFound
	case err != nil:
		return nil, err
	}
	// The session cookie is HttpOnly, only a server response can clear it.
	if ci, ok := connect.CallInfoForServerContext(ctx); ok {
		setCookie(ci, s.cfg.IAM.ClearSessionCookie())
	}
	return &nokkuv1.DeleteAccountResponse{}, nil
}
