package api

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/storage"
)

const minPasswordLength = 8

var identityMethods = []iam.Method{iam.MethodOIDC, iam.MethodOAuth2, iam.MethodSAML}

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
	u, err := s.cfg.IAM.UpdateSelf(ctx, db.UpdateUserParams{
		Name:                 req.Name,
		Picture:              req.Picture,
		DisablePasswordReset: req.DisablePasswordReset,
	})
	if err != nil {
		return nil, errInternal
	}
	return &nokkuv1.UpdateAccountResponse{User: u.ToProto()}, nil
}

func (s *accountService) ChangePassword(
	ctx context.Context,
	req *nokkuv1.ChangePasswordRequest,
) (*nokkuv1.ChangePasswordResponse, error) {
	userID := actor.UserIDFromContext(ctx)
	// A passwordless account may set its first password without a check.
	has, err := s.cfg.IAM.Password.HasPassword(ctx, userID)
	if err != nil {
		return nil, errInternal
	}
	if has {
		if err := s.cfg.IAM.Password.CheckPassword(
			ctx,
			userID,
			req.GetCurrentPassword(),
		); err != nil {
			return nil, errCurrentPassword
		}
	}
	if len(req.GetNewPassword()) < minPasswordLength {
		return nil, errPasswordTooShort
	}

	// Keep the current session, revoke the rest (NIST 800-63B).
	if err := s.cfg.IAM.Password.Store(ctx, userID, req.GetNewPassword()); err != nil {
		return nil, errInternal
	}
	current, _ := iam.CurrentSession(ctx)
	_, _ = s.cfg.IAM.RevokeOtherSessions(ctx, iam.SessionHash(current.TokenHash))
	return &nokkuv1.ChangePasswordResponse{}, nil
}

// RequestEmailChange asks for the password again, so a hijacked session alone
// cannot move the account. The new address gets the confirm link, the
// current one a notice with the cancel link.
func (s *accountService) RequestEmailChange(
	ctx context.Context,
	req *nokkuv1.RequestEmailChangeRequest,
) (*nokkuv1.RequestEmailChangeResponse, error) {
	u, err := s.cfg.IAM.GetUser(ctx)
	if err != nil {
		return nil, errAccountNotFound
	}
	// The identity provider owns the address of an account it signs in.
	for _, m := range append(slices.Clone(identityMethods), iam.MethodSCIM) {
		if creds, err := s.cfg.IAM.ListCredentialsByType(ctx, m); err != nil {
			return nil, errInternal
		} else if len(creds) > 0 {
			return nil, errEmailManaged
		}
	}
	if has, err := s.cfg.IAM.Password.HasPassword(ctx, u.ID); err != nil {
		return nil, errInternal
	} else if !has {
		return nil, errPasswordNeeded
	}
	if err := s.cfg.IAM.Password.CheckPassword(ctx, u.ID, req.GetCurrentPassword()); err != nil {
		return nil, errCurrentPassword
	}

	confirm, cancel, err := s.cfg.IAM.RequestEmailChange(ctx, u, req.GetNewEmail())
	switch {
	case errors.Is(err, iam.ErrSameEmail):
		return nil, newError(connect.CodeInvalidArgument, "this is already your email address")
	case errors.Is(err, iam.ErrEmailTaken):
		return nil, newError(connect.CodeAlreadyExists, "an account with this email already exists")
	case errors.Is(err, iam.ErrEmailRejected):
		return nil, newError(connect.CodeInvalidArgument, "please enter a valid email address")
	case err != nil:
		return nil, errInternal
	}

	base := s.cfg.FullURL() + "/email-change?"
	newEmail := strings.ToLower(strings.TrimSpace(req.GetNewEmail()))
	err = s.cfg.Email.SendVerificationEmail(
		ctx, u.ID, newEmail, base+"token="+confirm, iam.EmailChangeTTL.String(),
	)
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

func (s *accountService) RemovePassword(
	ctx context.Context,
	req *nokkuv1.RemovePasswordRequest,
) (*nokkuv1.RemovePasswordResponse, error) {
	userID := actor.UserIDFromContext(ctx)
	if err := s.cfg.IAM.Password.CheckPassword(ctx, userID, req.GetCurrentPassword()); err != nil {
		return nil, errCurrentPassword
	}
	if !s.requireRemovable(ctx, iam.MethodPassword) {
		return nil, errLastLoginMethod
	}
	if err := s.cfg.IAM.Password.DeletePassword(ctx, userID); err != nil {
		return nil, errInternal
	}
	return &nokkuv1.RemovePasswordResponse{}, nil
}

func (s *accountService) ListCredentials(
	ctx context.Context,
	_ *nokkuv1.ListCredentialsRequest,
) (*nokkuv1.ListCredentialsResponse, error) {
	types := append(
		[]iam.Method{iam.MethodPassword, iam.MethodPasskey, iam.MethodBackupCode},
		identityMethods...)
	credentials := []*nokkuv1.AccountCredential{}
	for _, typ := range types {
		creds, err := s.cfg.IAM.ListCredentialsByType(ctx, typ)
		if err != nil {
			return nil, errInternal
		}
		for _, c := range creds {
			credentials = append(credentials, c.ToProto())
		}
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
	cred, err := s.cfg.IAM.GetCredential(ctx, req.GetId())
	if err != nil {
		return nil, errAccountNotFound
	}
	if iam.Method(cred.Type) == iam.MethodPasskey {
		if !s.requireRemovable(ctx, iam.MethodPasskey) {
			return nil, errLastLoginMethod
		}
	}
	if err := s.cfg.IAM.DeleteCredential(ctx, req.GetId()); err != nil {
		return nil, errInternal
	}
	return &nokkuv1.RemoveCredentialResponse{}, nil
}

func (s *accountService) RemoveIdentity(
	ctx context.Context,
	req *nokkuv1.RemoveIdentityRequest,
) (*nokkuv1.RemoveIdentityResponse, error) {
	if !s.requireRemovable(ctx, iam.MethodOAuth2) {
		return nil, errLastLoginMethod
	}
	if err := s.cfg.IAM.UnlinkIdentity(ctx, req.GetProvider(), identityMethods...); err != nil {
		return nil, errInternal
	}
	return &nokkuv1.RemoveIdentityResponse{}, nil
}

func (s *accountService) ListBackupCodes(
	ctx context.Context,
	_ *nokkuv1.ListBackupCodesRequest,
) (*nokkuv1.ListBackupCodesResponse, error) {
	creds, err := s.cfg.IAM.ListBackupCodes(ctx)
	if err != nil {
		return nil, errInternal
	}
	codes := make([]*nokkuv1.AccountCredential, 0, len(creds))
	for _, c := range creds {
		codes = append(codes, c.ToProto())
	}
	return &nokkuv1.ListBackupCodesResponse{Codes: codes}, nil
}

func (s *accountService) RotateBackupCodes(
	ctx context.Context,
	_ *nokkuv1.RotateBackupCodesRequest,
) (*nokkuv1.RotateBackupCodesResponse, error) {
	codes, err := s.cfg.IAM.RotateBackupCodes(ctx)
	if err != nil {
		return nil, errInternal
	}
	return &nokkuv1.RotateBackupCodesResponse{Codes: codes}, nil
}

func (s *accountService) RemoveBackupCodes(
	ctx context.Context,
	_ *nokkuv1.RemoveBackupCodesRequest,
) (*nokkuv1.RemoveBackupCodesResponse, error) {
	if err := s.cfg.IAM.DeleteBackupCodes(ctx); err != nil {
		return nil, errInternal
	}
	return &nokkuv1.RemoveBackupCodesResponse{}, nil
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

func (s *accountService) DeleteAccount(
	ctx context.Context,
	_ *nokkuv1.DeleteAccountRequest,
) (*nokkuv1.DeleteAccountResponse, error) {
	u, err := s.cfg.IAM.GetUser(ctx)
	if err != nil {
		return nil, errAccountNotFound
	}

	// Solo workspaces go with the account, so cancel their billing while the
	// subscription rows still exist. Shared ones block the delete below.
	owned, err := s.cfg.Conn.Sys().ListOwnedWorkspaces(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if s.cfg.Billing.Enabled() {
		for _, w := range owned {
			if w.MemberCount > 1 {
				continue
			}
			if err := s.cfg.Billing.Cancel(ctx, w.ID, true, ""); err != nil {
				slog.Warn("failed to cancel subscription", "error", err)
			}
		}
	}

	err = s.cfg.IAM.DeleteUser(ctx)
	if shared, ok := errors.AsType[*iam.SharedWorkspacesError](err); ok {
		return nil, newError(
			connect.CodeFailedPrecondition,
			"transfer ownership of "+strings.Join(shared.Names, ", ")+" before deleting your account",
		)
	}
	if err != nil {
		return nil, errInternal
	}
	if err := s.cfg.Storage.Delete(ctx, storage.AvatarPath(u.ID)); err != nil {
		slog.Warn("failed to delete avatar", "error", err)
	}
	for _, w := range owned {
		if w.MemberCount <= 1 {
			s.cfg.Record.PurgeWorkspace(ctx, w.ID)
		}
	}

	// The session cookie is HttpOnly, only a backend response can clear it.
	if ci, ok := connect.CallInfoForHandlerContext(ctx); ok {
		setCookie(ci, s.cfg.IAM.ClearSessionCookie())
	}
	return &nokkuv1.DeleteAccountResponse{}, nil
}

// requireRemovable reports whether removing rm keeps the account reachable.
// Backup codes are recovery, not a way in.
func (s *accountService) requireRemovable(ctx context.Context, rm iam.Method) bool {
	has := func(m iam.Method) bool {
		creds, err := s.cfg.IAM.ListCredentialsByType(ctx, m)
		return err == nil && len(creds) > 0
	}
	hasIdentity := func() bool {
		return slices.ContainsFunc(identityMethods, has)
	}

	switch rm {
	case iam.MethodPassword:
		return has(iam.MethodPasskey) || hasIdentity()
	case iam.MethodPasskey:
		return has(iam.MethodPassword) || hasIdentity()
	case iam.MethodOIDC, iam.MethodOAuth2, iam.MethodSAML,
		iam.MethodBackupCode, iam.MethodDevice, iam.MethodSCIM:
		return has(iam.MethodPassword) || has(iam.MethodPasskey)
	}
	return false
}
