package api

// The self-service account surface as a Connect service: profile, password,
// credentials, linked identities, backup codes, sessions, and deletion. The
// caller's principal identifies the account; there is no account id in any
// request. Authentication runs in the Connect interceptor chain, which reads
// the same session cookie the HTTP surface used.

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/storage"
)

// minPasswordLength is the floor the proto schema also enforces.
const minPasswordLength = 8

// identityMethods are the external identities the account surface manages.
var identityMethods = []iam.Method{iam.MethodOIDC, iam.MethodOAuth2, iam.MethodSAML}

// Account errors. The messages surface verbatim in the UI, so they carry the
// same guidance the old HTTP codes did.
var (
	errAccountNotFound  = errors.New("account not found")
	errCurrentPassword  = errors.New("current password is incorrect")
	errPasswordTooShort = errors.New("password must be at least 8 characters")
	errLastLoginMethod  = errors.New("add another login method before removing this one")
	errCurrentSession   = errors.New("use logout to end the current session")
	ErrAccountNotFound  = connect.NewError(connect.CodeNotFound, errAccountNotFound)
	ErrCurrentPassword  = connect.NewError(connect.CodeInvalidArgument, errCurrentPassword)
	ErrPasswordTooShort = connect.NewError(connect.CodeInvalidArgument, errPasswordTooShort)
	ErrLastLoginMethod  = connect.NewError(connect.CodeFailedPrecondition, errLastLoginMethod)
	ErrCurrentSession   = connect.NewError(connect.CodeFailedPrecondition, errCurrentSession)
)

type AccountService struct {
	cfg *config.Config
}

func NewAccountService(cfg *config.Config) *AccountService {
	return &AccountService{cfg: cfg}
}

// principal returns the signed-in user principal of the request.
func (s *AccountService) principal(ctx context.Context) iam.Principal {
	p, _ := iam.PrincipalFromContext(ctx)
	return p
}

func (s *AccountService) GetAccount(
	ctx context.Context,
	_ *nokkuv1.GetAccountRequest,
) (*nokkuv1.GetAccountResponse, error) {
	u, err := s.cfg.IAM.GetUser(ctx, s.principal(ctx).ID)
	if err != nil {
		return nil, ErrAccountNotFound
	}
	return &nokkuv1.GetAccountResponse{User: db.UserToProto(u)}, nil
}

func (s *AccountService) UpdateAccount(
	ctx context.Context,
	req *nokkuv1.UpdateAccountRequest,
) (*nokkuv1.UpdateAccountResponse, error) {
	u, err := s.cfg.IAM.UpdateUser(ctx, s.principal(ctx).ID, iam.UpdateUserPatch{
		Name:                 req.Name,
		Picture:              req.Picture,
		DisablePasswordReset: req.DisablePasswordReset,
	})
	if err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.UpdateAccountResponse{User: db.UserToProto(u)}, nil
}

func (s *AccountService) ChangePassword(
	ctx context.Context,
	req *nokkuv1.ChangePasswordRequest,
) (*nokkuv1.ChangePasswordResponse, error) {
	p := s.principal(ctx)
	// A passwordless account sets its first password without a current-
	// password check; with a password present, the check is mandatory.
	has, err := s.cfg.IAM.Password.HasPassword(ctx, p.ID)
	if err != nil {
		return nil, ErrInternal
	}
	if has {
		if err := s.cfg.IAM.Password.CheckPassword(ctx, p.ID, req.GetCurrentPassword()); err != nil {
			return nil, ErrCurrentPassword
		}
	}
	if len(req.GetNewPassword()) < minPasswordLength {
		return nil, ErrPasswordTooShort
	}

	// Replace the hash and revoke the other sessions: the current session
	// survives a deliberate password change, everything else dies (NIST
	// 800-63B).
	if err := s.cfg.IAM.Password.Store(ctx, p.ID, req.GetNewPassword()); err != nil {
		return nil, ErrInternal
	}
	current, _ := iam.CurrentSession(ctx)
	_, _ = s.cfg.IAM.Sessions.RevokeOtherSessions(
		ctx,
		p.ID,
		iam.SessionHash(current.TokenHash),
	)
	return &nokkuv1.ChangePasswordResponse{}, nil
}

func (s *AccountService) RemovePassword(
	ctx context.Context,
	req *nokkuv1.RemovePasswordRequest,
) (*nokkuv1.RemovePasswordResponse, error) {
	p := s.principal(ctx)
	if err := s.cfg.IAM.Password.CheckPassword(ctx, p.ID, req.GetCurrentPassword()); err != nil {
		return nil, ErrCurrentPassword
	}
	// Removing the password must leave the account reachable: a passkey or a
	// linked identity has to remain.
	if !s.requireRemovable(ctx, p.ID, iam.MethodPassword) {
		return nil, ErrLastLoginMethod
	}
	if err := s.cfg.IAM.Password.DeletePassword(ctx, p.ID); err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.RemovePasswordResponse{}, nil
}

// requireRemovable reports whether removing one login method keeps the
// account reachable: a password needs a passkey or an identity left, a
// passkey needs a password or an identity. Backup codes are recovery, not a
// way in, and never satisfy it.
func (s *AccountService) requireRemovable(
	ctx context.Context,
	userID string,
	rm iam.Method,
) bool {
	has := func(m iam.Method) bool {
		creds, err := s.cfg.IAM.ListCredentialsByType(ctx, userID, m)
		return err == nil && len(creds) > 0
	}
	hasIdentity := func() bool {
		return slices.ContainsFunc(identityMethods, has)
	}

	var ok bool
	switch rm {
	case iam.MethodPassword:
		ok = has(iam.MethodPasskey) || hasIdentity()
	case iam.MethodPasskey:
		ok = has(iam.MethodPassword) || hasIdentity()
	default:
		ok = has(iam.MethodPassword) || has(iam.MethodPasskey)
	}
	return ok
}

func (s *AccountService) ListCredentials(
	ctx context.Context,
	_ *nokkuv1.ListCredentialsRequest,
) (*nokkuv1.ListCredentialsResponse, error) {
	types := append(
		[]iam.Method{iam.MethodPassword, iam.MethodPasskey, iam.MethodBackupCode},
		identityMethods...)
	credentials := []*nokkuv1.AccountCredential{}
	for _, typ := range types {
		creds, err := s.cfg.IAM.ListCredentialsByType(ctx, s.principal(ctx).ID, typ)
		if err != nil {
			return nil, ErrInternal
		}
		for _, c := range creds {
			credentials = append(credentials, credentialToProto(c))
		}
	}
	return &nokkuv1.ListCredentialsResponse{Credentials: credentials}, nil
}

func (s *AccountService) RenameCredential(
	ctx context.Context,
	req *nokkuv1.RenameCredentialRequest,
) (*nokkuv1.RenameCredentialResponse, error) {
	err := s.cfg.IAM.RenameCredential(
		ctx,
		s.principal(ctx).ID,
		req.GetId(),
		req.GetLabel(),
	)
	if err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.RenameCredentialResponse{}, nil
}

func (s *AccountService) RemoveCredential(
	ctx context.Context,
	req *nokkuv1.RemoveCredentialRequest,
) (*nokkuv1.RemoveCredentialResponse, error) {
	p := s.principal(ctx)

	cred, err := s.cfg.IAM.GetCredential(ctx, p.ID, req.GetId())
	if err != nil {
		return nil, ErrAccountNotFound
	}
	// Passkeys need a fallback way in; the password and backup codes have
	// their own RPCs.
	if iam.Method(cred.Type) == iam.MethodPasskey {
		if !s.requireRemovable(ctx, p.ID, iam.MethodPasskey) {
			return nil, ErrLastLoginMethod
		}
	}
	if err := s.cfg.IAM.DeleteCredential(ctx, p.ID, req.GetId()); err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.RemoveCredentialResponse{}, nil
}

func (s *AccountService) RemoveIdentity(
	ctx context.Context,
	req *nokkuv1.RemoveIdentityRequest,
) (*nokkuv1.RemoveIdentityResponse, error) {
	p := s.principal(ctx)
	if !s.requireRemovable(ctx, p.ID, iam.MethodOAuth2) {
		return nil, ErrLastLoginMethod
	}
	for _, m := range identityMethods {
		if _, err := s.cfg.IAM.DeleteCredentialsByProvider(
			ctx,
			p.ID,
			m,
			req.GetProvider(),
		); err != nil {
			return nil, ErrInternal
		}
	}
	return &nokkuv1.RemoveIdentityResponse{}, nil
}

func (s *AccountService) ListBackupCodes(
	ctx context.Context,
	_ *nokkuv1.ListBackupCodesRequest,
) (*nokkuv1.ListBackupCodesResponse, error) {
	creds, err := s.cfg.IAM.ListBackupCodes(ctx, s.principal(ctx).ID)
	if err != nil {
		return nil, ErrInternal
	}
	codes := make([]*nokkuv1.AccountCredential, 0, len(creds))
	for _, c := range creds {
		codes = append(codes, credentialToProto(c))
	}
	return &nokkuv1.ListBackupCodesResponse{Codes: codes}, nil
}

func (s *AccountService) RotateBackupCodes(
	ctx context.Context,
	_ *nokkuv1.RotateBackupCodesRequest,
) (*nokkuv1.RotateBackupCodesResponse, error) {
	codes, err := s.cfg.IAM.RotateBackupCodes(ctx, s.principal(ctx).ID)
	if err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.RotateBackupCodesResponse{Codes: codes}, nil
}

func (s *AccountService) RemoveBackupCodes(
	ctx context.Context,
	_ *nokkuv1.RemoveBackupCodesRequest,
) (*nokkuv1.RemoveBackupCodesResponse, error) {
	if err := s.cfg.IAM.DeleteBackupCodes(ctx, s.principal(ctx).ID); err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.RemoveBackupCodesResponse{}, nil
}

func (s *AccountService) ListAccountSessions(
	ctx context.Context,
	_ *nokkuv1.ListAccountSessionsRequest,
) (*nokkuv1.ListAccountSessionsResponse, error) {
	p := s.principal(ctx)
	current, _ := iam.CurrentSession(ctx)
	sessions, err := s.cfg.IAM.Sessions.List(ctx, p.ID)
	if err != nil {
		return nil, ErrInternal
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
		})
	}
	return &nokkuv1.ListAccountSessionsResponse{Sessions: out}, nil
}

func (s *AccountService) RemoveSession(
	ctx context.Context,
	req *nokkuv1.RemoveSessionRequest,
) (*nokkuv1.RemoveSessionResponse, error) {
	current, _ := iam.CurrentSession(ctx)
	if req.GetId() == string(current.TokenHash) {
		return nil, ErrCurrentSession
	}
	if err := s.cfg.IAM.Sessions.DeleteSessionByHash(
		ctx,
		iam.SessionHash(req.GetId()),
	); err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.RemoveSessionResponse{}, nil
}

func (s *AccountService) DeleteAccount(
	ctx context.Context,
	_ *nokkuv1.DeleteAccountRequest,
) (*nokkuv1.DeleteAccountResponse, error) {
	p := s.principal(ctx)
	u, err := s.cfg.IAM.GetUser(ctx, p.ID)
	if err != nil {
		return nil, ErrAccountNotFound
	}

	if err := s.cfg.Storage.Delete(ctx, storage.AvatarPath(u.ID)); err != nil {
		slog.Warn("failed to delete avatar", "error", err)
	}

	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		workspaceIDs, err := q.GetWorkspacesByOwner(ctx, u.ID)
		if err != nil {
			return err
		}
		for _, workspaceID := range workspaceIDs {
			if !s.cfg.Billing.Enabled() {
				break
			}
			if err := s.cfg.Billing.Cancel(ctx, workspaceID, true, ""); err != nil {
				slog.Warn("failed to cancel subscription", "error", err)
			}
		}
		return q.DeleteWorkspacesByOwner(ctx, u.ID)
	}); err != nil {
		return nil, DBError(err)
	}

	if err := s.cfg.IAM.DeleteUser(ctx, u.ID); err != nil {
		return nil, ErrInternal
	}

	// The session cookie is HttpOnly, so only a response from the backend
	// can clear it. Connect carries cookies on the response headers.
	if ci, ok := connect.CallInfoForHandlerContext(ctx); ok {
		ci.ResponseHeader().Add("Set-Cookie", s.cfg.IAM.ClearSessionCookie().String())
	}
	return &nokkuv1.DeleteAccountResponse{}, nil
}

// credentialToProto strips the credential to its metadata: Data holds the
// secret material and never leaves the database.
func credentialToProto(c *db.Credential) *nokkuv1.AccountCredential {
	return &nokkuv1.AccountCredential{
		Id:        new(c.ID),
		Type:      new(c.Type),
		Provider:  new(c.Provider),
		Subject:   new(c.Subject),
		Label:     new(c.Label),
		CreatedAt: db.SafeTimestamp(&c.CreatedAt),
	}
}
