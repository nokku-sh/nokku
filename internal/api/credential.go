package api

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kagi"
	"github.com/mizuchilabs/kagi/backupcode"
	"github.com/mizuchilabs/kagi/passkey"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/config"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
)

type CredentialService struct {
	cfg *config.Config
}

func NewCredentialService(cfg *config.Config) *CredentialService {
	return &CredentialService{cfg: cfg}
}

func (s *CredentialService) UpdatePassword(
	ctx context.Context,
	req *nokkuv1.UpdatePasswordRequest,
) (*nokkuv1.UpdatePasswordResponse, error) {
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, auth.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}
	if err := checkSSOEnforced(ctx, s.cfg, user.Email); err != nil {
		return nil, err
	}

	// Users without a password (passkey/SSO-only accounts) have no current
	// password to check, so verification is skipped for them.
	if has, err := s.cfg.Auth.HasPassword(ctx, user.ID); err != nil {
		return nil, DBError(err)
	} else if has {
		if err := s.cfg.Auth.CheckPassword(
			ctx,
			user.ID,
			req.GetCurrentPassword(),
		); err != nil {
			return nil, NewError(connect.CodeInvalidArgument, "current password is incorrect")
		}
	}

	if err := s.cfg.Auth.SetPassword(ctx, user.ID, req.GetNewPassword()); err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.UpdatePasswordResponse{}, nil
}

func (s *CredentialService) DeletePassword(
	ctx context.Context,
	req *nokkuv1.DeletePasswordRequest,
) (*nokkuv1.DeletePasswordResponse, error) {
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, auth.UserIDFromContext(ctx))
	if err != nil {
		return nil, ErrNotFound
	}
	if err := checkSSOEnforced(ctx, s.cfg, user.Email); err != nil {
		return nil, err
	}
	if err := s.cfg.Auth.CheckPassword(
		ctx,
		user.ID,
		req.GetCurrentPassword(),
	); err != nil {
		return nil, NewError(connect.CodeInvalidArgument, "password is incorrect")
	}

	if !s.hasOtherLoginMethod(ctx, user.ID) {
		return nil, NewError(
			connect.CodeFailedPrecondition,
			"add a passkey or link an SSO account before removing your password",
		)
	}

	if err := s.cfg.Auth.DeletePassword(ctx, user.ID); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.DeletePasswordResponse{}, nil
}

func (s *CredentialService) ListPasskeys(
	ctx context.Context,
	_ *nokkuv1.ListPasskeysRequest,
) (*nokkuv1.ListPasskeysResponse, error) {
	creds, err := s.cfg.Auth.ListCredentials(
		ctx,
		auth.UserIDFromContext(ctx),
		kagi.CredentialPasskey,
	)
	if err != nil {
		return nil, DBError(err)
	}

	passkeys := make([]*nokkuv1.Passkey, 0, len(creds))
	for _, c := range creds {
		name := passkey.Label(c)
		passkeys = append(passkeys, &nokkuv1.Passkey{
			Id:        &c.ID,
			Name:      &name,
			CreatedAt: timestamppb.New(c.CreatedAt),
		})
	}
	return &nokkuv1.ListPasskeysResponse{Passkeys: passkeys}, nil
}

func (s *CredentialService) RenamePasskey(
	ctx context.Context,
	req *nokkuv1.RenamePasskeyRequest,
) (*nokkuv1.RenamePasskeyResponse, error) {
	userID := auth.UserIDFromContext(ctx)
	cred, err := s.cfg.Auth.GetCredential(ctx, userID, req.GetId())
	if err != nil || cred.Type != kagi.CredentialPasskey {
		return nil, ErrNotFound
	}
	cred.Label = req.GetName()
	cred.UpdatedAt = time.Now()
	if err := s.cfg.Auth.PutCredential(ctx, cred); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.RenamePasskeyResponse{}, nil
}

func (s *CredentialService) DeletePasskey(
	ctx context.Context,
	req *nokkuv1.DeletePasskeyRequest,
) (*nokkuv1.DeletePasskeyResponse, error) {
	userID := auth.UserIDFromContext(ctx)
	cred, err := s.cfg.Auth.GetCredential(ctx, userID, req.GetId())
	if err != nil || cred.Type != kagi.CredentialPasskey {
		return nil, ErrNotFound
	}

	// Ensure the user keeps a password or a linked SSO account.
	if has, err := s.cfg.Auth.HasPassword(ctx, userID); err != nil {
		return nil, DBError(err)
	} else if !has && !s.hasLinkedAccount(ctx, userID) {
		return nil, NewError(
			connect.CodePermissionDenied,
			"set a password or link an SSO account before deleting your passkey",
		)
	}

	if err := s.cfg.Auth.DeleteCredential(ctx, userID, req.GetId()); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.DeletePasskeyResponse{}, nil
}

// hasOtherLoginMethod reports whether the user has any login method besides a
// password: a passkey or a linked SSO account.
func (s *CredentialService) hasOtherLoginMethod(ctx context.Context, userID string) bool {
	if creds, err := s.cfg.Auth.ListCredentials(
		ctx,
		userID,
		kagi.CredentialPasskey,
	); err == nil &&
		len(creds) > 0 {
		return true
	}
	return s.hasLinkedAccount(ctx, userID)
}

// hasLinkedAccount reports whether the user has a linked OIDC/OAuth2/SAML
// identity.
func (s *CredentialService) hasLinkedAccount(ctx context.Context, userID string) bool {
	for _, typ := range []kagi.CredentialType{kagi.CredentialOIDC, kagi.CredentialOAuth2, kagi.CredentialSAML} {
		if creds, err := s.cfg.Auth.ListCredentials(
			ctx,
			userID,
			typ,
		); err == nil &&
			len(creds) > 0 {
			return true
		}
	}
	return false
}

func (s *CredentialService) CreateBackupCodes(
	ctx context.Context,
	_ *nokkuv1.CreateBackupCodesRequest,
) (*nokkuv1.CreateBackupCodesResponse, error) {
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, auth.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}
	if err := checkSSOEnforced(ctx, s.cfg, user.Email); err != nil {
		return nil, err
	}

	codes, err := s.cfg.Auth.GenerateBackupCodes(ctx, user.ID, backupcode.DefaultCount)
	if err != nil {
		return nil, ErrInternal
	}

	return &nokkuv1.CreateBackupCodesResponse{Codes: codes}, nil
}

func (s *CredentialService) ListBackupCodes(
	ctx context.Context,
	_ *nokkuv1.ListBackupCodesRequest,
) (*nokkuv1.ListBackupCodesResponse, error) {
	creds, err := s.cfg.Auth.ListBackupCodes(ctx, auth.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}

	backupCodes := make([]*nokkuv1.BackupCode, len(creds))
	for i, c := range creds {
		backupCodes[i] = &nokkuv1.BackupCode{
			Id:        &c.ID,
			CreatedAt: timestamppb.New(c.CreatedAt),
		}
	}
	return &nokkuv1.ListBackupCodesResponse{Codes: backupCodes}, nil
}

func (s *CredentialService) DeleteBackupCodes(
	ctx context.Context,
	_ *nokkuv1.DeleteBackupCodesRequest,
) (*nokkuv1.DeleteBackupCodesResponse, error) {
	if err := s.cfg.Auth.DeleteBackupCodes(ctx, auth.UserIDFromContext(ctx)); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.DeleteBackupCodesResponse{}, nil
}
