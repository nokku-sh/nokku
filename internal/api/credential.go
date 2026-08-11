package api

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
	"github.com/nokku-sh/nokku/internal/util"
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
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}

	if err := checkSSOEnforced(ctx, s.cfg, user.Email); err != nil {
		return nil, err
	}
	if !user.PasswordHash.IsZero() {
		if ok := user.PasswordHash.Verify(req.GetCurrentPassword()); !ok {
			return nil, NewError(connect.CodeInvalidArgument, "current password is incorrect")
		}
	}

	hash, err := crypto.HashPassword(req.GetNewPassword())
	if err != nil {
		return nil, ErrInternal
	}

	if err = s.cfg.Conn.Q.UpdateUserPassword(ctx, &db.UpdateUserPasswordParams{
		UserID:       user.ID,
		PasswordHash: hash,
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.UpdatePasswordResponse{}, nil
}

func (s *CredentialService) DeletePassword(
	ctx context.Context,
	req *nokkuv1.DeletePasswordRequest,
) (*nokkuv1.DeletePasswordResponse, error) {
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		return nil, ErrNotFound
	}

	if err := checkSSOEnforced(ctx, s.cfg, user.Email); err != nil {
		return nil, err
	}
	if ok := user.PasswordHash.Verify(req.GetCurrentPassword()); !ok {
		return nil, NewError(connect.CodeInvalidArgument, "password is incorrect")
	}

	// Ensure user has at least one passkey or linked OAuth account before removing password
	passkeys, err := s.cfg.Conn.Q.GetPasskeysByUserID(ctx, user.ID)
	if err != nil {
		return nil, DBError(err)
	}
	if len(passkeys) == 0 {
		identities, err := s.cfg.Conn.Q.GetUserIdentitiesByUserID(ctx, user.ID)
		if err != nil {
			return nil, DBError(err)
		}
		if len(identities) == 0 {
			return nil, NewError(
				connect.CodeFailedPrecondition,
				"add a passkey or link an OAuth account before removing your password",
			)
		}
	}

	if err = s.cfg.Conn.Q.DeleteUserPassword(ctx, user.ID); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.DeletePasswordResponse{}, nil
}

func (s *CredentialService) UpdatePasskey(
	ctx context.Context,
	req *nokkuv1.UpdatePasskeyRequest,
) (*nokkuv1.UpdatePasskeyResponse, error) {
	credential, err := s.cfg.Conn.Q.GetPasskey(ctx, req.GetId())
	if err != nil {
		return nil, DBError(err)
	}

	if credential.UserID != meta.UserIDFromContext(ctx) {
		return nil, ErrPermissionDenied
	}

	if err = s.cfg.Conn.Q.UpdatePasskeyName(ctx, &db.UpdatePasskeyNameParams{
		PasskeyID: req.GetId(),
		Name:      req.Name,
	}); err != nil {
		return nil, DBError(err)
	}

	credential, err = s.cfg.Conn.Q.GetPasskey(ctx, req.GetId())
	if err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.UpdatePasskeyResponse{
		Passkey: &nokkuv1.Passkey{
			Id:         &credential.ID,
			Name:       credential.Name,
			CreatedAt:  timestamppb.New(credential.CreatedAt),
			LastUsedAt: db.SafeTimestamp(credential.LastUsedAt),
		},
	}, nil
}

func (s *CredentialService) ListPasskeys(
	ctx context.Context,
	_ *nokkuv1.ListPasskeysRequest,
) (*nokkuv1.ListPasskeysResponse, error) {
	credentials, err := s.cfg.Conn.Q.GetPasskeysByUserID(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}

	passkeys := make([]*nokkuv1.Passkey, len(credentials))
	for i, cred := range credentials {
		passkeys[i] = &nokkuv1.Passkey{
			Id:         &cred.ID,
			Name:       cred.Name,
			CreatedAt:  timestamppb.New(cred.CreatedAt),
			LastUsedAt: db.SafeTimestamp(cred.LastUsedAt),
		}
	}

	return &nokkuv1.ListPasskeysResponse{
		Passkeys: passkeys,
	}, nil
}

func (s *CredentialService) DeletePasskey(
	ctx context.Context,
	req *nokkuv1.DeletePasskeyRequest,
) (*nokkuv1.DeletePasskeyResponse, error) {
	credential, err := s.cfg.Conn.Q.GetPasskey(ctx, req.GetId())
	if err != nil {
		return nil, DBError(err)
	}

	if credential.UserID != meta.UserIDFromContext(ctx) {
		return nil, ErrPermissionDenied
	}

	// Ensure user has a password or linked OAuth account before removing passkey
	hasPassword, err := s.cfg.Conn.Q.HasUserPassword(ctx, credential.UserID)
	if err != nil {
		return nil, DBError(err)
	}
	if !hasPassword {
		identities, err := s.cfg.Conn.Q.GetUserIdentitiesByUserID(ctx, credential.UserID)
		if err != nil {
			return nil, DBError(err)
		}
		if len(identities) == 0 {
			return nil, NewError(
				connect.CodePermissionDenied,
				"set a password or link an OAuth account before deleting your passkey",
			)
		}
	}

	if err = s.cfg.Conn.Q.DeletePasskey(ctx, req.GetId()); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.DeletePasskeyResponse{}, nil
}

func (s *CredentialService) CreateBackupCodes(
	ctx context.Context,
	_ *nokkuv1.CreateBackupCodesRequest,
) (*nokkuv1.CreateBackupCodesResponse, error) {
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}

	if err := checkSSOEnforced(ctx, s.cfg, user.Email); err != nil {
		return nil, err
	}

	codes, err := util.GenerateBackupCodes()
	if err != nil {
		return nil, ErrInternal
	}

	hashes := make([]string, len(codes))
	for i, code := range codes {
		hash, err := crypto.HashToken(code)
		if err != nil {
			return nil, ErrInternal
		}
		hashes[i] = hash.Hash()
	}

	// Deletes old ones too
	if err := s.cfg.Conn.Q.CreateBackupCodes(ctx, &db.CreateBackupCodesParams{
		UserID:     meta.UserIDFromContext(ctx),
		CodeHashes: hashes,
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.CreateBackupCodesResponse{
		Codes: codes,
	}, nil
}

func (s *CredentialService) ListBackupCodes(
	ctx context.Context,
	_ *nokkuv1.ListBackupCodesRequest,
) (*nokkuv1.ListBackupCodesResponse, error) {
	codes, err := s.cfg.Conn.Q.ListBackupCodes(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}

	backupCodes := make([]*nokkuv1.BackupCode, len(codes))
	for i, code := range codes {
		backupCodes[i] = &nokkuv1.BackupCode{
			Id:        &code.ID,
			UsedAt:    db.SafeTimestamp(code.UsedAt),
			CreatedAt: db.SafeTimestamp(&code.CreatedAt),
		}
	}
	return &nokkuv1.ListBackupCodesResponse{
		Codes: backupCodes,
	}, nil
}

func (s *CredentialService) DeleteBackupCodes(
	ctx context.Context,
	_ *nokkuv1.DeleteBackupCodesRequest,
) (*nokkuv1.DeleteBackupCodesResponse, error) {
	if err := s.cfg.Conn.Q.DeleteBackupCodes(ctx, meta.UserIDFromContext(ctx)); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.DeleteBackupCodesResponse{}, nil
}
