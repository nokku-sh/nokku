package api

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/internal/authn"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
	"github.com/nokku-sh/nokku/internal/storage"
)

type UserService struct {
	cfg *config.Config
}

func NewUserService(cfg *config.Config) *UserService {
	return &UserService{cfg: cfg}
}

func (s *UserService) Whoami(
	ctx context.Context,
	_ *nokkuv1.WhoamiRequest,
) (*nokkuv1.WhoamiResponse, error) {
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.WhoamiResponse{
		User: user.ToProto(),
	}, nil
}

func (s *UserService) UpdateProfile(
	ctx context.Context,
	req *nokkuv1.UpdateProfileRequest,
) (*nokkuv1.UpdateProfileResponse, error) {
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}

	if user.Picture != nil && req.GetPicture() == "" {
		avatarPath := storage.AvatarPath(user.ID)
		if err := s.cfg.Storage.Delete(ctx, avatarPath); err != nil {
			slog.Warn("failed to delete avatar", "error", err)
		}
	}

	// Gate email changes when recovery is disabled
	if !user.EnableEmailRecovery && req.Email != nil && user.Email != req.GetEmail() {
		return nil, NewError(
			connect.CodeFailedPrecondition,
			"enable email recovery before changing your email",
		)
	}

	// Send verification email
	if req.Email != nil && user.Email != req.GetEmail() {
		token, err := s.cfg.Authn.CreateToken(&authn.TokenParams{
			UserID:    user.ID,
			Email:     req.GetEmail(),
			Username:  user.Username,
			TokenType: authn.VerifyToken,
		})
		if err != nil {
			return nil, DBError(err)
		}
		verifyURL := fmt.Sprintf("%s/verify?token=%s", s.cfg.FullURL(), token)

		if err = s.cfg.Email.SendVerificationEmail(
			ctx,
			user.ID,
			req.GetEmail(),
			verifyURL,
			authn.GetExpiry(authn.VerifyToken),
		); err != nil {
			return nil, ErrRateLimited
		}
		return &nokkuv1.UpdateProfileResponse{EmailSent: new(true)}, nil
	}

	result, err := s.cfg.Conn.Q.UpdateUser(ctx, &db.UpdateUserParams{
		UserID:   meta.UserIDFromContext(ctx),
		Name:     req.Name,
		Username: req.Username,
		Picture:  req.Picture,
	})
	if err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.UpdateProfileResponse{
		User: result.ToProto(),
	}, nil
}

func (s *UserService) DeleteAccount(
	ctx context.Context,
	_ *nokkuv1.DeleteAccountRequest,
) (*nokkuv1.DeleteAccountResponse, error) {
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}

	avatarPath := storage.AvatarPath(user.ID)
	if err := s.cfg.Storage.Delete(ctx, avatarPath); err != nil {
		slog.Warn("failed to delete avatar", "error", err)
	}

	if err := s.cfg.Conn.WithTx(ctx, func(q *db.Queries) error {
		workspaceIDs, err := q.GetWorkspacesByOwner(ctx, user.ID)
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
		if err := q.DeleteWorkspacesByOwner(ctx, user.ID); err != nil {
			return err
		}
		return q.DeleteUser(ctx, user.ID)
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.DeleteAccountResponse{}, nil
}

func (s *UserService) ListUserDevices(
	ctx context.Context,
	_ *nokkuv1.ListUserDevicesRequest,
) (*nokkuv1.ListUserDevicesResponse, error) {
	devices, err := s.cfg.Conn.Q.ListUserDevices(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.ListUserDevicesResponse{
		Devices: db.UserDevicesToProto(devices),
	}, nil
}

func (s *UserService) ListLinkedAccounts(
	ctx context.Context,
	_ *nokkuv1.ListLinkedAccountsRequest,
) (*nokkuv1.ListLinkedAccountsResponse, error) {
	identities, err := s.cfg.Conn.Q.GetUserIdentitiesByUserID(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		return nil, DBError(err)
	}

	accounts := make([]*nokkuv1.OAuthIdentity, 0, len(identities))
	for _, id := range identities {
		accounts = append(accounts, &nokkuv1.OAuthIdentity{
			Provider:         new(id.Provider),
			ProviderId:       new(id.ProviderID),
			Protocol:         new(id.Protocol),
			ProviderEmail:    id.ProviderEmail,
			ProviderUsername: id.ProviderUsername,
			CreatedAt:        timestamppb.New(id.CreatedAt),
		})
	}

	return &nokkuv1.ListLinkedAccountsResponse{Accounts: accounts}, nil
}

func (s *UserService) UnlinkAccount(
	ctx context.Context,
	req *nokkuv1.UnlinkAccountRequest,
) (*nokkuv1.UnlinkAccountResponse, error) {
	userID := meta.UserIDFromContext(ctx)

	// Workspace identities (enterprise OIDC/SAML) are owned by the
	// organization and cannot be unlinked by the user.
	if req.GetProvider() != "github" && req.GetProvider() != "google" {
		return nil, NewError(
			connect.CodePermissionDenied,
			"workspace identities cannot be unlinked",
		)
	}

	user, err := s.cfg.Conn.Q.GetUserByID(ctx, userID)
	if err != nil {
		return nil, DBError(err)
	}

	identities, err := s.cfg.Conn.Q.GetUserIdentitiesByUserID(ctx, userID)
	if err != nil {
		return nil, DBError(err)
	}

	// Prevent losing the last login method
	if len(identities) <= 1 && user.PasswordHash == "" {
		passkeys, err := s.cfg.Conn.Q.GetPasskeysByUserID(ctx, userID)
		if err != nil || len(passkeys) == 0 {
			return nil, NewError(
				connect.CodeFailedPrecondition,
				"set a password or add a passkey before unlinking your last account",
			)
		}
	}

	if err := s.cfg.Conn.Q.DeleteUserIdentityByUser(ctx, &db.DeleteUserIdentityByUserParams{
		UserID:   userID,
		Provider: req.GetProvider(),
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.UnlinkAccountResponse{}, nil
}

func (s *UserService) SetEmailRecovery(
	ctx context.Context,
	req *nokkuv1.SetEmailRecoveryRequest,
) (*nokkuv1.SetEmailRecoveryResponse, error) {
	if err := s.cfg.Conn.Q.UpdateEmailRecovery(ctx, &db.UpdateEmailRecoveryParams{
		UserID:              meta.UserIDFromContext(ctx),
		EnableEmailRecovery: req.GetEnable(),
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.SetEmailRecoveryResponse{}, nil
}

func (s *UserService) DeleteUserDevice(
	ctx context.Context,
	req *nokkuv1.DeleteUserDeviceRequest,
) (*nokkuv1.DeleteUserDeviceResponse, error) {
	if err := s.cfg.Conn.Q.DeleteUserDevice(ctx, &db.DeleteUserDeviceParams{
		ID:     req.GetId(),
		UserID: meta.UserIDFromContext(ctx),
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.DeleteUserDeviceResponse{}, nil
}
