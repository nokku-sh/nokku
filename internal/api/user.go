package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kagi"
	"github.com/mizuchilabs/kagi/tokens"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
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
	actor, _ := kagi.PrincipalFromContext(ctx)
	//nolint:exhaustive // daemon actors never call Whoami; treat them as users
	switch actor.Kind {
	case auth.ActorTypeServiceAccount:
		var result *db.GetServiceAccountRow
		if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
			result, err = q.GetServiceAccount(ctx, actor.SubjectID)
			return err
		}); err != nil {
			return nil, DBError(err)
		}
		if result == nil {
			return nil, ErrNotFound
		}
		return &nokkuv1.WhoamiResponse{
			ServiceAccount: result.ToProto(),
		}, nil
	default:
		user, err := s.cfg.Conn.Q.GetUserByID(ctx, auth.UserIDFromContext(ctx))
		if err != nil {
			return nil, DBError(err)
		}
		return &nokkuv1.WhoamiResponse{
			User: user.ToProto(),
		}, nil
	}
}

func (s *UserService) UpdateProfile(
	ctx context.Context,
	req *nokkuv1.UpdateProfileRequest,
) (*nokkuv1.UpdateProfileResponse, error) {
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, auth.UserIDFromContext(ctx))
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
		token, err := s.cfg.Auth.IssueToken(ctx, user.ID, tokens.PurposeVerify)
		if err != nil {
			return nil, DBError(err)
		}
		verifyURL := fmt.Sprintf("%s/verify?token=%s", s.cfg.FullURL(), token)

		if err = s.cfg.Email.SendVerificationEmail(
			ctx,
			user.ID,
			req.GetEmail(),
			verifyURL,
			s.cfg.Auth.Tokens().TTL().String(),
		); err != nil {
			return nil, ErrRateLimited
		}
		return &nokkuv1.UpdateProfileResponse{EmailSent: new(true)}, nil
	}

	result, err := s.cfg.Conn.Q.UpdateUser(ctx, &db.UpdateUserParams{
		UserID:   auth.UserIDFromContext(ctx),
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
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, auth.UserIDFromContext(ctx))
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

func (s *UserService) ListLinkedAccounts(
	ctx context.Context,
	_ *nokkuv1.ListLinkedAccountsRequest,
) (*nokkuv1.ListLinkedAccountsResponse, error) {
	userID := auth.UserIDFromContext(ctx)

	var accounts []*nokkuv1.OAuthIdentity
	for _, typ := range []kagi.CredentialType{kagi.CredentialOIDC, kagi.CredentialOAuth2, kagi.CredentialSAML} {
		creds, err := s.cfg.Auth.ListCredentials(ctx, userID, typ)
		if err != nil {
			return nil, DBError(err)
		}
		for _, c := range creds {
			accounts = append(accounts, &nokkuv1.OAuthIdentity{
				Provider:   new(c.Provider),
				ProviderId: new(c.Subject),
				Protocol:   new(protocolFromType(c.Type)),
				CreatedAt:  timestamppb.New(c.CreatedAt),
			})
		}
	}
	return &nokkuv1.ListLinkedAccountsResponse{Accounts: accounts}, nil
}

func (s *UserService) UnlinkAccount(
	ctx context.Context,
	req *nokkuv1.UnlinkAccountRequest,
) (*nokkuv1.UnlinkAccountResponse, error) {
	userID := auth.UserIDFromContext(ctx)

	// Workspace identities (enterprise OIDC/SAML) are owned by the
	// organization and cannot be unlinked by the user.
	if req.GetProvider() != "github" && req.GetProvider() != "google" {
		return nil, NewError(
			connect.CodePermissionDenied,
			"workspace identities cannot be unlinked",
		)
	}

	var linked []kagi.Credential
	for _, typ := range []kagi.CredentialType{kagi.CredentialOIDC, kagi.CredentialOAuth2} {
		creds, err := s.cfg.Auth.ListCredentials(ctx, userID, typ)
		if err != nil {
			return nil, DBError(err)
		}
		for _, c := range creds {
			if c.Provider == req.GetProvider() {
				linked = append(linked, c)
			}
		}
	}

	// Prevent losing the last login method.
	if len(linked) > 0 && !s.hasOtherLoginMethod(ctx, userID) {
		return nil, NewError(
			connect.CodeFailedPrecondition,
			"set a password or add a passkey before unlinking your last account",
		)
	}

	for _, c := range linked {
		if err := s.cfg.Auth.DeleteCredential(ctx, userID, c.ID); err != nil {
			return nil, DBError(err)
		}
	}
	return &nokkuv1.UnlinkAccountResponse{}, nil
}

// hasOtherLoginMethod reports whether the user keeps a password or a passkey
// besides the identities being unlinked.
func (s *UserService) hasOtherLoginMethod(ctx context.Context, userID string) bool {
	if has, err := s.cfg.Auth.HasPassword(ctx, userID); err == nil && has {
		return true
	}
	if creds, err := s.cfg.Auth.ListCredentials(
		ctx,
		userID,
		kagi.CredentialPasskey,
	); err == nil &&
		len(creds) > 0 {
		return true
	}
	return false
}

// protocolFromType maps a kagi credential type to the OAuth protocol label.
func protocolFromType(t kagi.CredentialType) string {
	switch t {
	case kagi.CredentialOIDC:
		return "oidc"
	case kagi.CredentialOAuth2:
		return "oauth"
	case kagi.CredentialSAML:
		return "saml"
	case kagi.CredentialPassword,
		kagi.CredentialPasskey,
		kagi.CredentialAPIKey,
		kagi.CredentialKey,
		kagi.CredentialBackupCode:
		return string(t)
	default:
		return string(t)
	}
}

func (s *UserService) SetEmailRecovery(
	ctx context.Context,
	req *nokkuv1.SetEmailRecoveryRequest,
) (*nokkuv1.SetEmailRecoveryResponse, error) {
	if err := s.cfg.Conn.Q.UpdateEmailRecovery(ctx, &db.UpdateEmailRecoveryParams{
		UserID:              auth.UserIDFromContext(ctx),
		EnableEmailRecovery: req.GetEnable(),
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.SetEmailRecoveryResponse{}, nil
}

// Sessions ----------------------------------------------------------------------

// ListUserSessions returns every live session of the calling user, newest
// activity first. It is always scoped to the principal in context; there is
// no way to list another user's sessions.
func (s *UserService) ListUserSessions(
	ctx context.Context,
	_ *nokkuv1.ListUserSessionsRequest,
) (*nokkuv1.ListUserSessionsResponse, error) {
	userID := auth.UserIDFromContext(ctx)
	if userID == "" {
		return nil, ErrNotFound
	}
	sessions, err := s.cfg.Auth.Kagi.Sessions.List(ctx, "", userID)
	if err != nil {
		return nil, DBError(err)
	}

	// The principal carries the raw token of the presenting session, so the
	// UI can mark it as the current one (and warn before revoking it).
	var current string
	if p, ok := kagi.PrincipalFromContext(ctx); ok {
		current = p.SessionToken
	}

	out := make([]*nokkuv1.UserSession, 0, len(sessions))
	for _, s := range sessions {
		id := hex.EncodeToString(s.TokenHash)
		out = append(out, &nokkuv1.UserSession{
			Id:         &id,
			Kind:       new(string(s.Kind)),
			Method:     new(string(s.Method)),
			IdentityId: new(s.IdentityID),
			Binding:    new(s.Binding),
			ExpiresAt:  db.SafeTimestamp(&s.ExpiresAt),
			LastSeen:   db.SafeTimestamp(&s.LastSeenAt),
			IsCurrent:  new(s.Token == current),
		})
	}
	return &nokkuv1.ListUserSessionsResponse{Sessions: out}, nil
}

// RevokeUserSession deletes one of the calling user's sessions by id. The id
// is the session's token hash (the value ListUserSessions returns). The delete
// is scoped to the caller's subject, so a session can only be revoked by the
// user it belongs to.
func (s *UserService) RevokeUserSession(
	ctx context.Context,
	req *nokkuv1.RevokeUserSessionRequest,
) (*nokkuv1.RevokeUserSessionResponse, error) {
	userID := auth.UserIDFromContext(ctx)
	if userID == "" {
		return nil, ErrNotFound
	}
	hash, err := hex.DecodeString(req.GetSessionId())
	if err != nil || len(hash) != 32 {
		return nil, ErrInvalidInput
	}
	if err := s.cfg.Conn.Q.DeleteSessionForSubject(ctx, &db.DeleteSessionForSubjectParams{
		TokenHash: hash,
		SubjectID: userID,
	}); err != nil {
		return nil, DBError(err)
	}
	return &nokkuv1.RevokeUserSessionResponse{}, nil
}
