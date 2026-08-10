package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/authn"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/email"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
	"github.com/nokku-sh/nokku/internal/util"
)

type CLISession struct {
	User       *nokkuv1.User `json:"user,omitempty"`
	Hostname   string        `json:"hostname,omitempty"`
	DeviceID   string        `json:"device_id,omitempty"`
	AuthMethod string        `json:"auth_method,omitempty"`
	AuthPubkey string        `json:"auth_pubkey,omitempty"`
}

type AuthService struct {
	cfg *config.Config
}

func NewAuthService(cfg *config.Config) *AuthService {
	return &AuthService{cfg: cfg}
}

func (s *AuthService) Register(
	ctx context.Context,
	req *nokkuv1.RegisterRequest,
) (*nokkuv1.RegisterResponse, error) {
	meta.SetAuditEmail(ctx, req.GetEmail())
	if req.GetUsername() == "" || req.GetEmail() == "" || req.GetPassword() == "" {
		return nil, ErrFieldMissing
	}
	if len(req.GetPassword()) < 8 {
		return nil, NewError(connect.CodeInvalidArgument, "password must be at least 8 characters")
	}

	// Validate email: syntax, MX records, disposable domain check
	if err := email.Verify(req.GetEmail()); err != nil {
		return nil, NewError(connect.CodeInvalidArgument, "invalid email address")
	}

	found, err := s.cfg.Conn.Q.EmailExists(ctx, req.GetEmail())
	if err != nil {
		return nil, ErrInternal
	}
	if found {
		return nil, ErrEmailTaken
	}

	if err := checkSSOEnforced(ctx, s.cfg, req.GetEmail()); err != nil {
		return nil, err
	}
	hash, err := crypto.HashPassword(req.GetPassword())
	if err != nil {
		return nil, ErrInternal
	}

	newUser, err := s.cfg.Conn.Q.CreateUser(ctx, &db.CreateUserParams{
		Name:         req.GetName(),
		Username:     req.GetUsername(),
		Email:        req.GetEmail(),
		PasswordHash: hash,
	})
	if err != nil {
		return nil, ErrInternal
	}

	token, err := s.cfg.Authn.CreateToken(&authn.TokenParams{
		UserID:    newUser.ID,
		Email:     newUser.Email,
		Username:  newUser.Username,
		TokenType: authn.VerifyToken,
	})
	if err != nil {
		return nil, ErrInternal
	}
	verifyURL := fmt.Sprintf("%s/verify?token=%s", s.cfg.FullURL(), token)

	if err := s.cfg.Email.SendWelcomeEmail(
		ctx,
		newUser.ID,
		newUser.Email,
		newUser.Username,
		verifyURL,
		authn.GetExpiry(authn.VerifyToken),
	); err != nil {
		// Even if email fails, user is registered
		slog.Error("failed to send welcome email", "error", err)
	}
	meta.SetAuditUserID(ctx, newUser.ID)
	return &nokkuv1.RegisterResponse{}, nil
}

func (s *AuthService) Login(
	ctx context.Context,
	req *nokkuv1.LoginRequest,
) (*nokkuv1.LoginResponse, error) {
	meta.SetAuditEmail(ctx, req.GetEmail())
	var user *db.User
	var err error

	user, err = s.cfg.Conn.Q.GetUserByEmail(ctx, req.GetEmail())
	if err != nil || user == nil {
		return nil, ErrBadCredentials
	}

	// Fail generically on account state so the response never reveals
	// whether an account exists, is deactivated or unverified.
	if !user.IsActive || !user.EmailVerified || user.PasswordHash.IsZero() {
		return nil, ErrBadCredentials
	}

	if err := checkSSOEnforced(ctx, s.cfg, req.GetEmail()); err != nil {
		return nil, err
	}
	if ok := user.PasswordHash.Verify(req.GetPassword()); !ok {
		return nil, ErrBadCredentials
	}

	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return nil, ErrInternal
	}
	accessToken := s.cfg.Authn.AccessCookie(ctx, ci.ResponseHeader(), user)
	refreshToken := s.cfg.Authn.RefreshCookie(ctx, ci.ResponseHeader(), user)
	syncWebDevice(ctx, s.cfg, ci.RequestHeader(), ci.ResponseHeader(), ci.Peer().Addr, user)
	meta.SetAuditUserID(ctx, user.ID)

	return &nokkuv1.LoginResponse{
		AccessToken:  &accessToken,
		RefreshToken: &refreshToken,
	}, nil
}

func (s *AuthService) LoginWithBackupCode(
	ctx context.Context,
	req *nokkuv1.LoginWithBackupCodeRequest,
) (*nokkuv1.LoginWithBackupCodeResponse, error) {
	meta.SetAuditEmail(ctx, req.GetEmail())
	user, err := s.cfg.Conn.Q.GetUserByEmail(ctx, req.GetEmail())
	if err != nil || user == nil {
		return nil, ErrBadCredentials
	}

	// Fail generically on account state so the response never reveals
	// whether an account exists, is deactivated or unverified.
	if !user.IsActive || !user.EmailVerified {
		return nil, ErrBadCredentials
	}

	// Backup codes must not work when SSO is enforced.
	if err := checkSSOEnforced(ctx, s.cfg, req.GetEmail()); err != nil {
		return nil, err
	}

	receivedCode := util.NormalizeBackupCode(req.GetCode())
	hash, err := crypto.HashToken(receivedCode)
	if err != nil {
		return nil, ErrInternal
	}

	_, err = s.cfg.Conn.Q.UseBackupCode(ctx, &db.UseBackupCodeParams{
		UserID:   user.ID,
		CodeHash: hash,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, NewError(connect.CodeInvalidArgument, "invalid or used backup code")
		}
		return nil, ErrInternal
	}

	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return nil, ErrInternal
	}

	accessToken := s.cfg.Authn.AccessCookie(ctx, ci.ResponseHeader(), user)
	refreshToken := s.cfg.Authn.RefreshCookie(ctx, ci.ResponseHeader(), user)
	syncWebDevice(ctx, s.cfg, ci.RequestHeader(), ci.ResponseHeader(), ci.Peer().Addr, user)
	meta.SetAuditUserID(ctx, user.ID)

	return &nokkuv1.LoginWithBackupCodeResponse{
		AccessToken:  &accessToken,
		RefreshToken: &refreshToken,
	}, nil
}

func (s *AuthService) RefreshToken(
	ctx context.Context,
	req *nokkuv1.RefreshTokenRequest,
) (*nokkuv1.RefreshTokenResponse, error) {
	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return nil, ErrInternal
	}

	token := req.GetRefreshToken()
	if token == "" {
		token = authn.GetRefreshToken(ci.RequestHeader())
	}

	if token == "" {
		authn.ClearCookies(ci.ResponseHeader())
		return nil, NewError(connect.CodeUnauthenticated, "session expired")
	}

	claims, err := s.cfg.Authn.VerifyToken(token)
	if err != nil || claims.TokenType != "refresh" {
		authn.ClearCookies(ci.ResponseHeader())
		return nil, NewError(connect.CodeUnauthenticated, "session expired")
	}

	user, err := s.cfg.Conn.Q.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil || !user.IsActive {
		authn.ClearCookies(ci.ResponseHeader())
		return nil, ErrSessionExpired
	}

	// Refreshing requires a known web device. Deleting a device row revokes
	// its sessions: without a matching device the refresh is denied and the
	// browser is logged out once its access token expires.
	deviceID, ok := verifyWebDevice(ctx, s.cfg, ci.RequestHeader(), user.ID)
	if !ok {
		authn.ClearCookies(ci.ResponseHeader())
		return nil, NewError(connect.CodeUnauthenticated, "session expired")
	}
	// A refresh counts as device activity, keeping the sliding 6-month
	// device expiry honest for sessions that never do a full re-login.
	_ = s.cfg.Conn.Q.UpdateUserDeviceUsage(ctx, deviceID)

	// Reuse detection: remember the current refresh token's jti per device.
	// A valid but stale jti means a previously rotated refresh token was
	// replayed, assume theft, revoke the device and log the session out.
	stateKey := "refresh:" + deviceID
	if current, err := s.cfg.Cache.Get(
		ctx,
		stateKey,
	); err == nil && len(current) > 0 &&
		string(current) != claims.Jti {
		_ = s.cfg.Cache.Delete(ctx, stateKey)
		_ = s.cfg.Conn.Q.DeleteUserDevice(
			ctx,
			&db.DeleteUserDeviceParams{ID: deviceID, UserID: user.ID},
		)
		authn.ClearCookies(ci.ResponseHeader())
		return nil, NewError(connect.CodeUnauthenticated, "session expired")
	}

	accessToken := s.cfg.Authn.AccessCookie(ctx, ci.ResponseHeader(), user)

	// Rotate the refresh token: every refresh issues a fresh token whose jti
	// becomes the expected value for this device. If the cache entry evicted
	// (24h sweep on the memory backend), reuse detection simply resets until
	// the next refresh writes it again.
	newRefresh, err := s.cfg.Authn.CreateToken(&authn.TokenParams{
		UserID:    user.ID,
		Email:     user.Email,
		Username:  user.Username,
		TokenType: authn.RefreshToken,
	})
	if err != nil {
		return nil, ErrInternal
	}
	newClaims, err := s.cfg.Authn.VerifyToken(newRefresh)
	if err != nil {
		return nil, ErrInternal
	}
	authn.SetRefreshCookie(ci.ResponseHeader(), newRefresh)
	_ = s.cfg.Cache.Set(ctx, stateKey, []byte(newClaims.Jti), authn.GetTokenTTL(authn.RefreshToken))

	meta.SetAuditUserID(ctx, user.ID)
	return &nokkuv1.RefreshTokenResponse{
		AccessToken: &accessToken,
	}, nil
}

func (s *AuthService) ForgotPassword(
	ctx context.Context,
	req *nokkuv1.ForgotPasswordRequest,
) (*nokkuv1.ForgotPasswordResponse, error) {
	meta.SetAuditEmail(ctx, req.GetEmail())
	user, err := s.cfg.Conn.Q.GetUserByEmail(ctx, req.GetEmail())
	if err != nil {
		slog.Error("failed to look up user for password reset", "error", err)
		return nil, ErrInternal
	}
	if user == nil {
		return &nokkuv1.ForgotPasswordResponse{}, nil
	}

	if !user.EnableEmailRecovery {
		return &nokkuv1.ForgotPasswordResponse{}, nil
	}

	token, err := s.cfg.Authn.CreateToken(&authn.TokenParams{
		UserID:    user.ID,
		Email:     user.Email,
		Username:  user.Username,
		TokenType: authn.VerifyToken,
	})
	if err != nil {
		slog.Error("failed to create verification token", "error", err)
		return nil, ErrInternal
	}
	recoveryURL := fmt.Sprintf("%s/reset?token=%s", s.cfg.FullURL(), token)

	if err := s.cfg.Email.SendRecoveryEmail(
		ctx,
		user.ID,
		user.Email,
		recoveryURL,
		authn.GetExpiry(authn.VerifyToken),
	); err != nil {
		slog.Error("failed to send recovery email", "error", err)
	}

	return &nokkuv1.ForgotPasswordResponse{}, nil
}

func (s *AuthService) ResendVerification(
	ctx context.Context,
	req *nokkuv1.ResendVerificationRequest,
) (*nokkuv1.ResendVerificationResponse, error) {
	meta.SetAuditEmail(ctx, req.GetEmail())
	user, err := s.cfg.Conn.Q.GetUserByEmail(ctx, req.GetEmail())
	if err != nil {
		return nil, ErrInternal
	}
	if user == nil {
		return &nokkuv1.ResendVerificationResponse{}, nil
	}

	if !user.EnableEmailRecovery {
		return &nokkuv1.ResendVerificationResponse{}, nil
	}

	// Send async to avoid response latency measurement
	go func(ctx context.Context) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()

		token, err := s.cfg.Authn.CreateToken(&authn.TokenParams{
			UserID:    user.ID,
			Email:     user.Email,
			Username:  user.Username,
			TokenType: authn.VerifyToken,
		})
		if err != nil {
			slog.Debug("failed to create verification token", "error", err)
			return
		}
		verifyURL := fmt.Sprintf("%s/verify?token=%s", s.cfg.FullURL(), token)

		if err := s.cfg.Email.SendVerificationEmail(
			ctx,
			user.ID,
			user.Email,
			verifyURL,
			authn.GetExpiry(authn.VerifyToken),
		); err != nil {
			slog.Debug("failed to send verification email", "error", err)
			return
		}
	}(ctx)

	return &nokkuv1.ResendVerificationResponse{}, nil
}

func (s *AuthService) VerifyEmail(
	ctx context.Context,
	req *nokkuv1.VerifyEmailRequest,
) (*nokkuv1.VerifyEmailResponse, error) {
	token := req.GetToken()
	if token == "" {
		return nil, ErrFieldMissing
	}

	claims, err := s.cfg.Authn.VerifyToken(token)
	if err != nil || claims.TokenType != "verification" {
		return nil, ErrTokenInvalid
	}

	if err = s.cfg.Conn.Q.VerifyUserEmail(ctx, &db.VerifyUserEmailParams{
		UserID: claims.UserID,
		Email:  claims.Email,
	}); err != nil {
		return nil, ErrInternal
	}
	meta.SetAuditUserID(ctx, claims.UserID)
	meta.SetAuditEmail(ctx, claims.Email)

	return &nokkuv1.VerifyEmailResponse{}, nil
}

func (s *AuthService) ResetPassword(
	ctx context.Context,
	req *nokkuv1.ResetPasswordRequest,
) (*nokkuv1.ResetPasswordResponse, error) {
	token := req.GetToken()
	if token == "" {
		return nil, ErrFieldMissing
	}

	claims, err := s.cfg.Authn.VerifyToken(token)
	if err != nil || claims.TokenType != "verification" {
		return nil, ErrTokenInvalid
	}

	hash, err := crypto.HashPassword(req.GetNewPassword())
	if err != nil {
		return nil, ErrInternal
	}

	err = s.cfg.Conn.Q.UpdateUserPassword(ctx, &db.UpdateUserPasswordParams{
		UserID:       claims.UserID,
		PasswordHash: hash,
	})
	if err != nil {
		return nil, ErrInternal
	}
	meta.SetAuditUserID(ctx, claims.UserID)
	meta.SetAuditEmail(ctx, claims.Email)

	return &nokkuv1.ResetPasswordResponse{}, nil
}

func (s *AuthService) Logout(
	ctx context.Context,
	_ *nokkuv1.LogoutRequest,
) (*nokkuv1.LogoutResponse, error) {
	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if ok {
		authn.ClearCookies(ci.ResponseHeader())
	}
	return &nokkuv1.LogoutResponse{}, nil
}

func (s *AuthService) StreamCLILogin(
	ctx context.Context,
	req *nokkuv1.StreamCLILoginRequest,
	stream *connect.ServerStream[nokkuv1.StreamCLILoginResponse],
) error {
	loginCode, err := s.cfg.Authn.CreateToken(&authn.TokenParams{TokenType: authn.CLIToken})
	if err != nil {
		return ErrInternal
	}

	hostname := getHeader(ctx, "nokku-client-hostname")
	deviceID := getHeader(ctx, "nokku-client-device-id")
	sessionData, err := json.Marshal(&CLISession{
		Hostname:   hostname,
		DeviceID:   deviceID,
		AuthMethod: req.GetAuthMethod(),
		AuthPubkey: req.GetAuthPubkey(),
	})
	if err != nil {
		return ErrInternal
	}
	_ = s.cfg.Cache.Set(ctx, loginCode, sessionData, 5*time.Minute)

	defer func() { _ = s.cfg.Cache.Delete(ctx, loginCode) }()

	verificationURL := fmt.Sprintf("%s/login?token=%s", s.cfg.FullURL(), loginCode)
	if err := stream.Send(&nokkuv1.StreamCLILoginResponse{
		VerificationUrl: &verificationURL,
	}); err != nil {
		return err
	}

	// Poll the cache for the verified session. VerifyCLILogin (running on the
	// user's authenticated web session) writes the user into the same cache
	// entry when it approves the login.
	timeout := time.After(5 * time.Minute)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timeout:
			return ErrTimeout
		case <-ticker.C:
			data, err := s.cfg.Cache.Get(ctx, loginCode)
			if err != nil {
				continue
			}
			var session CLISession
			if err := json.Unmarshal(data, &session); err != nil || session.User == nil {
				continue
			}
			return stream.Send(&nokkuv1.StreamCLILoginResponse{
				User: session.User,
			})
		}
	}
}

func (s *AuthService) VerifyCLILogin(
	ctx context.Context,
	req *nokkuv1.VerifyCLILoginRequest,
) (*nokkuv1.VerifyCLILoginResponse, error) {
	data, err := s.cfg.Cache.Get(ctx, req.GetLoginCode())
	if err != nil || data == nil {
		return nil, NewError(connect.CodeNotFound, "invalid or expired login code")
	}

	var session CLISession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, ErrInternal
	}

	user, err := s.cfg.Conn.Q.GetUserByID(ctx, meta.UserIDFromContext(ctx))
	if err != nil {
		return nil, ErrInternal
	}

	name := session.Hostname
	if name != "" {
		name = fmt.Sprintf("CLI on %s", name)
	} else {
		name = "CLI device"
	}

	isNew, err := s.registerCLIDevice(ctx, user, &session, name)
	if err != nil {
		return nil, err
	}
	meta.SetAuditUserID(ctx, user.ID)

	ci, ok := connect.CallInfoForHandlerContext(ctx)
	if !ok {
		return nil, ErrInternal
	}
	ipStr := util.GetRemoteIP(ci.RequestHeader(), ci.Peer().Addr)

	if isNew {
		go func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if err := s.cfg.Email.SendNewLoginEmail(
				ctx,
				user.ID,
				user.Email,
				session.DeviceID,
				name,
				s.cfg.Geo.Lookup(ipStr),
			); err != nil {
				slog.Debug("failed to send device added email", "error", err)
			}
		}()
	}

	// Publish the verified session so the waiting StreamCLILogin poll picks
	// it up. Overwriting is idempotent, so double-submissions are safe.
	session.User = user.ToProto()
	approved, err := json.Marshal(session)
	if err != nil {
		return nil, ErrInternal
	}
	if err := s.cfg.Cache.Set(ctx, req.GetLoginCode(), approved, 5*time.Minute); err != nil {
		return nil, ErrInternal
	}
	return &nokkuv1.VerifyCLILoginResponse{}, nil
}

// registerCLIDevice registers the CLI device's signing key from the login
// session. When the CLI presents a device ID it already owns, the existing
// row's credential is updated (no duplicate device); otherwise a new device
// is registered. Returns whether the device is new.
func (s *AuthService) registerCLIDevice(
	ctx context.Context,
	user *db.User,
	session *CLISession,
	name string,
) (bool, error) {
	authMethod := session.AuthMethod
	authPubkey := session.AuthPubkey
	if authPubkey == "" {
		return false, NewError(connect.CodeInvalidArgument, "auth_pubkey required")
	}
	if authMethod != "tpm" && authMethod != "soft" {
		return false, NewError(connect.CodeInvalidArgument, "unsupported auth_method")
	}
	if _, err := authn.ParseAuthPubkey([]byte(authPubkey)); err != nil {
		return false, NewError(connect.CodeInvalidArgument, "invalid auth_pubkey")
	}

	if session.DeviceID != "" {
		if _, err := s.cfg.Conn.Q.RotateUserDevice(ctx, &db.RotateUserDeviceParams{
			ID:         session.DeviceID,
			UserID:     user.ID,
			Name:       name,
			AuthMethod: authMethod,
			AuthPubkey: &authPubkey,
		}); err == nil {
			return false, nil
		}
		// Unknown/revoked device: fall through and register a fresh one.
	}

	id := session.DeviceID
	if id == "" {
		return false, NewError(connect.CodeInvalidArgument, "device id required")
	}
	if err := s.cfg.Conn.Q.CreateUserDevice(ctx, &db.CreateUserDeviceParams{
		ID:         id,
		UserID:     user.ID,
		Name:       name,
		Kind:       deviceKindCLI,
		AuthMethod: authMethod,
		AuthPubkey: &authPubkey,
	}); err != nil {
		return false, err
	}
	return true, nil
}
