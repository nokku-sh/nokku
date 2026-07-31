package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
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
	User     *nokkuv1.User `json:"user,omitempty"`
	Token    string        `json:"token,omitempty"`
	Hostname string        `json:"hostname,omitempty"`
	DeviceID string        `json:"device_id,omitempty"`
}

type AuthService struct {
	cfg          *config.Config
	loginWaiters map[string]chan *CLISession
	mu           sync.RWMutex
}

func NewAuthService(cfg *config.Config) *AuthService {
	return &AuthService{
		cfg:          cfg,
		loginWaiters: make(map[string]chan *CLISession),
	}
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

	// Check if user already exists
	found, err := s.cfg.Conn.Q.EmailExists(ctx, req.GetEmail())
	if err != nil {
		return nil, ErrInternal
	}
	if found {
		return nil, ErrEmailTaken
	}

	// Check if SSO is enforced
	if err := checkSSOEnforced(ctx, s.cfg, req.GetEmail()); err != nil {
		return nil, err
	}
	hash, err := crypto.HashPassword(req.GetPassword())
	if err != nil {
		return nil, ErrInternal
	}

	// Create user
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

	// Check if SSO is required
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

	// Check if SSO is enforced - backup codes should NOT work if SSO is enforced
	if err := checkSSOEnforced(ctx, s.cfg, req.GetEmail()); err != nil {
		return nil, err
	}

	receivedCode := util.NormalizeBackupCode(req.GetCode())
	hash, err := crypto.HashToken(receivedCode)
	if err != nil {
		return nil, ErrInternal
	}

	// Verify and mark backup code as used
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
		// No usable refresh token – clear cookies and signal auth failure
		authn.ClearCookies(ci.ResponseHeader())
		return nil, NewError(connect.CodeUnauthenticated, "session expired")
	}

	claims, err := s.cfg.Authn.VerifyToken(token)
	if err != nil || claims.TokenType != "refresh" {
		authn.ClearCookies(ci.ResponseHeader())
		return nil, NewError(connect.CodeUnauthenticated, "session expired")
	}

	// Get user info by ID
	user, err := s.cfg.Conn.Q.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil || !user.IsActive {
		authn.ClearCookies(ci.ResponseHeader())
		return nil, ErrSessionExpired
	}

	accessToken := s.cfg.Authn.AccessCookie(ctx, ci.ResponseHeader(), user)
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

	// Update user as verified
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

	// Hash new password
	hash, err := crypto.HashPassword(req.GetNewPassword())
	if err != nil {
		return nil, ErrInternal
	}

	// Update password
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
	_ *nokkuv1.StreamCLILoginRequest,
	stream *connect.ServerStream[nokkuv1.StreamCLILoginResponse],
) error {
	loginCode, err := s.cfg.Authn.CreateToken(&authn.TokenParams{TokenType: authn.CLIToken})
	if err != nil {
		return ErrInternal
	}

	hostname := getHeader(ctx, "nokku-client-hostname")
	deviceID := getHeader(ctx, "nokku-client-device-id")
	sessionData, err := json.Marshal(&CLISession{Hostname: hostname, DeviceID: deviceID})
	if err != nil {
		return ErrInternal
	}
	_ = s.cfg.Cache.Set(ctx, loginCode, sessionData, 5*time.Minute)

	defer func() { _ = s.cfg.Cache.Delete(ctx, loginCode) }()

	// Register waiter channel before sending URL to avoid race
	ch := make(chan *CLISession, 1)
	s.mu.Lock()
	s.loginWaiters[loginCode] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.loginWaiters, loginCode)
		s.mu.Unlock()
	}()

	// Send URL immediately so CLI can display it
	verificationURL := fmt.Sprintf("%s/login?token=%s", s.cfg.FullURL(), loginCode)
	if err := stream.Send(&nokkuv1.StreamCLILoginResponse{
		VerificationUrl: &verificationURL,
	}); err != nil {
		return err
	}

	timeout := time.After(5 * time.Minute)
	select {
	case <-ctx.Done():
		return nil
	case <-timeout:
		return ErrTimeout
	case session := <-ch:
		return stream.Send(&nokkuv1.StreamCLILoginResponse{
			User:  session.User,
			Token: &session.Token,
		})
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

	token, isNew, err := s.rotateOrCreateDevice(ctx, user, &session, name)
	if err != nil {
		return nil, ErrInternal
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
				token.ID,
				name,
				s.cfg.Geo.Lookup(ipStr),
			); err != nil {
				slog.Debug("failed to send device added email", "error", err)
			}
		}()
	}

	// Notify the waiter channel instead of cache update
	s.mu.RLock()
	ch, exists := s.loginWaiters[req.GetLoginCode()]
	s.mu.RUnlock()
	if exists {
		ch <- &CLISession{
			User:  user.ToProto(),
			Token: token.Plaintext,
		}
	}
	return &nokkuv1.VerifyCLILoginResponse{}, nil
}

// rotateOrCreateDevice issues a CLI token for the device in the session. When
// the CLI presents a device ID it already owns, the existing row's credential
// is rotated (no duplicate device); otherwise a new device is registered.
func (s *AuthService) rotateOrCreateDevice(
	ctx context.Context,
	user *db.User,
	session *CLISession,
	name string,
) (token *crypto.Token, isNew bool, err error) {
	if session.DeviceID != "" {
		token, err = crypto.NewToken(
			crypto.WithPrefix(crypto.PrefixCLI),
			crypto.WithID(session.DeviceID),
		)
		if err != nil {
			return nil, false, err
		}
		if _, err = s.cfg.Conn.Q.RotateUserDevice(ctx, &db.RotateUserDeviceParams{
			ID:        session.DeviceID,
			UserID:    user.ID,
			Name:      name,
			TokenHash: token.Hash,
		}); err == nil {
			return token, false, nil
		}
		// Unknown/revoked device: fall through and register a fresh one.
	}

	token, err = crypto.NewCLIToken()
	if err != nil {
		return nil, false, err
	}
	if err = s.cfg.Conn.Q.CreateUserDevice(ctx, &db.CreateUserDeviceParams{
		ID:        token.ID,
		UserID:    user.ID,
		Name:      name,
		Kind:      deviceKindCLI,
		TokenHash: token.Hash,
	}); err != nil {
		return nil, false, err
	}
	return token, true, nil
}
