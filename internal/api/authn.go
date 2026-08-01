package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/authn"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/meta"
)

type AuthRequest struct {
	Header http.Header
	IP     string
}

type AuthNInterceptor struct {
	cfg *config.Config
}

func NewAuthNInterceptor(cfg *config.Config) *AuthNInterceptor {
	return &AuthNInterceptor{cfg: cfg}
}

func (a *AuthNInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if isPublicEndpoint(req.Spec().Procedure) {
			return next(ctx, req)
		}

		ctx, err := a.authenticate(ctx, req.Header())
		if err != nil {
			return nil, ErrUnauthorized
		}

		return next(ctx, req)
	}
}

func (a *AuthNInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}

func (a *AuthNInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if isPublicEndpoint(conn.Spec().Procedure) {
			return next(ctx, conn)
		}

		ctx, err := a.authenticate(ctx, conn.RequestHeader())
		if err != nil {
			return ErrUnauthorized
		}

		return next(ctx, conn)
	}
}

// HTTP wrappers --------------------------------------------------------------

func (a *AuthNInterceptor) WithAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Authenticate user using the same logic as Connect-RPC
		ctx, err := a.authenticate(r.Context(), r.Header)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Authentication logic -------------------------------------------------------

func (a *AuthNInterceptor) authenticate(
	ctx context.Context,
	header http.Header,
) (context.Context, error) {
	bearer := authn.GetBearerToken(header)
	parsed, err := crypto.Parse(bearer)
	if err != nil {
		return a.authenticateUser(ctx, header)
	}

	switch parsed.Prefix {
	case crypto.PrefixCLI:
		return a.authenticateCLI(ctx, parsed.ID, bearer)
	case crypto.PrefixDaemon:
		return a.authenticateDaemon(ctx, parsed.ID, bearer)
	case crypto.PrefixSA:
		return a.authenticateServiceAccount(ctx, parsed.ID, bearer)
	default:
		return a.authenticateUser(ctx, header)
	}
}

func (a *AuthNInterceptor) authenticateUser(
	ctx context.Context,
	header http.Header,
) (context.Context, error) {
	tokenString := authn.GetAccessToken(header)
	if tokenString == "" {
		return nil, errors.New("unauthorized")
	}
	claims, err := a.cfg.Authn.VerifyToken(tokenString)
	if err != nil {
		return nil, errors.New("unauthorized")
	}
	if claims.TokenType != "access" {
		return nil, errors.New("invalid token type")
	}

	actor := &meta.Actor{
		ID:   claims.UserID,
		Name: claims.Username,
		Type: meta.ActorTypeUser,
	}
	return meta.WithActor(ctx, actor), nil
}

func (a *AuthNInterceptor) authenticateCLI(
	ctx context.Context,
	cliID, bearer string,
) (context.Context, error) {
	cli, err := a.cfg.Conn.Q.VerifyUserDevice(ctx, cliID)
	if err != nil {
		return nil, errors.New("unauthorized")
	}

	if ok := cli.TokenHash.Verify(bearer); !ok {
		return nil, errors.New("unauthorized")
	}

	actor := &meta.Actor{
		ID:   cli.UserID,
		Name: cli.Name,
		Type: meta.ActorTypeUser,
	}
	a.reportUsage(crypto.PrefixCLI, cliID)
	return meta.WithActor(ctx, actor), nil
}

func (a *AuthNInterceptor) authenticateDaemon(
	ctx context.Context,
	daemonID, bearer string,
) (context.Context, error) {
	daemon, err := a.cfg.Conn.Q.GetDaemon(ctx, daemonID)
	if err != nil {
		return nil, errors.New("daemon not found")
	}

	if ok := daemon.TokenHash.Verify(bearer); !ok {
		return nil, errors.New("unauthorized")
	}

	actor := &meta.Actor{
		ID:   daemon.ID,
		Name: daemon.Name,
		Type: meta.ActorTypeDaemon,
	}
	a.reportUsage(crypto.PrefixDaemon, daemonID)
	return meta.WithActor(ctx, actor), nil
}

func (a *AuthNInterceptor) authenticateServiceAccount(
	ctx context.Context,
	saID, bearer string,
) (context.Context, error) {
	serviceAccount, err := a.cfg.Conn.Q.GetServiceAccount(ctx, saID)
	if err != nil {
		return nil, errors.New("service account not found")
	}

	if ok := serviceAccount.TokenHash.Verify(bearer); !ok {
		return nil, errors.New("unauthorized")
	}

	actor := &meta.Actor{
		ID:   serviceAccount.ID,
		Name: serviceAccount.Name,
		Type: meta.ActorTypeServiceAccount,
	}
	a.reportUsage(crypto.PrefixSA, saID)
	return meta.WithActor(ctx, actor), nil
}

func (a *AuthNInterceptor) reportUsage(prefix, id string) {
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		switch prefix {
		case crypto.PrefixCLI:
			_ = a.cfg.Conn.Q.UpdateUserDeviceUsage(bgCtx, id)
		case crypto.PrefixDaemon:
			_ = a.cfg.Conn.Q.UpdateDaemonUsage(bgCtx, id)
		case crypto.PrefixSA:
			_ = a.cfg.Conn.Q.UpdateServiceAccountUsage(bgCtx, id)
		}
	}()
}

// Endpoint routing sets ------------------------------------------------------

var publicEndpoints = map[string]struct{}{
	nokkuv1connect.AuthServiceLoginProcedure:               {},
	nokkuv1connect.AuthServiceLoginWithBackupCodeProcedure: {},
	nokkuv1connect.AuthServiceLogoutProcedure:              {},
	nokkuv1connect.AuthServiceRegisterProcedure:            {},
	nokkuv1connect.AuthServiceRefreshTokenProcedure:        {},
	nokkuv1connect.AuthServiceForgotPasswordProcedure:      {},
	nokkuv1connect.AuthServiceResetPasswordProcedure:       {},
	nokkuv1connect.AuthServiceVerifyEmailProcedure:         {},
	nokkuv1connect.AuthServiceResendVerificationProcedure:  {},
	nokkuv1connect.AuthServiceStreamCLILoginProcedure:      {},
	nokkuv1connect.DaemonServiceEnrollDaemonProcedure:      {},
	nokkuv1connect.SSOServiceCheckSSOProcedure:             {},
	nokkuv1connect.UtilServiceGetVersionProcedure:          {},
}

func isPublicEndpoint(procedure string) bool {
	_, ok := publicEndpoints[procedure]
	return ok
}
