package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/nokku-sh/nokku/internal/authn"
	"github.com/nokku-sh/nokku/internal/cache"
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
		ctx = withRequestWorkspace(ctx, req.Any())
		if isPublicEndpoint(req.Spec().Procedure) {
			return next(ctx, req)
		}

		ctx, err := a.authenticate(ctx, req.Header(), req.Spec().Procedure)
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

		ctx, err := a.authenticate(ctx, conn.RequestHeader(), conn.Spec().Procedure)
		if err != nil {
			return ErrUnauthorized
		}

		return next(ctx, conn)
	}
}

// HTTP wrappers --------------------------------------------------------------

func (a *AuthNInterceptor) WithAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := a.authenticate(r.Context(), r.Header, "")
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
	procedure string,
) (context.Context, error) {
	if challenge := authn.GetChallenge(header); challenge != "" {
		return a.authenticateChallenge(ctx, challenge, procedure)
	}

	bearer := authn.GetBearerToken(header)
	parsed, err := crypto.Parse(bearer)
	if err != nil {
		return a.authenticateUser(ctx, header)
	}

	switch parsed.Prefix {
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

// authenticateChallenge verifies a signed request challenge against the
// identity's registered public key. The challenge is bound to the exact
// procedure being invoked, must be fresh (within ChallengeMaxSkew) and its
// nonce must not have been seen before. Daemons and CLI user devices both
// authenticate this way; service accounts keep bearer tokens.
//
// TODO: GetDaemon/GetUserDevice here is a primary-key read per authenticated
// RPC. Fine today, but when daemon+CLI traffic grows, add a short-TTL
// read-through cache for {auth_pubkey, kind} and invalidate on delete/rotate.
func (a *AuthNInterceptor) authenticateChallenge(
	ctx context.Context,
	challenge, procedure string,
) (context.Context, error) {
	chal, err := authn.ParseChallenge(challenge)
	if err != nil {
		return nil, err
	}
	if procedure == "" || chal.Procedure != procedure {
		return nil, errors.New("challenge bound to a different procedure")
	}

	age := time.Since(time.Unix(chal.Timestamp, 0))
	if age < -authn.ChallengeMaxSkew || age > authn.ChallengeMaxSkew {
		return nil, errors.New("stale challenge")
	}

	daemon, err := a.cfg.Conn.Q.GetDaemon(ctx, chal.IdentityID)
	if err == nil {
		if daemon.AuthPubkey == "" {
			return nil, errors.New("daemon does not use challenge authentication")
		}
		if err := a.verifyChallenge(ctx, chal, daemon.AuthPubkey); err != nil {
			return nil, err
		}
		actor := &meta.Actor{
			ID:   daemon.ID,
			Name: daemon.Name,
			Type: meta.ActorTypeDaemon,
		}
		a.reportUsage(crypto.PrefixDaemon, daemon.ID)
		return meta.WithActor(ctx, actor), nil
	}

	device, err := a.cfg.Conn.Q.GetUserDevice(ctx, chal.IdentityID)
	if err == nil {
		if device.Kind != "cli" || device.AuthPubkey == nil {
			return nil, errors.New("device does not use challenge authentication")
		}
		if err := a.verifyChallenge(ctx, chal, *device.AuthPubkey); err != nil {
			return nil, err
		}
		actor := &meta.Actor{
			ID:   device.UserID,
			Name: device.Name,
			Type: meta.ActorTypeUser,
		}
		a.reportUsage(crypto.PrefixCLI, device.ID)
		return meta.WithActor(ctx, actor), nil
	}

	return nil, errors.New("unknown identity")
}

// verifyChallenge checks the challenge signature and enforces one-time use
// of its nonce. The signature is verified before touching the replay cache
// so invalid challenges cannot fill it.
func (a *AuthNInterceptor) verifyChallenge(
	ctx context.Context,
	chal *authn.Challenge,
	pubkey string,
) error {
	if err := chal.Verify([]byte(pubkey)); err != nil {
		return err
	}

	nonceKey := "challenge:" + chal.IdentityID + ":" + chal.Nonce
	if _, err := a.cfg.Cache.Get(ctx, nonceKey); err == nil {
		return errors.New("replayed challenge")
	} else if !errors.Is(err, cache.ErrNotFound) {
		return errors.New("challenge cache unavailable")
	}
	if err := a.cfg.Cache.Set(ctx, nonceKey, []byte("seen"), authn.ChallengeMaxSkew); err != nil {
		return errors.New("challenge cache unavailable")
	}
	return nil
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

// withRequestWorkspace promotes the conventional workspace_id protobuf field
// into request context before authentication and business logic run. Requests
// without that field are intentionally left global/user-scoped.
func withRequestWorkspace(ctx context.Context, request any) context.Context {
	message, ok := request.(proto.Message)
	if !ok {
		return ctx
	}

	fields := message.ProtoReflect().Descriptor().Fields()
	field := fields.ByName("workspace_id")
	if field == nil || field.Kind() != protoreflect.StringKind {
		return ctx
	}

	workspaceID := message.ProtoReflect().Get(field).String()
	if workspaceID == "" {
		return ctx
	}
	return meta.WithWorkspaceID(ctx, workspaceID)
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
