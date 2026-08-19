package api

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/mizuchilabs/kagi"
	kagiconnect "github.com/mizuchilabs/kagi/connectrpc"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/meta"
)

// publicEndpoints are the connectrpc procedures that skip authentication.
var publicEndpoints = map[string]struct{}{
	nokkuv1connect.DaemonServiceEnrollDaemonProcedure: {},
	nokkuv1connect.SSOServiceCheckSSOProcedure:        {},
	nokkuv1connect.UtilServiceGetVersionProcedure:     {},
}

func isPublicEndpoint(procedure string) bool {
	_, ok := publicEndpoints[procedure]
	return ok
}

// NewKagiAuthNInterceptor builds the connectrpc authentication interceptor
// from kagi: opaque sessions, API keys, and DPoP-bound machine tokens. It
// replaces the challenge-based interceptor.
func NewKagiAuthNInterceptor(cfg *config.Config) connect.Interceptor {
	return kagiconnect.New(kagiconnect.Options{
		Authenticator: cfg.Auth.Authenticator(),
		APIKeys:       cfg.Auth.APIKeys(),
		IsPublic: func(spec connect.Spec) bool {
			return isPublicEndpoint(spec.Procedure)
		},
		ResolveTenant: func(_ context.Context, _ connect.Spec, msg proto.Message) (kagi.TenantID, error) {
			return kagi.TenantID(requestWorkspace(msg)), nil
		},
		BaseURL:    cfg.FullURL(),
		CookieName: "session",
	})
}

// NewHTTPAuth returns middleware that authenticates web requests via kagi
// sessions, mapping the principal onto meta.Actor.
func NewHTTPAuth(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return cfg.Auth.Kagi.Middleware(
			cfg.Auth.Kagi.RequireLogin(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					p, _ := kagi.PrincipalFromContext(r.Context())
					next.ServeHTTP(w, r.WithContext(applyPrincipal(r.Context(), p)))
				}),
			),
		)
	}
}

// NewActorInterceptor maps the kagi principal placed in context by the authn
// interceptor onto nokku's meta.Actor and workspace model. The authorization
// interceptor and data layer consume meta.Actor, not kagi.Principal, so this
// is the only place the two worlds meet.
func NewActorInterceptor(cfg *config.Config) connect.Interceptor {
	return &actorInterceptor{cfg: cfg}
}

type actorInterceptor struct {
	cfg *config.Config
}

func (a *actorInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		ctx = a.withActor(ctx)
		return next(ctx, req)
	}
}

func (a *actorInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}

func (a *actorInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx = a.withActor(ctx)
		return next(ctx, conn)
	}
}

func (a *actorInterceptor) withActor(ctx context.Context) context.Context {
	p, ok := kagi.PrincipalFromContext(ctx)
	if !ok {
		return ctx
	}
	ctx = applyPrincipal(ctx, p)
	return ctx
}

// applyPrincipal maps a kagi principal onto nokku's actor/workspace context.
// It is pure (no side effects) so it can be unit tested.
func applyPrincipal(ctx context.Context, p kagi.Principal) context.Context {
	ctx = meta.WithActor(ctx, &meta.Actor{ID: p.SubjectID, Type: p.Kind})
	if p.TenantID != "" {
		// Machine principals are tenant-scoped by construction.
		ctx = meta.WithWorkspaceID(ctx, string(p.TenantID))
	} else if ws, ok := kagi.TenantFromContext(ctx); ok {
		// User principals are global; the workspace was resolved from the
		// request by the authn interceptor's ResolveTenant hook.
		ctx = meta.WithWorkspaceID(ctx, string(ws))
	}
	return ctx
}

// requestWorkspace returns the conventional workspace_id protobuf field from
// request, or "" when absent. It is the tenant resolution hook for user
// principals: their workspace comes from the request, not the credential.
func requestWorkspace(request proto.Message) string {
	fields := request.ProtoReflect().Descriptor().Fields()
	field := fields.ByName("workspace_id")
	if field == nil || field.Kind() != protoreflect.StringKind {
		return ""
	}
	return request.ProtoReflect().Get(field).String()
}
