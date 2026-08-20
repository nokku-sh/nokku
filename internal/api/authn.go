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
			return requestWorkspace(msg)
		},
		BaseURL:    cfg.FullURL(),
		CookieName: "session",
	})
}

// NewHTTPAuth returns middleware that authenticates web requests via kagi
// sessions. The kagi middleware places the principal and resolved tenant on
// the context, which meta reads directly.
func NewHTTPAuth(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return cfg.Auth.Kagi.Middleware(
			cfg.Auth.Kagi.RequireLogin(next),
		)
	}
}

// requestWorkspace returns the conventional workspace_id protobuf field from
// request, or "" when absent. It is the tenant resolution hook for user
// principals: their workspace comes from the request, not the credential.
func requestWorkspace(request proto.Message) (kagi.TenantID, error) {
	fields := request.ProtoReflect().Descriptor().Fields()
	field := fields.ByName("workspace_id")
	if field == nil || field.Kind() != protoreflect.StringKind {
		return "", nil
	}

	workspaceID := request.ProtoReflect().Get(field).String()
	return kagi.TenantID(workspaceID), nil
}
