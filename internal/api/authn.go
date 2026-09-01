package api

// Transport authentication, ported from the kagi interceptor to internal/iam:
// opaque session cookies or bearer tokens for users, hashed service-account
// tokens, and DPoP-bound machine sessions. Tenant resolution and the RLS
// GUCs ride on the same context values (iam.AnnotateTenant).

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/iam"
)

// publicEndpoints are the connectrpc procedures that skip authentication.
var publicEndpoints = map[string]struct{}{
	nokkuv1connect.DaemonServiceEnrollDaemonProcedure: {},
	nokkuv1connect.UtilServiceGetVersionProcedure:     {},
}

func isPublicEndpoint(procedure string) bool {
	_, ok := publicEndpoints[procedure]
	return ok
}

// prefixSA marks service-account bearer tokens. The remainder is the raw
// secret; only its hash is stored.
const prefixSA = "nokku_sa_"

// NewAuthNInterceptor builds the connect authentication interceptor on iam.
func NewAuthNInterceptor(cfg *config.Config) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if isPublicEndpoint(req.Spec().Procedure) {
				return next(ctx, req)
			}

			token, isBearer := sessionToken(req.Header())
			p, err := authenticateToken(ctx, cfg, token)
			if err == nil && isBearer && p.Kind == iam.KindWebDevice {
				// The remembered-device cookie is a device handle, not an
				// API credential: it only ever rides the cookie path, so a
				// bearer presentation means a leaked cookie being replayed.
				// Accepting it would turn a 24-hour session leak into a
				// 180-day one.
				err = errors.New("device credentials are not API tokens")
			}
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}
			// Machine principals carry their workspace in the credential;
			// user principals resolve it from the request.
			workspace := p.WorkspaceID
			if workspace == "" {
				workspace = requestWorkspace(req)
			}
			if workspace != "" {
				ctx = iam.AnnotateTenant(ctx, workspace)
			}
			return next(iam.ContextWithPrincipal(ctx, p), req)
		}
	})
}

// authenticateToken resolves a session cookie or bearer token to a principal.
// Bearer tokens try the iam session store first, then service-account token
// hashes.
func authenticateToken(
	ctx context.Context,
	cfg *config.Config,
	token string,
) (iam.Principal, error) {
	if token == "" {
		return iam.Principal{}, errors.New("missing credentials")
	}

	// Service accounts authenticate by bearer token hash.
	if strings.HasPrefix(token, prefixSA) {
		return authenticateServiceAccount(ctx, cfg, token)
	}

	p, _, err := cfg.IAM.AuthenticateRequest(ctx, token)
	if err != nil {
		return iam.Principal{}, err
	}
	return p, nil
}

func authenticateServiceAccount(
	ctx context.Context,
	cfg *config.Config,
	raw string,
) (iam.Principal, error) {
	// The token is looked up by the hash of the full raw credential, the
	// same value minted with the row. The lookup runs on the admin pool:
	// it is the step that establishes the tenant, so it cannot be
	// tenant-scoped (RLS) itself.
	hash, err := crypto.HashToken(raw)
	if err != nil {
		return iam.Principal{}, err
	}
	sa, err := cfg.Conn.AdminQ.GetServiceAccountByTokenHash(ctx, &hash)
	if err != nil {
		return iam.Principal{}, errors.New("invalid credentials")
	}
	if sa.ExpiresAt != nil && sa.ExpiresAt.Before(time.Now()) {
		return iam.Principal{}, errors.New("credentials expired")
	}
	return iam.Principal{
		ID:          sa.ID,
		Kind:        iam.KindServiceAccount,
		WorkspaceID: sa.WorkspaceID,
	}, nil
}

// sessionToken extracts the request credential and reports whether it came
// from the Authorization header (as opposed to the session cookie).
func sessionToken(header http.Header) (token string, isBearer bool) {
	const prefix = "Bearer "
	if h := header.Get("Authorization"); strings.HasPrefix(h, prefix) {
		return strings.TrimPrefix(h, prefix), true
	}
	// The session cookie doubles as the browser credential for connect
	// calls made with credentials: include.
	if c, err := (&http.Request{Header: header}).Cookie(iam.SessionCookieName); err == nil {
		return c.Value, false
	}
	return "", false
}

// NewHTTPAuth returns middleware that authenticates web requests via iam
// sessions and annotates the workspace for the RLS layer.
func NewHTTPAuth(cfg *config.Config) func(http.Handler) http.Handler {
	svc := cfg.IAM
	return func(next http.Handler) http.Handler {
		return svc.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := iam.PrincipalFromContext(r.Context()); !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// requestWorkspace returns the conventional workspace_id protobuf field from
// request, or "" when absent. It is the tenant resolution hook for user
// principals: their workspace comes from the request, not the credential.
//
// Streaming RPCs (client/server streams) have no single request message at
// authentication time, so a nil request contributes no workspace, and the
// streaming handler authorizes against its own request.
func requestWorkspace(request connect.AnyRequest) string {
	if request == nil {
		return ""
	}
	msg, _ := request.Any().(proto.Message)
	if msg == nil {
		// Fall back to the header: the UI sends X-Nokku-Workspace when the
		// request carries no workspace field (streaming calls).
		return request.Header().Get("X-Nokku-Workspace")
	}

	fields := msg.ProtoReflect().Descriptor().Fields()
	field := fields.ByName("workspace_id")
	if field == nil || field.Kind() != protoreflect.StringKind {
		return request.Header().Get("X-Nokku-Workspace")
	}

	workspaceID := msg.ProtoReflect().Get(field).String()
	if workspaceID == "" {
		return request.Header().Get("X-Nokku-Workspace")
	}
	return workspaceID
}
