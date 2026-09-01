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

// errDPoPRequired marks a key-bound session token presented without a DPoP
// proof. Like a stale nonce, it is advertised with a DPoP-Nonce header so
// the client signs and retries (RFC 9449 section 8).
var errDPoPRequired = errors.New("iam: dpop proof required")

// NewAuthNInterceptor builds the connect authentication interceptor on iam.
// It covers unary RPCs and server-side streaming handlers; streaming
// clients pass through unauthenticated, as connect authenticates on the
// handler side.
func NewAuthNInterceptor(cfg *config.Config) connect.Interceptor {
	return &authNInterceptor{cfg: cfg}
}

type authNInterceptor struct {
	cfg *config.Config
}

func (a *authNInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if isPublicEndpoint(req.Spec().Procedure) {
			return next(ctx, req)
		}
		p, err := a.authenticate(ctx, req.Header(), req.Spec().Procedure)
		if err != nil {
			return nil, a.fail(ctx, err)
		}
		// Machine principals carry their workspace in the credential; user
		// principals resolve it from the request message.
		workspace := p.WorkspaceID
		if workspace == "" {
			workspace = requestWorkspace(req)
		}
		if workspace != "" {
			ctx = iam.AnnotateTenant(ctx, workspace)
		}
		return next(iam.ContextWithPrincipal(ctx, p), req)
	}
}

func (a *authNInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler authenticates streaming RPCs (the daemon control
// stream, recording uploads) with the same rules as unary calls. A
// streaming request has no single message at authentication time, so user
// principals resolve their workspace inside the handler from the request
// message (see SubscribeWorkspaceEvents and GetRecording), and machine
// principals carry it in the credential.
func (a *authNInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if isPublicEndpoint(conn.Spec().Procedure) {
			return next(ctx, conn)
		}
		p, err := a.authenticate(ctx, conn.RequestHeader(), conn.Spec().Procedure)
		if err != nil {
			a.advertiseNonce(conn.ResponseHeader(), err)
			return connect.NewError(connect.CodeUnauthenticated, err)
		}
		if p.WorkspaceID != "" {
			ctx = iam.AnnotateTenant(ctx, p.WorkspaceID)
		}
		return next(iam.ContextWithPrincipal(ctx, p), conn)
	}
}

// authenticate resolves the request credential into a principal and verifies
// the DPoP proof of key-bound sessions.
func (a *authNInterceptor) authenticate(
	ctx context.Context,
	header http.Header,
	procedure string,
) (iam.Principal, error) {
	token, isBearer := sessionToken(header)
	p, binding, err := authenticateToken(ctx, a.cfg, token)
	if err == nil && isBearer && p.Kind == iam.KindWebDevice {
		// The remembered-device cookie is a device handle, not an API
		// credential: it only ever rides the cookie path, so a header
		// presentation means a leaked cookie being replayed. Accepting it
		// would turn a 24-hour session leak into a 180-day one.
		err = errors.New("device credentials are not API tokens")
	}
	if err != nil {
		return iam.Principal{}, err
	}
	if binding != "" {
		if err := a.verifyProof(ctx, header, procedure, token, binding); err != nil {
			return iam.Principal{}, err
		}
	}
	return p, nil
}

// verifyProof checks the DPoP proof that must accompany every request made
// with a key-bound session (CLI device logins and daemons): a fresh
// signature by the session's bound key over this procedure, carrying the
// hash of the token itself (RFC 9449 section 7.1). Cookie sessions carry no
// binding and skip the check.
func (a *authNInterceptor) verifyProof(
	ctx context.Context,
	header http.Header,
	procedure, token, binding string,
) error {
	if a.cfg.IAM.DPoP == nil {
		return errors.New("iam: dpop is not configured")
	}
	proof := header.Get("DPoP")
	if proof == "" {
		return errDPoPRequired
	}
	htu := a.cfg.FullURL() + procedure
	return a.cfg.IAM.DPoP.VerifySession(ctx, proof, token, http.MethodPost, htu, binding)
}

// fail converts an authentication error into a connect error, advertising a
// fresh DPoP nonce when the client fixes the failure by re-signing.
func (a *authNInterceptor) fail(ctx context.Context, err error) error {
	if ci, ok := connect.CallInfoForHandlerContext(ctx); ok {
		a.advertiseNonce(ci.ResponseHeader(), err)
	}
	return connect.NewError(connect.CodeUnauthenticated, err)
}

// advertiseNonce writes the current DPoP nonce when the failure is one the
// client fixes by re-signing with a fresh nonce: a stale nonce, or a bound
// session that arrived without a proof.
func (a *authNInterceptor) advertiseNonce(header http.Header, err error) {
	if !errors.Is(err, iam.ErrDPoPNonce) && !errors.Is(err, errDPoPRequired) {
		return
	}
	if a.cfg.IAM.DPoP != nil {
		header.Set("DPoP-Nonce", a.cfg.IAM.DPoP.CurrentNonce())
	}
}

// authenticateToken resolves a session cookie or bearer token to a principal
// and reports the session's DPoP key binding, if any. Bearer tokens try the
// iam session store first, then service-account token hashes.
func authenticateToken(
	ctx context.Context,
	cfg *config.Config,
	token string,
) (iam.Principal, string, error) {
	if token == "" {
		return iam.Principal{}, "", errors.New("missing credentials")
	}

	// Service accounts authenticate by bearer token hash. They carry no
	// DPoP binding: the secret is the whole credential.
	if strings.HasPrefix(token, prefixSA) {
		p, err := authenticateServiceAccount(ctx, cfg, token)
		return p, "", err
	}

	p, sess, err := cfg.IAM.AuthenticateRequest(ctx, token)
	if err != nil {
		return iam.Principal{}, "", err
	}
	return p, sess.Binding, nil
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
// from the Authorization header (as opposed to the session cookie). Both the
// "Bearer" and "DPoP" schemes are accepted: DPoP-bound clients (CLI and
// daemons) MUST use the DPoP scheme for their bound tokens (RFC 9449).
func sessionToken(header http.Header) (token string, isBearer bool) {
	if h := header.Get("Authorization"); h != "" {
		// Schemes are case-insensitive (RFC 9110 section 11.1).
		for _, scheme := range []string{"bearer ", "dpop "} {
			if len(h) >= len(scheme) && strings.EqualFold(h[:len(scheme)], scheme) {
				return strings.TrimSpace(h[len(scheme):]), true
			}
		}
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
// principals: their workspace comes from the request message, never from a
// header. Handlers that need a workspace for a message without the field
// (or streaming handlers, which have no message here) pin it themselves
// with iam.AnnotateTenant.
func requestWorkspace(request connect.AnyRequest) string {
	if request == nil {
		return ""
	}
	msg, _ := request.Any().(proto.Message)
	if msg == nil {
		return ""
	}

	fields := msg.ProtoReflect().Descriptor().Fields()
	field := fields.ByName("workspace_id")
	if field == nil || field.Kind() != protoreflect.StringKind {
		return ""
	}
	return msg.ProtoReflect().Get(field).String()
}
