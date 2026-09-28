package api

// Transport authentication is iam's: the interceptor asks iam.Authenticate
// to resolve the request credential (session cookie, bearer token, or
// DPoP-bound token) into a principal, then injects the principal, session,
// tenant, and request metadata into the context. Tenant resolution rides
// the same context values (iam.AnnotateTenant).

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokku/internal/iam"
)

// publicEndpoints are the connectrpc procedures that skip authentication.
// AuthService is the pre-session surface entirely: its RPCs establish (or
// tear down) the session, so authn must not gate them. Logout in particular
// must stay reachable with a stale session to clear the cookie.
var publicEndpoints = map[string]struct{}{
	nokkuv1connect.DaemonServiceEnrollDaemonProcedure:      {},
	nokkuv1connect.UtilServiceGetVersionProcedure:          {},
	nokkuv1connect.AuthServiceRegisterProcedure:            {},
	nokkuv1connect.AuthServiceLoginProcedure:               {},
	nokkuv1connect.AuthServiceLoginWithBackupCodeProcedure: {},
	nokkuv1connect.AuthServiceLogoutProcedure:              {},
	nokkuv1connect.AuthServiceForgotPasswordProcedure:      {},
	nokkuv1connect.AuthServiceResetPasswordProcedure:       {},
	nokkuv1connect.AuthServiceVerifyEmailProcedure:         {},
	nokkuv1connect.AuthServiceResendVerificationProcedure:  {},
	nokkuv1connect.AuthServiceDiscoverSSOProcedure:         {},
}

func isPublicEndpoint(procedure string) bool {
	_, ok := publicEndpoints[procedure]
	return ok
}

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
		p, sess, err := a.cfg.IAM.Authenticate(ctx, req.Header(), req.Spec().Procedure)
		if err != nil {
			return nil, a.fail(ctx, err)
		}
		// Machine principals carry their workspace in the credential; user
		// principals resolve it from the request message.
		workspace := p.WorkspaceID
		if workspace == "" {
			workspace = requestWorkspace(req)
		}
		return next(a.inject(ctx, workspace, p, sess, req.Header(), req.Peer().Addr), req)
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
// message (see GetRecording), and machine
// principals carry it in the credential.
func (a *authNInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if isPublicEndpoint(conn.Spec().Procedure) {
			return next(ctx, conn)
		}
		p, sess, err := a.cfg.IAM.Authenticate(ctx, conn.RequestHeader(), conn.Spec().Procedure)
		if err != nil {
			a.advertiseNonce(conn.ResponseHeader(), err)
			return connect.NewError(connect.CodeUnauthenticated, err)
		}
		return next(a.inject(ctx, p.WorkspaceID, p, sess, conn.RequestHeader(), conn.Peer().Addr), conn)
	}
}

// inject carries the authenticated request state: tenant for RLS, the
// session row, transport facts for the audit sink, and the principal.
func (a *authNInterceptor) inject(
	ctx context.Context,
	workspace string,
	p iam.Principal,
	sess db.Session,
	header http.Header,
	remoteAddr string,
) context.Context {
	if workspace != "" {
		ctx = iam.AnnotateTenant(ctx, workspace)
	}
	ctx = iam.ContextWithSession(ctx, sess)
	ctx = iam.ContextWithRequestMeta(ctx, iam.RequestMeta{
		Header:     header,
		RemoteAddr: remoteAddr,
	})
	return iam.ContextWithPrincipal(ctx, p)
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
	if !errors.Is(err, iam.ErrDPoPNonce) && !errors.Is(err, iam.ErrDPoPRequired) {
		return
	}
	a.cfg.IAM.AdvertiseDPoPNonce(header)
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
