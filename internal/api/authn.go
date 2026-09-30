package api

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

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
		// Machine principals carry their workspace in the credential.
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

// WrapStreamingHandler has no request message yet, so user principals pin
// their workspace inside the handler.
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

func (a *authNInterceptor) inject(
	ctx context.Context,
	workspace string,
	p actor.Principal,
	sess db.Session,
	header http.Header,
	remoteAddr string,
) context.Context {
	if workspace != "" {
		ctx = actor.AnnotateTenant(ctx, workspace)
	}
	ctx = iam.ContextWithSession(ctx, sess)
	ctx = iam.ContextWithRequestMeta(ctx, iam.RequestMeta{
		Header:     header,
		RemoteAddr: remoteAddr,
	})
	return actor.ContextWithPrincipal(ctx, p)
}

func (a *authNInterceptor) fail(ctx context.Context, err error) error {
	if ci, ok := connect.CallInfoForHandlerContext(ctx); ok {
		a.advertiseNonce(ci.ResponseHeader(), err)
	}
	return connect.NewError(connect.CodeUnauthenticated, err)
}

// advertiseNonce sends a fresh DPoP nonce when re-signing fixes the failure.
func (a *authNInterceptor) advertiseNonce(header http.Header, err error) {
	if !errors.Is(err, iam.ErrDPoPNonce) && !errors.Is(err, iam.ErrDPoPRequired) {
		return
	}
	a.cfg.IAM.AdvertiseDPoPNonce(header)
}

// requestWorkspace reads the workspace_id field off the request message.
// User principals never take their workspace from a header.
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
