package api

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/iam"
)

// The workspace is already on the context, the tenant middleware put it there from the host.
func newAuthNInterceptor(cfg *config.Config) connect.Interceptor {
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
		p, tok, err := a.cfg.IAM.Authenticate(ctx, req.Header(), req.Spec().Procedure)
		if err != nil {
			return nil, a.fail(ctx, err)
		}
		return next(inject(ctx, p, tok), req)
	}
}

func (a *authNInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return next
}

func (a *authNInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if isPublicEndpoint(conn.Spec().Procedure) {
			return next(ctx, conn)
		}
		p, tok, err := a.cfg.IAM.Authenticate(ctx, conn.RequestHeader(), conn.Spec().Procedure)
		if err != nil {
			a.advertiseNonce(ctx, conn.ResponseHeader(), err)
			return connect.NewError(connect.CodeUnauthenticated, err)
		}
		return next(inject(ctx, p, tok), conn)
	}
}

func inject(ctx context.Context, p actor.Principal, tok db.AccessToken) context.Context {
	return actor.ContextWithPrincipal(iam.ContextWithToken(ctx, tok), p)
}

func (a *authNInterceptor) fail(ctx context.Context, err error) error {
	if ci, ok := connect.CallInfoForHandlerContext(ctx); ok {
		a.advertiseNonce(ctx, ci.ResponseHeader(), err)
	}
	return connect.NewError(connect.CodeUnauthenticated, err)
}

// advertiseNonce sends a fresh DPoP nonce when re-signing fixes the failure.
func (a *authNInterceptor) advertiseNonce(ctx context.Context, header http.Header, err error) {
	if !errors.Is(err, iam.ErrDPoPNonce) && !errors.Is(err, iam.ErrDPoPRequired) {
		return
	}
	a.cfg.IAM.AdvertiseDPoPNonce(ctx, header)
}
