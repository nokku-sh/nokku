package api

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect/v2"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

// The workspace is already on the context, the tenant middleware put it there from the host.
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
			var header http.Header
			if ci, ok := connect.CallInfoForHandlerContext(ctx); ok {
				header = ci.ResponseHeader()
			}
			return nil, a.fail(ctx, header, err)
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
			return a.fail(ctx, conn.ResponseHeader(), err)
		}
		return next(inject(ctx, p, tok), conn)
	}
}

func inject(ctx context.Context, p actor.Principal, tok db.AccessToken) context.Context {
	return actor.ContextWithPrincipal(iam.ContextWithToken(ctx, tok), p)
}

// fail answers Unauthenticated only for a refused credential. A client reads that code as the end of its session,
// which a database that is briefly away must not cause.
func (a *authNInterceptor) fail(ctx context.Context, header http.Header, err error) error {
	if !iam.IsCredentialError(err) {
		return toConnectError(err)
	}
	// A fresh DPoP nonce, re-signing with it fixes these two.
	if header != nil && (errors.Is(err, iam.ErrDPoPNonce) || errors.Is(err, iam.ErrDPoPRequired)) {
		a.cfg.IAM.AdvertiseDPoPNonce(ctx, header)
	}
	return connect.NewError(connect.CodeUnauthenticated, err)
}
