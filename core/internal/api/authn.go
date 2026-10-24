package api

import (
	"context"
	"errors"

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

func (a *authNInterceptor) intercept(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		if isPublicEndpoint(spec.Procedure) {
			return next(ctx, spec, stream)
		}
		meta, _ := actor.RequestMetaFromContext(ctx)
		p, tok, err := a.cfg.IAM.Authenticate(ctx, meta.Header, spec.Procedure)
		if err != nil {
			var header *connect.Header
			if ci, ok := connect.CallInfoForServerContext(ctx); ok {
				header = ci.ResponseHeader()
			}
			return a.fail(ctx, header, err)
		}
		return next(inject(ctx, p, tok), spec, stream)
	}
}

func inject(ctx context.Context, p actor.Principal, tok db.AccessToken) context.Context {
	return actor.ContextWithPrincipal(iam.ContextWithToken(ctx, tok), p)
}

// fail answers Unauthenticated only for a refused credential. A client reads that code as the end of its session,
// which a database that is briefly away must not cause.
func (a *authNInterceptor) fail(ctx context.Context, header *connect.Header, err error) error {
	if !iam.IsCredentialError(err) {
		return toConnectError(err)
	}
	// A fresh DPoP nonce, re-signing with it fixes these two.
	if header != nil && (errors.Is(err, iam.ErrDPoPNonce) || errors.Is(err, iam.ErrDPoPRequired)) {
		a.cfg.IAM.AdvertiseDPoPNonce(ctx, header)
	}
	return connect.NewError(connect.CodeUnauthenticated, err.Error()).WithCause(err)
}
