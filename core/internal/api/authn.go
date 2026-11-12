package api

import (
	"context"
	"errors"

	"connectrpc.com/connect/v2"

	"github.com/nokku-sh/nokku/internal/dpop"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

// The tenant middleware already put the host's workspace on the context.
func authenticate(svc *iam.Service) connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			if procedureAccess[spec.Procedure].GetPublic() {
				return next(ctx, spec, stream)
			}
			meta, _ := actor.RequestMetaFromContext(ctx)
			p, tok, err := svc.Authenticate(ctx, meta.Header, spec.Procedure)
			if err != nil {
				var header *connect.Header
				if ci, ok := connect.CallInfoForServerContext(ctx); ok {
					header = ci.ResponseHeader()
				}
				return authFailure(ctx, svc, header, err)
			}
			return next(actor.ContextWithPrincipal(iam.ContextWithToken(ctx, tok), p), spec, stream)
		}
	}
}

// Only a refused credential gets Unauthenticated, a client logs out on that.
func authFailure(ctx context.Context, svc *iam.Service, header *connect.Header, err error) error {
	if !iam.IsCredentialError(err) {
		return toConnectError(ctx, err)
	}
	// A fresh DPoP nonce, re-signing with it fixes these two.
	if header != nil && (errors.Is(err, dpop.ErrNonce) || errors.Is(err, iam.ErrDPoPRequired)) {
		svc.AdvertiseDPoPNonce(ctx, header)
	}
	return connect.NewError(connect.CodeUnauthenticated, err.Error()).WithCause(err)
}
