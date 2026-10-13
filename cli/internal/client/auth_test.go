package client

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
)

func TestBearerAuthSetsHeader(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	var authz, ua string
	next := func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		authz = req.Header().Get("Authorization")
		ua = req.Header().Get("User-Agent")
		return connect.NewResponse(&nokkuv1.User{}), nil
	}

	auth := &bearerAuth{token: "nk_sa_secret", ua: "nk/test"}
	_, err := auth.WrapUnary(next)(t.Context(), connect.NewRequest(&nokkuv1.User{}))
	must.NoError(err)
	is.Equal("Bearer nk_sa_secret", authz)
	is.Equal("nk/test", ua, "service-account requests must still identify the client")
}
