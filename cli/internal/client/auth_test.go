package client

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBearerAuthSetsHeader(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	ctx, info := connect.NewClientContext(t.Context())
	errOpened := errors.New("opened")
	next := func(context.Context, connect.Spec) (connect.ClientStream, error) { return nil, errOpened }

	auth := &bearerAuth{token: "nk_sa_secret", ua: "nk/test"}
	_, err := auth.intercept(next)(ctx, connect.Spec{})
	must.ErrorIs(err, errOpened, "the call must go on")
	is.Equal("Bearer nk_sa_secret", info.RequestHeader().Get("Authorization"))
	is.Equal(
		"nk/test",
		info.RequestHeader().Get("User-Agent"),
		"service-account requests must still identify the client",
	)
}
