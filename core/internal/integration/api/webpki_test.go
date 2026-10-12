//go:build integration

package api_test

import (
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/webpki"
)

// caSeen asks for the CA and the pin the way the web app and the tools do. viaProxy makes the request look like
// one a proxy on this machine forwarded for a client on https.
func caSeen(t *testing.T, viaProxy bool) (status int, pin string) {
	t.Helper()
	_, srv := newTestAPI(t)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+webpki.Path, nil)
	require.NoError(t, err)
	ctx, call := connect.NewClientContext(t.Context())
	if viaProxy {
		req.Header.Set("X-Forwarded-Proto", "https")
		call.RequestHeader().Set("X-Forwarded-Proto", "https")
	}
	res, err := srv.Client().Do(req)
	require.NoError(t, err)
	_ = res.Body.Close()

	info, err := nokkuv1connect.NewUtilServiceClient(srv.Client(), srv.URL).
		GetInstanceInfo(ctx, &nokkuv1.GetInstanceInfoRequest{})
	require.NoError(t, err)
	return res.StatusCode, info.GetCaPin()
}

// A client reads a missing CA as "nothing to pin". The SPA fallback would answer the path with HTML and a 200.
func TestNoCAIsAdvertisedBehindAProxyWithAPublicCertificate(t *testing.T) {
	status, pin := caSeen(t, true)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Empty(t, pin, "the pin of the built-in CA would make nk refuse the proxy's certificate")
}

func TestBuiltInCAIsAdvertisedToAClientThatConnectsItself(t *testing.T) {
	status, pin := caSeen(t, false)
	assert.Equal(t, http.StatusOK, status)
	assert.NotEmpty(t, pin)
}
