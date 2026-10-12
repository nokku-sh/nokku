//go:build integration

package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/webpki"
)

// A client reads a missing CA as "nothing to pin". The SPA fallback would answer the path with HTML and a 200.
func TestNoCAIsAdvertisedByDefault(t *testing.T) {
	_, srv := newTestAPI(t)

	res, err := srv.Client().Get(srv.URL + webpki.Path)
	require.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, http.StatusNotFound, res.StatusCode)

	info, err := nokkuv1connect.NewUtilServiceClient(srv.Client(), srv.URL).
		GetInstanceInfo(t.Context(), &nokkuv1.GetInstanceInfoRequest{})
	require.NoError(t, err)
	assert.Empty(t, info.GetCaPin())
}
