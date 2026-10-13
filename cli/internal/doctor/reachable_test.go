package doctor

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/cli/internal/state"
	"github.com/nokku-sh/nokku/internal/dpopclient"
)

func TestBackendReachable(t *testing.T) {
	t.Parallel()
	var path, advertised string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if advertised != "" {
			w.Header().Set("Nokku-Api-Url", advertised)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	// The client speaks HTTP/2 only, h2c on a plain URL.
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	s := &state.State{APIURL: srv.URL + "/"}

	require.NoError(t, probe(t.Context(), s), "any answer counts, even an error status")
	assert.Equal(t, "/auth/device/nonce", path)

	advertised = "https://nokku.example.com"
	require.ErrorIs(t, probe(t.Context(), s), dpopclient.ErrAPIURLMismatch, "the server lives at another URL")

	srv.Close()
	err := probe(t.Context(), s)
	require.Error(t, err, "a closed port is out of reach")
	assert.NotErrorIs(t, err, dpopclient.ErrAPIURLMismatch)
}
