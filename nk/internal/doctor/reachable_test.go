package doctor

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/nk/internal/state"
)

func TestBackendReachable(t *testing.T) {
	t.Parallel()
	var path string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.WriteHeader(http.StatusNotFound)
	}))
	// The client speaks HTTP/2 only, h2c on a plain URL.
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	s := &state.State{APIURL: srv.URL + "/"}

	assert.True(t, reachable(t.Context(), s), "any answer counts, even an error status")
	assert.Equal(t, "/auth/device/nonce", path)

	srv.Close()
	assert.False(t, reachable(t.Context(), s), "a closed port is out of reach")
}
