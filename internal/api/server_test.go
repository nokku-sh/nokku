package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/tenant"
)

// Session rows and audit events take the IP and the user agent from the
// request context. The server sets them for every route. They used to be
// missing on the plain HTTP ones, where the passkey and SSO sign-ins live.
func TestEveryRequestCarriesItsAddressAndHeaders(t *testing.T) {
	// Self-hosted and never booted: every host is the one workspace, and
	// nothing here reaches the database.
	cfg := &config.Config{Port: "3000", Tenant: &tenant.Resolver{}}
	s := &Server{mux: http.NewServeMux(), cfg: cfg}
	var got actor.RequestMeta
	s.mux.HandleFunc("POST /passkey/login/finish", func(_ http.ResponseWriter, r *http.Request) {
		got, _ = actor.RequestMetaFromContext(r.Context())
	})

	req := httptest.NewRequest(http.MethodPost, "/passkey/login/finish", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Firefox/140.0")
	req.RemoteAddr = "203.0.113.7:4242"
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "203.0.113.7:4242", got.RemoteAddr)
	assert.Equal(t, "Mozilla/5.0 Firefox/140.0", got.Header.Get("User-Agent"))
}
