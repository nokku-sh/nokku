package tenant

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/cache"
)

func TestFromHostParsesWithoutTheDatabase(t *testing.T) {
	r := &Resolver{saas: true, scheme: "https", host: "nokku.sh", slugs: cache.NewLocal[actor.Workspace](time.Minute)}
	cached := actor.Workspace{ID: "1", Slug: "acme", BaseURL: "https://acme.nokku.sh"}
	r.slugs.Put("acme", cached)

	root, err := r.FromHost(t.Context(), "nokku.sh")
	require.NoError(t, err)
	assert.Empty(t, root.ID, "the root host has no workspace")

	ws, err := r.FromHost(t.Context(), "ACME.nokku.sh:443")
	require.NoError(t, err)
	assert.Equal(t, cached, ws)

	for _, host := range []string{"app.nokku.sh", "a.b.nokku.sh", "evil.com", ".nokku.sh", "nokku.sh.evil.com"} {
		_, err := r.FromHost(t.Context(), host)
		assert.ErrorIs(t, err, ErrUnknownWorkspace, host)
	}
}

func TestBaseURL(t *testing.T) {
	saas := &Resolver{saas: true, scheme: "https", host: "nokku.sh"}
	assert.Equal(t, "https://acme.nokku.sh", saas.BaseURL("acme"))
	local := &Resolver{scheme: "http", host: "localhost", port: "3000"}
	assert.Equal(t, "http://localhost:3000", local.BaseURL("ignored"))
}

func TestForbiddenSlugs(t *testing.T) {
	for _, slug := range []string{"www", "api", "google", "my-google-sso", "acme-login", "paypal-verify", "okta"} {
		assert.True(t, Forbidden(slug), slug)
	}
	for _, slug := range []string{"acme", "blue-sky", "w0rkshop", "default"} {
		assert.False(t, Forbidden(slug), slug)
	}
}
