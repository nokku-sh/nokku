package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/config"
)

// Workspaces pick the URLs the core calls, this would open its network to them.
func TestHostedServiceRefusesPrivateNetworks(t *testing.T) {
	t.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "true")
	cfg := &config.Config{}
	cfg.SaaS = true
	assert.ErrorContains(t, New(cfg).Start(t.Context()), "NOKKU_ALLOW_PRIVATE_NETWORKS")
}

// Unset, any peer on a private network could name the client address that
// source-address limits are checked against.
func TestHostedServiceNeedsTrustedProxies(t *testing.T) {
	cfg := &config.Config{}
	cfg.SaaS = true
	require.ErrorContains(t, New(cfg).Start(t.Context()), "NOKKU_TRUSTED_PROXIES")
	cfg.TrustedProxies = []string{" "}
	assert.ErrorContains(t, New(cfg).Start(t.Context()), "NOKKU_TRUSTED_PROXIES", "a blank entry names no proxy")
}
