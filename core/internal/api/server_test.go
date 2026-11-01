package api

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/core/internal/config"
)

// Workspaces pick the URLs the core calls, so on the hosted service this setting would open the network it runs in.
func TestHostedServiceRefusesPrivateNetworks(t *testing.T) {
	t.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "true")
	cfg := &config.Config{}
	cfg.SaaS = true
	assert.ErrorContains(t, New(cfg).Start(t.Context()), "NOKKU_ALLOW_PRIVATE_NETWORKS")
}
