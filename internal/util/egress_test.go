package util

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEgressClientRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	client, err := NewEgressClient(time.Second)
	require.NoError(t, err)
	_, err = client.Get(srv.URL)
	assert.ErrorIs(t, err, errNotPublic, "loopback must be refused, got %v", err)
}

func TestEgressClientAllowsPrivateWhenConfigured(t *testing.T) {
	t.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "true")
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	client, err := NewEgressClient(time.Second)
	require.NoError(t, err)
	resp, err := client.Get(srv.URL)
	require.NoError(t, err, "loopback must be allowed with NOKKU_ALLOW_PRIVATE_NETWORKS")
	_ = resp.Body.Close()
}
