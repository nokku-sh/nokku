package egress

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"code.dny.dev/ssrf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEgressClientRefusesPrivateAddresses(t *testing.T) {
	t.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "")
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	client, err := NewClient(time.Second)
	require.NoError(t, err)
	_, err = client.Get(srv.URL)
	assert.ErrorIs(t, err, ssrf.ErrProhibitedIP, "loopback must be refused, got %v", err)
}

// An issuer a workspace picked must not fill the memory of the core, go-oidc reads an answer whole.
func TestEgressClientStopsAtTheCap(t *testing.T) {
	t.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "true")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 2*maxResponseBytes))
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(time.Second)
	require.NoError(t, err)
	res, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	_, capped := errors.AsType[*http.MaxBytesError](err)
	assert.True(t, capped, "got %v", err)
	assert.LessOrEqual(t, len(body), maxResponseBytes)
}

func TestCheckHosted(t *testing.T) {
	t.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "")
	require.NoError(t, CheckHosted())
	t.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "true")
	assert.ErrorContains(t, CheckHosted(), "NOKKU_ALLOW_PRIVATE_NETWORKS")
}

func TestEgressClientAllowsPrivateWhenConfigured(t *testing.T) {
	t.Setenv("NOKKU_ALLOW_PRIVATE_NETWORKS", "true")
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	client, err := NewClient(time.Second)
	require.NoError(t, err)
	resp, err := client.Get(srv.URL)
	require.NoError(t, err, "loopback must be allowed with NOKKU_ALLOW_PRIVATE_NETWORKS")
	_ = resp.Body.Close()
}

// The ranges a hand-rolled check missed. On a NAT64 network the first reaches the cloud metadata service.
func TestEgressGuardRefusesSpecialRanges(t *testing.T) {
	guard := ssrf.New(ssrf.WithAnyPort())
	for _, addr := range []string{
		"[64:ff9b::a9fe:a9fe]:80", // NAT64 of 169.254.169.254
		"[2002:a9fe:a9fe::1]:443", // 6to4
		"198.18.0.1:443",          // benchmarking
		"240.0.0.1:443",           // reserved
		"100.64.0.1:443",          // carrier-grade NAT
		"10.0.0.1:8443",
	} {
		network := "tcp4"
		if addr[0] == '[' {
			network = "tcp6"
		}
		require.Error(t, guard.Safe(network, addr, nil), addr)
	}
	assert.NoError(t, guard.Safe("tcp4", "93.184.216.34:8443", nil), "a public address on any port")
}
