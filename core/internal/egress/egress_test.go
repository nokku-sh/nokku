package egress

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"code.dny.dev/ssrf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The owner of a self-hosted core runs the identity provider next to it.
func TestSelfHostedClientReachesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	resp, err := NewClient(time.Second, false).Get(srv.URL)
	require.NoError(t, err, "loopback must be allowed on a self-hosted core")
	_ = resp.Body.Close()
}

// Any workspace picks the URLs there, private ones would open the core's network.
func TestHostedClientRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	_, err := NewClient(time.Second, true).Get(srv.URL)
	assert.ErrorIs(t, err, ssrf.ErrProhibitedIP, "loopback must be refused on the hosted service")
}

// A workspace's issuer must not fill the core's memory, go-oidc reads it whole.
func TestEgressClientStopsAtTheCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 2*maxResponseBytes))
	}))
	t.Cleanup(srv.Close)

	res, err := NewClient(time.Second, false).Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	_, capped := errors.AsType[*http.MaxBytesError](err)
	assert.True(t, capped, "got %v", err)
	assert.LessOrEqual(t, len(body), maxResponseBytes)
}

// A hand-rolled check missed these. Over NAT64 the first is cloud metadata.
// Self-hosted lets the private ranges through and still none of these.
func TestEgressGuardRefusesSpecialRanges(t *testing.T) {
	special := []string{
		"[64:ff9b::a9fe:a9fe]:80", // NAT64 of 169.254.169.254
		"[2002:a9fe:a9fe::1]:443", // 6to4
		"169.254.169.254:80",      // cloud metadata
		"[fe80::1]:80",            // link-local
		"[fd00:ec2::254]:80",      // AWS metadata over IPv6
		"100.100.100.200:80",      // Alibaba metadata, in carrier-grade NAT
		"198.18.0.1:443",          // benchmarking
		"240.0.0.1:443",           // reserved
	}
	private := []string{
		"127.0.0.1:8080",
		"10.0.0.1:8443",
		"172.16.0.1:443",
		"192.168.1.10:443",
		"[::1]:443",
		"[fd12::1]:443",
	}
	network := func(addr string) string {
		if addr[0] == '[' {
			return "tcp6"
		}
		return "tcp4"
	}

	hosted, selfHosted := guard(true), guard(false)
	for _, addr := range special {
		require.ErrorIs(t, hosted(network(addr), addr, nil), ssrf.ErrProhibitedIP, addr)
		require.ErrorIs(t, selfHosted(network(addr), addr, nil), ssrf.ErrProhibitedIP, "self-hosted "+addr)
	}
	for _, addr := range private {
		require.ErrorIs(t, hosted(network(addr), addr, nil), ssrf.ErrProhibitedIP, addr)
		require.NoError(t, selfHosted(network(addr), addr, nil), "self-hosted "+addr)
	}
	for _, check := range []func(string, string, syscall.RawConn) error{hosted, selfHosted} {
		assert.NoError(t, check("tcp4", "93.184.216.34:8443", nil), "a public address on any port")
	}
}
