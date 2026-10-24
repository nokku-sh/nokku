package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/cli/internal/state"
	"github.com/nokku-sh/nokku/internal/dpopclient"
	"github.com/nokku-sh/nokku/internal/trust"
)

// privateServer is a core whose certificate no system root knows, and it advertises it as its CA.
func privateServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != trust.CAPath {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestPinServerKeepsCA(t *testing.T) {
	setTestDirs(t)
	srv := privateServer(t)
	pin := trust.Pin(srv.Certificate())
	c := &Client{State: &state.State{APIURL: srv.URL, Pin: pin}}

	require.NoError(t, c.pinServer(t.Context()))
	assert.True(t, keeps(c.State.APICA, pin))
	assert.Equal(t, c.State.APICA, state.Load().APICA, "the CA is kept for the next run")

	_, err := dpopclient.FetchNonce(t.Context(), c.httpc, srv.URL)
	require.NoError(t, err, "the client verifies the server with the kept CA")

	httpc := c.httpc
	require.NoError(t, c.pinServer(t.Context()))
	assert.Same(t, httpc, c.httpc, "a CA that is kept already is not fetched again")
}

func TestPinServerRefusesWrongPin(t *testing.T) {
	setTestDirs(t)
	srv := privateServer(t)
	c := &Client{State: &state.State{APIURL: srv.URL, Pin: "sha256:" + strings.Repeat("00", 32)}}
	require.Error(t, c.pinServer(t.Context()))
	assert.Empty(t, c.State.APICA)
}

// Without a terminal nobody can compare a fingerprint, so nothing is trusted and the error says what to do.
func TestSyncUntrustedServerWithoutPin(t *testing.T) {
	setTestDirs(t)
	srv := privateServer(t)
	c := &Client{State: &state.State{APIURL: srv.URL, Token: "nk_sa_test"}}
	require.NoError(t, c.dial())

	err := c.Sync(t.Context(), false)
	require.ErrorContains(t, err, "--pin")
	assert.Empty(t, c.State.APICA)
}

// A server that once came from a kept CA and now does not may be intercepted, so nk does not offer the new one.
func TestSyncRefusesChangedCA(t *testing.T) {
	setTestDirs(t)
	srv := privateServer(t)
	kept := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSignedCA(t, &x509.Certificate{}).Raw}))
	c := &Client{State: &state.State{APIURL: srv.URL, Token: "nk_sa_test"}}
	c.State.APICA = kept
	require.NoError(t, c.dial())

	err := c.Sync(t.Context(), true)
	require.ErrorContains(t, err, "no longer comes from a CA this machine trusts")
	assert.Equal(t, kept, c.State.APICA, "the kept CA stays")
}

// output is what fn prints to stderr, where prompts and notices go.
func output(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	stderr := os.Stderr
	os.Stderr = w //nolint:reassign // test isolation
	fn()
	os.Stderr = stderr //nolint:reassign // test isolation
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

// A scripted sign-out cannot answer, so the CA stays and the output says so.
func TestOfferRemovalWithoutATerminal(t *testing.T) {
	installed := &state.State{APIURL: "https://nokku.test", APICAInstalled: true}
	assert.Contains(t, output(t, func() { OfferRemoval(installed) }),
		"The CA of https://nokku.test stays in the system trust store")

	assert.Empty(t, output(t, func() { OfferRemoval(&state.State{APIURL: "https://nokku.test"}) }))
}

func selfSignedCA(t *testing.T, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl.SerialNumber = big.NewInt(1)
	tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
	tmpl.NotBefore, tmpl.NotAfter = time.Now(), time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestScopedTo(t *testing.T) {
	t.Parallel()
	noIPs := []*net.IPNet{
		{IP: net.IP{0, 0, 0, 0}, Mask: net.CIDRMask(0, 32)},
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	}
	// The shape of the core's built-in CA, see core/internal/webpki.
	builtin := selfSignedCA(t, &x509.Certificate{
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{"nokku.example.com"},
		ExcludedIPRanges:            noIPs,
	})
	assert.True(t, scopedTo(builtin, "nokku.example.com"))
	assert.True(t, scopedTo(builtin, "NOKKU.example.com"))
	assert.False(t, scopedTo(builtin, "other.example.com"))

	assert.False(t, scopedTo(selfSignedCA(t, &x509.Certificate{}), "nokku.example.com"), "an unconstrained root")
	assert.False(t, scopedTo(selfSignedCA(t, &x509.Certificate{
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{"nokku.example.com"},
	}), "nokku.example.com"), "a root that still vouches for any IP address")
	assert.False(t, scopedTo(selfSignedCA(t, &x509.Certificate{
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{"nokku.example.com", "example.org"},
		ExcludedIPRanges:            noIPs,
	}), "nokku.example.com"), "a root for more names than this server")
}
