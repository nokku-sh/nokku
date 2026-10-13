package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serve starts a TLS server that advertises bundle at CAPath, or nothing
// when it is empty.
func serve(t *testing.T, bundle func(*httptest.Server) []byte) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := bundle(srv)
		if r.URL.Path != CAPath || body == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func ownCert(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func foreignCA(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "someone else"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestBootstrap(t *testing.T) {
	srv := serve(t, ownCert)
	pin := Pin(srv.Certificate())

	ca, err := Bootstrap(t.Context(), srv.URL, strings.ToUpper(pin))
	require.NoError(t, err)
	pool, err := Pool(ca)
	require.NoError(t, err)
	require.NotNil(t, pool)
	// The kept CA is enough for an ordinary verified request.
	httpc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := httpc.Get(srv.URL + CAPath)
	require.NoError(t, err, "verified request with the kept CA")
	_ = resp.Body.Close()
}

func TestBootstrapRefusesWrongPin(t *testing.T) {
	srv := serve(t, ownCert)
	_, err := Bootstrap(t.Context(), srv.URL, Pin(foreignCA(t)))
	require.ErrorContains(t, err, "matches the pin", "a pin of another CA must be refused")
}

// Whoever sits in between can copy the public CA of the real server, but has
// no certificate from it.
func TestBootstrapRefusesCAWithoutItsCertificate(t *testing.T) {
	other := foreignCA(t)
	srv := serve(t, func(*httptest.Server) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw})
	})
	_, err := Bootstrap(t.Context(), srv.URL, Pin(other))
	require.ErrorContains(t, err, "does not come from the pinned CA",
		"an advertised CA the server has no certificate from must be refused")
}

func TestAdvertisedNoCA(t *testing.T) {
	srv := serve(t, func(*httptest.Server) []byte { return nil })
	_, err := Advertised(t.Context(), srv.URL)
	require.ErrorIs(t, err, ErrNoCA)
	_, err = Advertised(t.Context(), "http://localhost:1")
	require.Error(t, err, "plain http has no CA to fetch")
}

func TestUntrusted(t *testing.T) {
	srv := serve(t, ownCert)
	_, err := (&http.Client{Transport: &http.Transport{}}).Get(srv.URL)
	assert.True(t, Untrusted(err), "an unknown issuer must count as untrusted, got %v", err)
	assert.False(t, Untrusted(errors.New("connection refused")), "a plain network error is not a trust problem")
}

func TestParsePin(t *testing.T) {
	good := "sha256:" + strings.Repeat("ab", 32)
	got, err := ParsePin("  SHA256:" + strings.Repeat("AB", 32) + "\n")
	require.NoError(t, err)
	assert.Equal(t, good, got)
	for _, bad := range []string{"", strings.Repeat("ab", 32), "sha256:abcd", "sha256:" + strings.Repeat("zz", 32)} {
		_, err = ParsePin(bad)
		require.Error(t, err, "ParsePin(%q) must fail", bad)
	}
}

func TestPoolWithoutCAsIsSystemRoots(t *testing.T) {
	pool, err := Pool([]byte("  \n"))
	require.NoError(t, err)
	assert.NotNil(t, pool, "want the system roots")
	_, err = Pool([]byte("not pem"))
	require.Error(t, err, "CA data without a certificate must fail")
}
