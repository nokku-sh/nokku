package webpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/realip"
)

const testHost = "nokku.test"

func testCA(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
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
	return cert, key
}

func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func keyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func useCAFile(t *testing.T, content []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, content, 0o600))
	t.Setenv("NOKKU_TLS_CA", path)
}

// proxyAddr is the one proxy the tests trust.
const proxyAddr = "10.0.0.2:4242"

func trustProxy(t *testing.T) {
	t.Helper()
	require.NoError(t, realip.SetTrustedProxies([]string{"10.0.0.2"}))
	t.Cleanup(func() { _ = realip.SetTrustedProxies(nil) })
}

// direct is a client that connects to the server itself.
func direct() actor.RequestMeta {
	return actor.RequestMeta{RemoteAddr: "203.0.113.7:4242", TLS: true}
}

// forwarded is a client that reached the proxy over https.
func forwarded() actor.RequestMeta {
	return actor.RequestMeta{RemoteAddr: proxyAddr, Header: http.Header{"X-Forwarded-Proto": {"https"}}}
}

func get(id *Identity, meta actor.RequestMeta) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, Path, nil)
	req.RemoteAddr = meta.RemoteAddr
	req.Header = meta.Header
	if meta.TLS {
		req.TLS = &tls.ConnectionState{}
	}
	rec := httptest.NewRecorder()
	id.ServeHTTP(rec, req)
	return rec
}

func clearEnv(t *testing.T) {
	t.Helper()
	t.Setenv("NOKKU_TLS_CA", "")
}

// A pin for the wrong certificate makes nk and nokkud refuse the server, so each client gets the one it saw.
func TestEachClientIsToldTheCAOfTheCertificateItSaw(t *testing.T) {
	trustProxy(t)
	ca := testIssuer(t)
	company, _ := testCA(t, "company")
	id := &Identity{cert: ca.certificate, builtin: advertise(ca.root), proxy: advertise(company)}

	assert.Equal(t, advertise(ca.root).pin, id.Pin(direct()))
	assert.Equal(t, string(certPEM(ca.root)), get(id, direct()).Body.String())

	assert.Equal(t, advertise(company).pin, id.Pin(forwarded()))
	assert.Equal(t, string(certPEM(company)), get(id, forwarded()).Body.String())

	spoofed := direct()
	spoofed.Header = forwarded().Header
	assert.Equal(t, advertise(ca.root).pin, id.Pin(spoofed), "only a trusted proxy speaks for the client")

	plain := actor.RequestMeta{RemoteAddr: "127.0.0.1:4242"}
	assert.Empty(t, id.Pin(plain), "plain localhost has no certificate to pin")
	assert.Equal(t, http.StatusNotFound, get(id, plain).Code)
}

// The built-in CA is always there, but a client behind Let's Encrypt must not be handed its pin.
func TestBehindAProxyWithAPublicCertificateNothingIsAdvertised(t *testing.T) {
	trustProxy(t)
	ca := testIssuer(t)
	id := &Identity{cert: ca.certificate, builtin: advertise(ca.root)}

	assert.Empty(t, id.Pin(forwarded()))
	assert.Equal(t, http.StatusNotFound, get(id, forwarded()).Code)
}

// The pin is what internal/trust computes on the client: sha256 over the public key, in hex.
func TestPinIsOfTheFirstCertificate(t *testing.T) {
	current, _ := testCA(t, "current")
	next, _ := testCA(t, "next")
	file := append(certPEM(current), certPEM(next)...)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, file, 0o600))

	cas, err := readCAs(path)
	require.NoError(t, err)
	told := advertise(cas...)
	sum := sha256.Sum256(current.RawSubjectPublicKeyInfo)
	assert.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), told.pin)
	assert.Equal(t, string(file), string(told.pem), "the whole file is served")
}

// The file is public, so a key in it is a mistake worth stopping the start for.
func TestRefusesPrivateKey(t *testing.T) {
	clearEnv(t)
	cert, key := testCA(t, "current")
	useCAFile(t, append(certPEM(cert), keyPEM(t, key)...))
	_, err := New(t.Context(), nil, testHost)
	require.ErrorContains(t, err, "private key")
}

func TestRefusesFileWithoutCertificate(t *testing.T) {
	clearEnv(t)
	useCAFile(t, []byte("nothing here"))
	_, err := New(t.Context(), nil, testHost)
	require.ErrorContains(t, err, "no certificate")

	t.Setenv("NOKKU_TLS_CA", filepath.Join(t.TempDir(), "missing.pem"))
	_, err = New(t.Context(), nil, testHost)
	require.Error(t, err)
}
