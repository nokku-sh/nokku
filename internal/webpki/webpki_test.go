package webpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

func get(id *Identity) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	id.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, Path, nil))
	return rec
}

func clearEnv(t *testing.T) {
	t.Helper()
	t.Setenv("NOKKU_TLS_CA", "")
}

func TestBehindAProxyNothingIsServedOrAdvertised(t *testing.T) {
	clearEnv(t)
	id, err := New(t.Context(), nil, ModeOff, testHost)
	require.NoError(t, err)
	assert.Empty(t, id.Pin())
	assert.Equal(t, http.StatusNotFound, get(id).Code)
	assert.Nil(t, id.TLSConfig(), "the listener stays plain for the proxy")
}

// The pin is what mon/trust computes on the client: sha256 over the public key, in hex.
func TestPinIsOfTheFirstCertificate(t *testing.T) {
	clearEnv(t)
	current, _ := testCA(t, "current")
	next, _ := testCA(t, "next")
	bundle := append(certPEM(current), certPEM(next)...)
	useCAFile(t, bundle)

	id, err := New(t.Context(), nil, ModeOff, testHost)
	require.NoError(t, err)
	sum := sha256.Sum256(current.RawSubjectPublicKeyInfo)
	assert.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), id.Pin())

	rec := get(id)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, string(bundle), rec.Body.String(), "the whole file is served")
}

// The file is public, so a key in it is a mistake worth stopping the start for.
func TestRefusesPrivateKey(t *testing.T) {
	clearEnv(t)
	cert, key := testCA(t, "current")
	useCAFile(t, append(certPEM(cert), keyPEM(t, key)...))
	_, err := New(t.Context(), nil, ModeOff, testHost)
	require.ErrorContains(t, err, "private key")
}

func TestRefusesFileWithoutCertificate(t *testing.T) {
	clearEnv(t)
	useCAFile(t, []byte("nothing here"))
	_, err := New(t.Context(), nil, ModeOff, testHost)
	require.ErrorContains(t, err, "no certificate")

	t.Setenv("NOKKU_TLS_CA", filepath.Join(t.TempDir(), "missing.pem"))
	_, err = New(t.Context(), nil, ModeOff, testHost)
	require.Error(t, err)
}

func TestModeIsCheckedOnParse(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeOff, "internal": ModeInternal, "Internal": ModeInternal} {
		var m Mode
		require.NoError(t, m.UnmarshalText([]byte(in)), in)
		assert.Equal(t, want, m)
	}
	var m Mode
	require.ErrorContains(t, m.UnmarshalText([]byte("acme")), "it takes internal")
}

// The built-in CA is the one clients see, a second one would only confuse which pin is right.
func TestInternalModeTakesNoCAFile(t *testing.T) {
	t.Setenv("NOKKU_TLS_CA", "/etc/nokku/ca.pem")
	_, err := New(t.Context(), nil, ModeInternal, testHost)
	require.ErrorContains(t, err, "NOKKU_TLS_CA has no use")
}
