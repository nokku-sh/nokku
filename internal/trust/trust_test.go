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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestBootstrap(t *testing.T) {
	srv := serve(t, ownCert)
	pin := Pin(srv.Certificate())

	ca, err := Bootstrap(t.Context(), srv.URL, strings.ToUpper(pin))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	pool, err := Pool(ca)
	if err != nil || pool == nil {
		t.Fatalf("Pool: %v", err)
	}
	// The kept CA is enough for an ordinary verified request.
	httpc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := httpc.Get(srv.URL + CAPath)
	if err != nil {
		t.Fatalf("verified request with the kept CA: %v", err)
	}
	_ = resp.Body.Close()
}

func TestBootstrapRefusesWrongPin(t *testing.T) {
	srv := serve(t, ownCert)
	_, err := Bootstrap(t.Context(), srv.URL, Pin(foreignCA(t)))
	if err == nil || !strings.Contains(err.Error(), "matches the pin") {
		t.Fatalf("a pin of another CA must be refused, got %v", err)
	}
}

// Whoever sits in between can copy the public CA of the real server, but has
// no certificate from it.
func TestBootstrapRefusesCAWithoutItsCertificate(t *testing.T) {
	other := foreignCA(t)
	srv := serve(t, func(*httptest.Server) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw})
	})
	_, err := Bootstrap(t.Context(), srv.URL, Pin(other))
	if err == nil || !strings.Contains(err.Error(), "does not come from the pinned CA") {
		t.Fatalf("an advertised CA the server has no certificate from must be refused, got %v", err)
	}
}

func TestAdvertisedNoCA(t *testing.T) {
	srv := serve(t, func(*httptest.Server) []byte { return nil })
	if _, err := Advertised(t.Context(), srv.URL); !errors.Is(err, ErrNoCA) {
		t.Fatalf("err = %v, want ErrNoCA", err)
	}
	if _, err := Advertised(t.Context(), "http://localhost:1"); err == nil {
		t.Fatal("plain http has no CA to fetch")
	}
}

func TestUntrusted(t *testing.T) {
	srv := serve(t, ownCert)
	_, err := (&http.Client{Transport: &http.Transport{}}).Get(srv.URL)
	if !Untrusted(err) {
		t.Fatalf("an unknown issuer must count as untrusted, got %v", err)
	}
	if Untrusted(errors.New("connection refused")) {
		t.Fatal("a plain network error is not a trust problem")
	}
}

func TestParsePin(t *testing.T) {
	good := "sha256:" + strings.Repeat("ab", 32)
	if got, err := ParsePin("  SHA256:" + strings.Repeat("AB", 32) + "\n"); err != nil || got != good {
		t.Fatalf("ParsePin = %q, %v", got, err)
	}
	for _, bad := range []string{"", strings.Repeat("ab", 32), "sha256:abcd", "sha256:" + strings.Repeat("zz", 32)} {
		if _, err := ParsePin(bad); err == nil {
			t.Fatalf("ParsePin(%q) must fail", bad)
		}
	}
}

func TestPoolWithoutCAsIsSystemRoots(t *testing.T) {
	pool, err := Pool([]byte("  \n"))
	if err != nil || pool == nil {
		t.Fatalf("Pool = %v, %v, want the system roots", pool, err)
	}
	if _, err = Pool([]byte("not pem")); err == nil {
		t.Fatal("CA data without a certificate must fail")
	}
}
