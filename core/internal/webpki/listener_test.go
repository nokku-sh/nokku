package webpki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serve runs a server on the sniffing listener that answers with what it saw of the connection.
func serve(t *testing.T, ca *issuer) (addr string) {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	proto := new(http.Protocols)
	proto.SetHTTP1(true)
	proto.SetHTTP2(true)
	proto.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Protocols:         proto,
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s tls=%t", r.Proto, r.TLS != nil)
		}),
	}
	id := &Identity{cert: ca.certificate}
	go func() { _ = srv.Serve(id.Listener(l)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

func fetch(t *testing.T, transport *http.Transport, url string) string {
	t.Helper()
	httpc := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	defer httpc.CloseIdleConnections()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)
	res, err := httpc.Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return string(body)
}

// only is a transport that speaks nothing but the given protocols.
func only(set func(*http.Protocols), conf *tls.Config) *http.Transport {
	proto := new(http.Protocols)
	set(proto)
	return &http.Transport{Protocols: proto, TLSClientConfig: conf}
}

// A browser, nk and nokkud connect by themselves with TLS. A proxy forwards plain, and the daemon streams
// behind it still need HTTP/2.
func TestOnePortAnswersTLSAndPlainHTTP(t *testing.T) {
	ca := testIssuer(t)
	addr := serve(t, ca)
	roots := x509.NewCertPool()
	roots.AddCert(ca.root)
	// The server listens on an address, the certificate is for the name.
	trusting := func() *tls.Config {
		return &tls.Config{RootCAs: roots, ServerName: testHost, MinVersion: tls.VersionTLS13}
	}
	h1 := func(p *http.Protocols) { p.SetHTTP1(true) }

	assert.Equal(t, "HTTP/2.0 tls=true",
		fetch(t, only(func(p *http.Protocols) { p.SetHTTP2(true) }, trusting()), "https://"+addr))
	assert.Equal(t, "HTTP/1.1 tls=true", fetch(t, only(h1, trusting()), "https://"+addr))
	assert.Equal(t, "HTTP/2.0 tls=false",
		fetch(t, only(func(p *http.Protocols) { p.SetUnencryptedHTTP2(true) }, nil), "http://"+addr))
	assert.Equal(t, "HTTP/1.1 tls=false", fetch(t, only(h1, nil), "http://"+addr))
}

// The first byte is read before the server gets the connection. Waiting for it must not stop the accept loop.
func TestASilentClientHoldsUpNoOne(t *testing.T) {
	addr := serve(t, testIssuer(t))
	var d net.Dialer
	silent, err := d.DialContext(t.Context(), "tcp", addr)
	require.NoError(t, err)
	defer func() { _ = silent.Close() }()

	h1 := func(p *http.Protocols) { p.SetHTTP1(true) }
	assert.Equal(t, "HTTP/1.1 tls=false", fetch(t, only(h1, nil), "http://"+addr))
}
