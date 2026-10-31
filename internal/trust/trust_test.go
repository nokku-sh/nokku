package trust

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPoolTrustsTheCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	_, err := (&http.Client{Transport: &http.Transport{}}).Get(srv.URL)
	assert.True(t, Untrusted(err), "an unknown issuer must count as untrusted, got %v", err)
	assert.False(t, Untrusted(errors.New("connection refused")), "a plain network error is not a trust problem")

	pool, err := Pool(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	require.NoError(t, err)
	httpc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := httpc.Get(srv.URL)
	require.NoError(t, err, "a verified request with the CA from the file")
	_ = resp.Body.Close()
}

func TestPoolWithoutCAsIsSystemRoots(t *testing.T) {
	pool, err := Pool([]byte("  \n"))
	require.NoError(t, err)
	assert.NotNil(t, pool, "want the system roots")
	_, err = Pool([]byte("not pem"))
	require.Error(t, err, "CA data without a certificate must fail")
}

func TestCheckBundle(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	require.NoError(t, CheckBundle(cert))
	require.Error(t, CheckBundle([]byte("not pem")), "CA data without a certificate passed")
	broken := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	require.Error(t, CheckBundle(append(cert, broken...)), "a corrupt certificate in the bundle passed")
}
