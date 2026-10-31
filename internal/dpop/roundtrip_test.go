package dpop_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/dpop"
	"github.com/nokku-sh/nokku/internal/dpopclient"
)

// What nk and nokkud sign is what the core verifies, nonce, URL and token hash included.
func TestClientProofPassesTheVerifier(t *testing.T) {
	const token, procedure = "session-token", "/nokku.v1.UserService/Whoami"
	v := dpop.NewVerifier([]byte("secret"), func([32]byte) bool { return true }, time.Now)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("DPoP-Nonce", v.CurrentNonce())
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	proofer, err := dpop.NewProofer(key)
	require.NoError(t, err)
	// A trailing slash on the configured URL is how people type it.
	c := dpopclient.New(
		proofer,
		srv.Client(),
		func() string { return token },
		dpopclient.Options{BaseURL: srv.URL + "/"},
	)

	proof, err := c.Proof(t.Context(), http.MethodPost, procedure)
	require.NoError(t, err)
	jkt, err := v.Verify(proof, token, http.MethodPost, srv.URL+procedure, "")
	require.NoError(t, err)
	assert.NotEmpty(t, jkt)

	_, err = v.Verify(proof, "another-token", http.MethodPost, srv.URL+procedure, "")
	require.ErrorIs(t, err, dpop.ErrInvalidProof, "the proof carries the hash of its own token only")
}
