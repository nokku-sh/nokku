package iam

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/dpop"

	"github.com/nokku-sh/nokku/core/internal/actor"
)

func TestRequestCredential(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		want          string
	}{
		{"bearer", "Bearer tok", "tok"},
		{"dpop", "DPoP tok", "tok"},
		{"dpop lowercase", "dpop tok", "tok"},
		{"other scheme", "Basic tok", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			if tt.authorization != "" {
				header.Set("Authorization", tt.authorization)
			}
			require.Equal(t, tt.want, (&Service{}).requestCredential(header))
		})
	}

	t.Run("cookie", func(t *testing.T) {
		header := http.Header{}
		header.Add("Cookie", sessionCookieName+"=cookietok")
		require.Equal(t, "cookietok", (&Service{}).requestCredential(header))
	})
}

func newTestVerifier(now func() time.Time) *dpop.Verifier {
	return dpop.NewVerifier([]byte("test-secret"), func([32]byte) bool { return true }, now)
}

// signProof produces a client-style DPoP proof with an ES256 key.
func signProof(
	t *testing.T,
	key *ecdsa.PrivateKey,
	htu, ath, nonce string,
	now time.Time,
) string {
	t.Helper()
	claims := map[string]any{
		"htm": http.MethodPost,
		"htu": htu,
		"iat": now.Unix(),
		"jti": rand.Text(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if ath != "" {
		claims["ath"] = ath
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	opts := (&jose.SignerOptions{}).WithType("dpop+jwt")
	opts.EmbedJWK = true
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: cryptosigner.Opaque(key)},
		opts,
	)
	require.NoError(t, err)
	jws, err := signer.Sign(payload)
	require.NoError(t, err)
	compact, err := jws.CompactSerialize()
	require.NoError(t, err)
	return compact
}

func TestVerifySessionProof(t *testing.T) {
	const (
		procedure = "/nokku.v1.UserService/Whoami"
		token     = "session-token"
		binding   = "test-jkt"
	)
	now := time.Unix(1_800_000_000, 0)
	svc := &Service{}
	svc.DPoP = newTestVerifier(func() time.Time { return now })
	ctx := actor.WithWorkspace(t.Context(), actor.Workspace{ID: "ws", BaseURL: "https://nokku.example.com"})
	htu := "https://nokku.example.com" + procedure

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("a valid proof for another key", func(t *testing.T) {
		proof := signProof(t, key, htu, dpop.ATH(token), svc.DPoP.CurrentNonce(), now)
		header := http.Header{}
		header.Set("Authorization", "DPoP "+token)
		header.Set("DPoP", proof)
		err := svc.verifySessionProof(ctx, header, procedure, token, binding)
		// The fixture binding can't match, any other error is a bad proof.
		require.ErrorContains(t, err, "jkt mismatch")
	})

	t.Run("proof bound to the session key passes verification", func(t *testing.T) {
		jwk := &jose.JSONWebKey{Key: &key.PublicKey}
		tp, err := jwk.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		realBinding := base64.RawURLEncoding.EncodeToString(tp)

		proof := signProof(t, key, htu, dpop.ATH(token), svc.DPoP.CurrentNonce(), now)
		header := http.Header{}
		header.Set("DPoP", proof)
		require.NoError(t, svc.verifySessionProof(ctx, header, procedure, token, realBinding))
	})

	t.Run("missing proof is ErrDPoPRequired", func(t *testing.T) {
		header := http.Header{}
		header.Set("Authorization", "DPoP "+token)
		err := svc.verifySessionProof(ctx, header, procedure, token, binding)
		require.ErrorIs(t, err, ErrDPoPRequired)
	})

	t.Run("stale nonce maps to dpop.ErrNonce", func(t *testing.T) {
		proof := signProof(t, key, htu, dpop.ATH(token), "stale-nonce", now)
		header := http.Header{}
		header.Set("DPoP", proof)
		err := svc.verifySessionProof(ctx, header, procedure, token, binding)
		require.ErrorIs(t, err, dpop.ErrNonce)
	})
}

func TestAdvertiseDPoPNonce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	svc := &Service{}
	svc.DPoP = newTestVerifier(func() time.Time { return now })
	ctx := actor.WithWorkspace(t.Context(), actor.Workspace{ID: "ws", BaseURL: "https://acme.nokku.example"})

	t.Run("sets nonce and the workspace url", func(t *testing.T) {
		header := http.Header{}
		svc.AdvertiseDPoPNonce(ctx, header)
		assert.Equal(t, svc.DPoP.CurrentNonce(), header.Get("DPoP-Nonce"), "the DPoP-Nonce header")
		assert.Equal(t, "https://acme.nokku.example", header.Get(deviceURLHeader), "the canonical URL header")
	})
}
