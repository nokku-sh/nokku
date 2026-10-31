package iam

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"

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
			if got := (&Service{}).requestCredential(header); got != tt.want {
				t.Fatalf("requestCredential() = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("cookie", func(t *testing.T) {
		header := http.Header{}
		header.Add("Cookie", sessionCookieName+"=cookietok")
		if got := (&Service{}).requestCredential(header); got != "cookietok" {
			t.Fatalf("requestCredential() = %q, want cookietok", got)
		}
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
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	opts := (&jose.SignerOptions{}).WithType("dpop+jwt")
	opts.EmbedJWK = true
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: cryptosigner.Opaque(key)},
		opts,
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
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
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	t.Run("valid bound proof", func(t *testing.T) {
		proof := signProof(t, key, htu, dpop.ATH(token), svc.DPoP.CurrentNonce(), now)
		header := http.Header{}
		header.Set("Authorization", "DPoP "+token)
		header.Set("DPoP", proof)
		err := svc.verifySessionProof(ctx, header, procedure, token, binding)
		// The fixture binding cannot match. Anything but a binding mismatch means the proof itself failed.
		if err == nil {
			t.Fatal("expected a jkt mismatch for the fixture binding")
		}
		if !strings.Contains(err.Error(), "jkt mismatch") {
			t.Fatalf("verifySessionProof() = %v, want a jkt mismatch", err)
		}
	})

	t.Run("proof bound to the session key passes verification", func(t *testing.T) {
		jwk := &jose.JSONWebKey{Key: &key.PublicKey}
		tp, err := jwk.Thumbprint(crypto.SHA256)
		if err != nil {
			t.Fatalf("thumbprint: %v", err)
		}
		realBinding := base64.RawURLEncoding.EncodeToString(tp)

		proof := signProof(t, key, htu, dpop.ATH(token), svc.DPoP.CurrentNonce(), now)
		header := http.Header{}
		header.Set("DPoP", proof)
		if err := svc.verifySessionProof(ctx, header, procedure, token, realBinding); err != nil {
			t.Fatalf("verifySessionProof() = %v, want nil", err)
		}
	})

	t.Run("missing proof is ErrDPoPRequired", func(t *testing.T) {
		header := http.Header{}
		header.Set("Authorization", "DPoP "+token)
		err := svc.verifySessionProof(ctx, header, procedure, token, binding)
		if err == nil || !errors.Is(err, ErrDPoPRequired) {
			t.Fatalf("verifySessionProof() = %v, want ErrDPoPRequired", err)
		}
	})

	t.Run("stale nonce maps to dpop.ErrNonce", func(t *testing.T) {
		proof := signProof(t, key, htu, dpop.ATH(token), "stale-nonce", now)
		header := http.Header{}
		header.Set("DPoP", proof)
		err := svc.verifySessionProof(ctx, header, procedure, token, binding)
		if !errors.Is(err, dpop.ErrNonce) {
			t.Fatalf("verifySessionProof() = %v, want dpop.ErrNonce", err)
		}
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
		if header.Get("DPoP-Nonce") != svc.DPoP.CurrentNonce() {
			t.Error("AdvertiseDPoPNonce did not set the DPoP-Nonce header")
		}
		if header.Get(deviceURLHeader) != "https://acme.nokku.example" {
			t.Error("AdvertiseDPoPNonce did not set the canonical URL header")
		}
	})
}
