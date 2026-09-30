package iam

import (
	"context"
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

	"github.com/nokku-sh/nokku/internal/cache"
)

func TestRequestCredential(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		wantToken     string
		wantIsBearer  bool
	}{
		{"bearer", "Bearer tok", "tok", true},
		{"dpop", "DPoP tok", "tok", true},
		{"dpop lowercase", "dpop tok", "tok", true},
		{"other scheme", "Basic tok", "", false},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			if tt.authorization != "" {
				header.Set("Authorization", tt.authorization)
			}
			token, isBearer := requestCredential(header)
			if token != tt.wantToken || isBearer != tt.wantIsBearer {
				t.Fatalf("requestCredential() = (%q, %v), want (%q, %v)",
					token, isBearer, tt.wantToken, tt.wantIsBearer)
			}
		})
	}

	t.Run("cookie", func(t *testing.T) {
		header := http.Header{}
		header.Add("Cookie", sessionCookieName+"=cookietok")
		token, isBearer := requestCredential(header)
		if token != "cookietok" || isBearer {
			t.Fatalf("requestCredential() = (%q, %v), want (cookietok, false)", token, isBearer)
		}
	})
}

// newTestVerifier builds a DPoP verifier with a fixed secret and clock.
func newTestVerifier(t *testing.T, now func() time.Time) *DPoPVerifier {
	t.Helper()
	return &DPoPVerifier{secret: []byte("test-secret"), replay: cache.NewMemory(100), now: now}
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
	svc := &Service{baseURL: "https://nokku.example.com"}
	svc.DPoP = newTestVerifier(t, func() time.Time { return now })
	htu := svc.baseURL + procedure

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	t.Run("valid bound proof", func(t *testing.T) {
		proof := signProof(t, key, htu, DPoPATH(token), svc.DPoP.CurrentNonce(), now)
		header := http.Header{}
		header.Set("Authorization", "DPoP "+token)
		header.Set("DPoP", proof)
		err := svc.verifySessionProof(context.Background(), header, procedure, token, binding)
		// The jkt mismatch is expected (the binding is a fixture value);
		// anything but a binding mismatch means the proof itself failed.
		if err == nil {
			t.Fatal("expected a jkt mismatch for the fixture binding")
		}
		if !strings.Contains(err.Error(), "jkt mismatch") {
			t.Fatalf("verifySessionProof() = %v, want a jkt mismatch", err)
		}
	})

	t.Run("proof bound to the session key passes verification", func(t *testing.T) {
		// Compute the real thumbprint of the test key and rebind.
		jwk := &jose.JSONWebKey{Key: &key.PublicKey}
		tp, err := jwk.Thumbprint(crypto.SHA256)
		if err != nil {
			t.Fatalf("thumbprint: %v", err)
		}
		realBinding := base64.RawURLEncoding.EncodeToString(tp)

		proof := signProof(t, key, htu, DPoPATH(token), svc.DPoP.CurrentNonce(), now)
		header := http.Header{}
		header.Set("DPoP", proof)
		if err := svc.verifySessionProof(context.Background(), header, procedure, token, realBinding); err != nil {
			t.Fatalf("verifySessionProof() = %v, want nil", err)
		}
	})

	t.Run("missing proof is ErrDPoPRequired", func(t *testing.T) {
		header := http.Header{}
		header.Set("Authorization", "DPoP "+token)
		err := svc.verifySessionProof(context.Background(), header, procedure, token, binding)
		if err == nil || !errors.Is(err, ErrDPoPRequired) {
			t.Fatalf("verifySessionProof() = %v, want ErrDPoPRequired", err)
		}
	})

	t.Run("stale nonce maps to ErrDPoPNonce", func(t *testing.T) {
		proof := signProof(t, key, htu, DPoPATH(token), "stale-nonce", now)
		header := http.Header{}
		header.Set("DPoP", proof)
		err := svc.verifySessionProof(context.Background(), header, procedure, token, binding)
		if err == nil || !strings.Contains(err.Error(), "dpop nonce required") {
			t.Fatalf("verifySessionProof() = %v, want ErrDPoPNonce", err)
		}
	})
}

func TestAdvertiseDPoPNonce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	svc := &Service{baseURL: "https://nokku.example.com"}
	svc.DPoP = newTestVerifier(t, func() time.Time { return now })

	t.Run("sets nonce and canonical url", func(t *testing.T) {
		header := http.Header{}
		svc.AdvertiseDPoPNonce(header)
		if header.Get("DPoP-Nonce") != svc.DPoP.CurrentNonce() {
			t.Error("AdvertiseDPoPNonce did not set the DPoP-Nonce header")
		}
		if header.Get(deviceURLHeader) != svc.baseURL {
			t.Error("AdvertiseDPoPNonce did not set the canonical URL header")
		}
	})
}
