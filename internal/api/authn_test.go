package api

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/iam"
)

func TestRequestWorkspace(t *testing.T) {
	t.Run("nil request is safe for streaming RPCs", func(t *testing.T) {
		tenant := requestWorkspace(nil)
		if tenant != "" {
			t.Fatalf("requestWorkspace(nil) tenant = %q, want empty", tenant)
		}
	})
}

func TestSessionTokenSchemes(t *testing.T) {
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
			token, isBearer := sessionToken(header)
			if token != tt.wantToken || isBearer != tt.wantIsBearer {
				t.Fatalf("sessionToken() = (%q, %v), want (%q, %v)",
					token, isBearer, tt.wantToken, tt.wantIsBearer)
			}
		})
	}

	t.Run("cookie", func(t *testing.T) {
		header := http.Header{}
		header.Add("Cookie", iam.SessionCookieName+"=cookietok")
		token, isBearer := sessionToken(header)
		if token != "cookietok" || isBearer {
			t.Fatalf("sessionToken() = (%q, %v), want (cookietok, false)", token, isBearer)
		}
	})
}

// newTestVerifier builds a DPoP verifier with a fixed secret and clock.
func newTestVerifier(t *testing.T, now func() time.Time) *iam.DPoPVerifier {
	t.Helper()
	v, err := iam.NewDPoPVerifier(iam.DPoPOptions{
		NonceSecret: []byte("test-secret"),
		Now:         now,
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return v
}

// signProof produces a client-style DPoP proof with an ES256 key.
func signProof(
	t *testing.T,
	key *ecdsa.PrivateKey,
	htm, htu, ath, nonce string,
	now time.Time,
) string {
	t.Helper()
	claims := map[string]any{
		"htm": htm,
		"htu": htu,
		"iat": now.Unix(),
		"jti": "test-jti-" + htu + nonce,
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

func TestVerifyProof(t *testing.T) {
	const (
		procedure = "/nokku.v1.UserService/Whoami"
		token     = "session-token"
		binding   = "test-jkt"
	)
	now := time.Unix(1_800_000_000, 0)
	cfg := &config.Config{BaseURL: "https://nokku.example.com"}
	cfg.IAM = &iam.Service{}
	cfg.IAM.DPoP = newTestVerifier(t, func() time.Time { return now })
	a := &authNInterceptor{cfg: cfg}
	htu := cfg.FullURL() + procedure

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	t.Run("valid bound proof", func(t *testing.T) {
		proof := signProof(t, key, http.MethodPost, htu, iam.DPoPATH(token), cfg.IAM.DPoP.CurrentNonce(), now)
		header := http.Header{}
		header.Set("Authorization", "DPoP "+token)
		header.Set("DPoP", proof)
		err := a.verifyProof(context.Background(), header, procedure, token, binding)
		// The jkt mismatch is expected (the binding is a fixture value);
		// anything but a binding mismatch means the proof itself failed.
		if err == nil {
			t.Fatal("expected a jkt mismatch for the fixture binding")
		}
		if !strings.Contains(err.Error(), "jkt mismatch") {
			t.Fatalf("verifyProof() = %v, want a jkt mismatch", err)
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

		proof := signProof(t, key, http.MethodPost, htu, iam.DPoPATH(token), cfg.IAM.DPoP.CurrentNonce(), now)
		header := http.Header{}
		header.Set("DPoP", proof)
		if err := a.verifyProof(context.Background(), header, procedure, token, realBinding); err != nil {
			t.Fatalf("verifyProof() = %v, want nil", err)
		}
	})

	t.Run("missing proof is errDPoPRequired", func(t *testing.T) {
		header := http.Header{}
		header.Set("Authorization", "DPoP "+token)
		err := a.verifyProof(context.Background(), header, procedure, token, binding)
		if err == nil || err != errDPoPRequired {
			t.Fatalf("verifyProof() = %v, want errDPoPRequired", err)
		}
	})

	t.Run("stale nonce maps to ErrDPoPNonce", func(t *testing.T) {
		proof := signProof(t, key, http.MethodPost, htu, iam.DPoPATH(token), "stale-nonce", now)
		header := http.Header{}
		header.Set("DPoP", proof)
		err := a.verifyProof(context.Background(), header, procedure, token, binding)
		if err == nil || !strings.Contains(err.Error(), "dpop nonce required") {
			t.Fatalf("verifyProof() = %v, want ErrDPoPNonce", err)
		}
	})
}

func TestAdvertiseNonce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cfg := &config.Config{}
	cfg.IAM = &iam.Service{}
	cfg.IAM.DPoP = newTestVerifier(t, func() time.Time { return now })
	a := &authNInterceptor{cfg: cfg}

	t.Run("sets nonce on dpop failures", func(t *testing.T) {
		for _, err := range []error{iam.ErrDPoPNonce, errDPoPRequired} {
			header := http.Header{}
			a.advertiseNonce(header, err)
			if header.Get("DPoP-Nonce") != cfg.IAM.DPoP.CurrentNonce() {
				t.Errorf("advertiseNonce(%v) did not set the DPoP-Nonce header", err)
			}
		}
	})

	t.Run("leaves other errors untouched", func(t *testing.T) {
		header := http.Header{}
		a.advertiseNonce(header, errDPoPRequired)
		a.advertiseNonce(header, context.Canceled)
		if header.Get("DPoP-Nonce") != cfg.IAM.DPoP.CurrentNonce() {
			t.Error("expected the DPoP-Nonce header from the required case to survive")
		}
	})
}
