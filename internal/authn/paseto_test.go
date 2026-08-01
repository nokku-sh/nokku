package authn

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/google/uuid"
)

// newTestService builds a Service with a fixed random seed, bypassing env parsing.
func newTestService(t *testing.T) *Service {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	secret, err := paseto.NewV4AsymmetricSecretKeyFromSeed(hex.EncodeToString(seed))
	if err != nil {
		t.Fatal(err)
	}
	return &Service{secret: secret}
}

func TestCreateVerifyToken_RoundTrip(t *testing.T) {
	svc := newTestService(t)

	tp := &TokenParams{
		UserID:      uuid.NewString(),
		WorkspaceID: uuid.NewString(),
		Email:       "ops@acme.io",
		Username:    "ops",
		TokenType:   AccessToken,
	}

	token, err := svc.CreateToken(tp)
	if err != nil {
		t.Fatalf("CreateToken() error: %v", err)
	}

	claims, err := svc.VerifyToken(token)
	if err != nil {
		t.Fatalf("VerifyToken() error: %v", err)
	}

	if claims.TokenType != tp.TokenType {
		t.Errorf("TokenType = %q, want %q", claims.TokenType, tp.TokenType)
	}
	if claims.UserID != tp.UserID {
		t.Errorf("UserID = %q, want %q", claims.UserID, tp.UserID)
	}
	if claims.WorkspaceID != tp.WorkspaceID {
		t.Errorf("WorkspaceID = %q, want %q", claims.WorkspaceID, tp.WorkspaceID)
	}
	if claims.Email != tp.Email {
		t.Errorf("Email = %q, want %q", claims.Email, tp.Email)
	}
	if claims.Username != tp.Username {
		t.Errorf("Username = %q, want %q", claims.Username, tp.Username)
	}
}

func TestCreateToken_PartialParams(t *testing.T) {
	svc := newTestService(t)

	tests := []struct {
		name string
		tp   *TokenParams
	}{
		{"only token type", &TokenParams{TokenType: CLIToken}},
		{"no optional claims", &TokenParams{TokenType: VerifyToken}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := svc.CreateToken(tt.tp)
			if err != nil {
				t.Fatalf("CreateToken() error: %v", err)
			}
			claims, err := svc.VerifyToken(token)
			if err != nil {
				t.Fatalf("VerifyToken() error: %v", err)
			}
			if claims.TokenType != tt.tp.TokenType {
				t.Errorf("TokenType = %q, want %q", claims.TokenType, tt.tp.TokenType)
			}
			if claims.UserID != "" || claims.Email != "" {
				t.Errorf("unexpected claims: %+v", claims)
			}
		})
	}
}

func TestCreateToken_Errors(t *testing.T) {
	svc := newTestService(t)

	if _, err := svc.CreateToken(nil); err == nil {
		t.Error("CreateToken(nil): want error")
	}
	if _, err := svc.CreateToken(&TokenParams{}); err == nil {
		t.Error("CreateToken(empty params): want error")
	}
	if _, err := svc.CreateToken(&TokenParams{TokenType: "bogus"}); err == nil {
		t.Error("CreateToken(unknown type): want error")
	}
}

func TestVerifyToken_RejectsForeignSignature(t *testing.T) {
	svc := newTestService(t)
	other := newTestService(t)

	token, err := other.CreateToken(&TokenParams{UserID: "u1", TokenType: AccessToken})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.VerifyToken(token); err == nil {
		t.Error("VerifyToken() with foreign key: want error")
	}
}

func TestVerifyToken_RejectsGarbage(t *testing.T) {
	svc := newTestService(t)

	for _, raw := range []string{"", "garbage", "v4.local.not-a-token"} {
		if _, err := svc.VerifyToken(raw); err == nil {
			t.Errorf("VerifyToken(%q): want error", raw)
		}
	}
}

func TestVerifyToken_RejectsTamperedToken(t *testing.T) {
	svc := newTestService(t)

	token, err := svc.CreateToken(&TokenParams{UserID: "u1", TokenType: AccessToken})
	if err != nil {
		t.Fatal(err)
	}

	tampered := token[:len(token)-4] + "AAAA"
	if _, err := svc.VerifyToken(tampered); err == nil {
		t.Error("VerifyToken() with tampered token: want error")
	}
}

func TestVerifyToken_RejectsForeignIssuer(t *testing.T) {
	svc := newTestService(t)

	other := paseto.NewToken()
	other.SetIssuer("evil")
	other.SetIssuedAt(time.Now())
	other.SetNotBefore(time.Now())
	other.SetExpiration(time.Now().Add(time.Hour))
	other.SetJti(uuid.NewString())
	other.SetString("token_type", AccessToken)

	raw := other.V4Sign(svc.secret, nil)
	if _, err := svc.VerifyToken(raw); err == nil {
		t.Error("VerifyToken() with wrong issuer: want error")
	}
}

func TestGetExpiry(t *testing.T) {
	if got := GetExpiry(AccessToken); got == "" {
		t.Error("GetExpiry(access) = empty")
	}
	if got := GetExpiry("bogus"); got != "" {
		t.Errorf("GetExpiry(bogus) = %q, want empty", got)
	}
}
