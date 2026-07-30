// Package authn package implements the authentication service
package authn

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/caarlos0/env/v11"
	"github.com/google/uuid"
	"github.com/mergestat/timediff"
	"github.com/nokku-sh/nokku/internal/db"
)

type TokenParams struct {
	UserID      string `json:"user_id"`
	WorkspaceID string `json:"workspace_id"`
	Email       string `json:"email"`
	Username    string `json:"username"`
	TokenType   string `json:"token_type"`
}

type Service struct {
	secret      paseto.V4AsymmetricSecretKey
	conn        *db.Connection
	SessionSeed string `env:"NOKKU_SESSION_SEED"`
}

func New(conn *db.Connection) (*Service, error) {
	p, err := env.ParseAs[Service]()
	if err != nil {
		return nil, err
	}
	p.conn = conn

	if p.SessionSeed == "" {
		p.secret = paseto.NewV4AsymmetricSecretKey()
	} else {
		if len(p.SessionSeed) != 64 {
			return nil, fmt.Errorf("session seed must be 64 characters long")
		}

		var err error
		p.secret, err = paseto.NewV4AsymmetricSecretKeyFromSeed(p.SessionSeed)
		if err != nil {
			return nil, fmt.Errorf("failed to parse secret key: %w", err)
		}
	}
	return &p, nil
}

func (s *Service) CreateToken(tp *TokenParams) (string, error) {
	if tp == nil || tp.TokenType == "" {
		return "", fmt.Errorf("missing token type")
	}

	duration, ok := defaultExpiry[tp.TokenType]
	if !ok {
		return "", fmt.Errorf("unknown token type: %s", tp.TokenType)
	}

	token := paseto.NewToken()
	token.SetString("token_type", tp.TokenType)

	// Standard claims
	token.SetIssuer("nokku")
	token.SetIssuedAt(time.Now())
	token.SetNotBefore(time.Now())
	token.SetExpiration(time.Now().Add(duration))
	token.SetJti(uuid.New().String())

	if tp.UserID != "" {
		token.SetSubject(tp.UserID)
		token.SetString("user_id", tp.UserID)
	}
	if tp.WorkspaceID != "" {
		token.SetString("workspace_id", tp.WorkspaceID)
	}

	if tp.Email != "" {
		token.SetString("email", tp.Email)
	}
	if tp.Username != "" {
		token.SetString("username", tp.Username)
	}
	return token.V4Sign(s.secret, nil), nil
}

func (s *Service) VerifyToken(tokenString string) (*TokenParams, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))
	parser.AddRule(paseto.IssuedBy("nokku"))

	token, err := parser.ParseV4Public(s.secret.Public(), tokenString, nil)
	if err != nil {
		return nil, err
	}

	claims := &TokenParams{}
	claims.TokenType, err = token.GetString("token_type")
	if err != nil {
		return nil, err
	}

	claims.UserID, _ = token.GetString("user_id")
	claims.WorkspaceID, _ = token.GetString("workspace_id")
	claims.Email, _ = token.GetString("email")
	claims.Username, _ = token.GetString("username")

	return claims, nil
}

// GetExpiry returns the expiry for a given token type as a nice human-readable string.
func GetExpiry(tokenType string) string {
	duration, ok := defaultExpiry[tokenType]
	if !ok {
		return ""
	}
	return timediff.TimeDiff(time.Now().Add(duration))
}
