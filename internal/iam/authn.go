package iam

// Credential resolution:
//
//   session cookie                    → user session (browser)
//   Authorization: Bearer nokku_sa_…  → service-account API key (no session)
//   Authorization: Bearer <token>     → session token (device cookies rejected)
//   Authorization: DPoP <token>       → key-bound session, proof on every request (RFC 9449)

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

const APIKeyPrefix = "nokku_sa_" //nolint:gosec // a token scheme prefix, not a credential

// Authenticate returns an empty session for service accounts.
func (s *Service) Authenticate(
	ctx context.Context,
	header http.Header,
	procedure string,
) (Principal, db.Session, error) {
	token, fromHeader := requestCredential(header)
	if strings.HasPrefix(token, APIKeyPrefix) {
		p, err := s.AuthenticateAPIKey(ctx, token)
		return p, db.Session{}, err
	}

	p, sess, err := s.AuthenticateToken(ctx, token)
	if err != nil {
		return Principal{}, db.Session{}, err
	}
	// A device cookie in a header is a leaked cookie being replayed.
	// Accepting it would turn a 24-hour session leak into a 180-day one.
	if fromHeader && p.Kind == KindWebDevice {
		return Principal{}, db.Session{}, errors.New("device credentials are not API tokens")
	}
	if sess.Binding != "" {
		if err := s.verifySessionProof(ctx, header, procedure, token, sess.Binding); err != nil {
			return Principal{}, db.Session{}, err
		}
	}
	return p, sess, nil
}

// AuthenticateToken loads the account for user sessions so inactive accounts
// fail closed. Device sessions authenticate on the row alone.
func (s *Service) AuthenticateToken(
	ctx context.Context,
	token string,
) (Principal, db.Session, error) {
	sess, err := s.VerifySession(ctx, token)
	if err != nil {
		return Principal{}, db.Session{}, err
	}
	kind := Kind(sess.Kind)
	p := Principal{ID: sess.SubjectID, Kind: kind, WorkspaceID: deref(sess.WorkspaceID)}
	if kind == KindUser {
		u, err := s.GetUserByID(ctx, sess.SubjectID)
		if err != nil {
			return Principal{}, db.Session{}, err
		}
		if !u.Active {
			return Principal{}, db.Session{}, ErrInactive
		}
		p.Email = u.Email
	}
	return p, sess, nil
}

// AuthenticateAPIKey uses Sys since this lookup is what establishes the tenant.
func (s *Service) AuthenticateAPIKey(ctx context.Context, raw string) (Principal, error) {
	hash, err := crypto.HashToken(raw)
	if err != nil {
		return Principal{}, err
	}
	sa, err := s.sys.GetServiceAccountByTokenHash(ctx, &hash)
	if err != nil {
		return Principal{}, ErrInvalidCredentials
	}
	if sa.ExpiresAt != nil && sa.ExpiresAt.Before(s.now()) {
		return Principal{}, ErrCredentialsExpired
	}
	_ = s.sys.TouchServiceAccount(ctx, sa.ID)
	return Principal{
		ID:          sa.ID,
		Kind:        KindServiceAccount,
		WorkspaceID: sa.WorkspaceID,
	}, nil
}

func NewAPIKey() (raw string, hash crypto.HashedToken, err error) {
	secret, _, err := crypto.NewSecret()
	if err != nil {
		return "", "", err
	}
	raw = APIKeyPrefix + secret
	hash, err = crypto.HashToken(raw)
	if err != nil {
		return "", "", err
	}
	return raw, hash, nil
}

func (s *Service) verifySessionProof(
	ctx context.Context,
	header http.Header,
	procedure, token, binding string,
) error {
	proof := header.Get("DPoP")
	if proof == "" {
		return ErrDPoPRequired
	}
	return s.DPoP.VerifySession(ctx, proof, token, http.MethodPost, s.baseURL+procedure, binding)
}

// AdvertiseDPoPNonce also sends the canonical API URL so a recovering client
// corrects the htu it signs.
func (s *Service) AdvertiseDPoPNonce(h http.Header) {
	h.Set(DeviceURLHeader, s.baseURL)
	h.Set("DPoP-Nonce", s.DPoP.CurrentNonce())
}

func requestCredential(h http.Header) (token string, fromHeader bool) {
	if a := h.Get("Authorization"); a != "" {
		for _, scheme := range []string{"bearer ", "dpop "} {
			if len(a) >= len(scheme) && strings.EqualFold(a[:len(scheme)], scheme) {
				return strings.TrimSpace(a[len(scheme):]), true
			}
		}
	}
	return cookieFromHeader(h, sessionCookieName), false
}
