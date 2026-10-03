package iam

// Credential resolution:
//
//   session cookie                    → user session (browser)
//   Authorization: Bearer nokku_sa_…  → service-account API key (no session)
//   Authorization: Bearer <token>     → session token
//   Authorization: DPoP <token>       → key-bound session, proof on every request (RFC 9449)

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
)

const apiKeyPrefix = "nokku_sa_" //nolint:gosec // a token scheme prefix, not a credential

// Authenticate returns an empty session for service accounts.
func (s *Service) Authenticate(
	ctx context.Context,
	header http.Header,
	procedure string,
) (actor.Principal, db.Session, error) {
	token := requestCredential(header)
	if strings.HasPrefix(token, apiKeyPrefix) {
		p, err := s.authenticateAPIKey(ctx, token)
		return p, db.Session{}, err
	}

	p, sess, err := s.AuthenticateToken(ctx, token)
	if err != nil {
		return actor.Principal{}, db.Session{}, err
	}
	// A device marker only names a known browser. Accepting it anywhere
	// would be a 180 day session that survives logout.
	if p.Kind == actor.KindWebDevice {
		return actor.Principal{}, db.Session{}, errors.New("device credentials are not sessions")
	}
	if sess.Binding != "" {
		if err := s.verifySessionProof(ctx, header, procedure, token, sess.Binding); err != nil {
			return actor.Principal{}, db.Session{}, err
		}
	}
	return p, sess, nil
}

// AuthenticateToken loads the account for user sessions so inactive accounts
// fail closed. Device sessions authenticate on the row alone.
func (s *Service) AuthenticateToken(
	ctx context.Context,
	token string,
) (actor.Principal, db.Session, error) {
	sess, err := s.verifySession(ctx, token)
	if err != nil {
		return actor.Principal{}, db.Session{}, err
	}
	kind := actor.Kind(sess.Kind)
	p := actor.Principal{ID: sess.SubjectID, Kind: kind, WorkspaceID: deref(sess.WorkspaceID)}
	if kind == actor.KindUser {
		u, err := s.getUserByID(ctx, sess.SubjectID)
		if err != nil {
			return actor.Principal{}, db.Session{}, err
		}
		if !u.Active {
			return actor.Principal{}, db.Session{}, ErrInactive
		}
		p.Email = u.Email
	}
	return p, sess, nil
}

// authenticateAPIKey uses Sys since this lookup is what establishes the tenant.
func (s *Service) authenticateAPIKey(ctx context.Context, raw string) (actor.Principal, error) {
	hash, err := crypto.HashToken(raw)
	if err != nil {
		return actor.Principal{}, err
	}
	sa, err := s.sys.GetServiceAccountByTokenHash(ctx, &hash)
	if err != nil {
		return actor.Principal{}, errInvalidCredentials
	}
	if sa.ExpiresAt != nil && sa.ExpiresAt.Before(s.now()) {
		return actor.Principal{}, errCredentialsExpired
	}
	_ = s.sys.TouchServiceAccount(ctx, sa.ID)
	return actor.Principal{
		ID:          sa.ID,
		Kind:        actor.KindServiceAccount,
		WorkspaceID: sa.WorkspaceID,
	}, nil
}

func NewAPIKey() (raw string, hash crypto.HashedToken, err error) {
	secret, _, err := crypto.NewSecret()
	if err != nil {
		return "", "", err
	}
	raw = apiKeyPrefix + secret
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
	return s.DPoP.verifySession(ctx, proof, token, http.MethodPost, s.baseURL+procedure, binding)
}

// AdvertiseDPoPNonce also sends the canonical API URL so a recovering client
// corrects the htu it signs.
func (s *Service) AdvertiseDPoPNonce(h http.Header) {
	h.Set(deviceURLHeader, s.baseURL)
	h.Set("DPoP-Nonce", s.DPoP.CurrentNonce())
}

func requestCredential(h http.Header) string {
	if a := h.Get("Authorization"); a != "" {
		for _, scheme := range []string{"bearer ", "dpop "} {
			if len(a) >= len(scheme) && strings.EqualFold(a[:len(scheme)], scheme) {
				return strings.TrimSpace(a[len(scheme):])
			}
		}
	}
	return cookieFromHeader(h, sessionCookieName)
}
