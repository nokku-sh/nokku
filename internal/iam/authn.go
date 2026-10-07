package iam

// Credential resolution:
//
//   session cookie                    → user session (browser)
//   Authorization: Bearer nokku_sa_…  → service-account API key (no session)
//   Authorization: Bearer <token>     → session token
//   Authorization: DPoP <token>       → key-bound session, proof on every request (RFC 9449)
//
// Everything is looked up inside the request's workspace, so a credential
// presented on another workspace's host does not exist there.

import (
	"context"
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
	if sess.Binding != "" {
		if err := s.verifySessionProof(ctx, header, procedure, token, sess.Binding); err != nil {
			return actor.Principal{}, db.Session{}, err
		}
	}
	s.noteSeen(ctx, sess)
	return p, sess, nil
}

// AuthenticateToken loads the account for user and CLI sessions so inactive
// accounts fail closed. A daemon session authenticates on the row alone.
func (s *Service) AuthenticateToken(
	ctx context.Context,
	token string,
) (actor.Principal, db.Session, error) {
	sess, err := s.verifySession(ctx, token)
	if err != nil {
		return actor.Principal{}, db.Session{}, err
	}
	kind := actor.Kind(sess.Kind)
	p := actor.Principal{ID: sess.SubjectID, Kind: kind}
	if kind == actor.KindUser || kind == actor.KindCLI {
		u, err := s.getUser(ctx, sess.SubjectID)
		if err != nil {
			return actor.Principal{}, db.Session{}, err
		}
		if !u.Active {
			return actor.Principal{}, db.Session{}, ErrInactive
		}
		p.Email = u.Email
		p.Role = u.Role
	}
	return p, sess, nil
}

func (s *Service) authenticateAPIKey(ctx context.Context, raw string) (actor.Principal, error) {
	hash := crypto.HashToken(raw)
	var sa *db.ServiceAccount
	err := s.conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		sa, err = q.GetServiceAccountByTokenHash(ctx, &hash)
		if err != nil {
			return err
		}
		return q.TouchServiceAccount(ctx, sa.ID)
	})
	if err != nil {
		return actor.Principal{}, errInvalidCredentials
	}
	if sa.ExpiresAt != nil && sa.ExpiresAt.Before(s.now()) {
		return actor.Principal{}, errCredentialsExpired
	}
	return actor.Principal{ID: sa.ID, Kind: actor.KindServiceAccount, Role: sa.RoleName}, nil
}

func NewAPIKey() (raw string, hash crypto.HashedToken) {
	raw = apiKeyPrefix + crypto.RandomString(32)
	return raw, crypto.HashToken(raw)
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
	return s.DPoP.verifySession(ctx, proof, token, http.MethodPost, baseURL(ctx)+procedure, binding)
}

// AdvertiseDPoPNonce also sends the canonical API URL so a recovering client
// corrects the htu it signs.
func (s *Service) AdvertiseDPoPNonce(ctx context.Context, h http.Header) {
	h.Set(deviceURLHeader, baseURL(ctx))
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
