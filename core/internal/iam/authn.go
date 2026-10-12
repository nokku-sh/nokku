package iam

// Every bearer is one lookup in access_tokens, inside the request's workspace. The kind of the row says what it is.

import (
	"context"
	"net/http"
	"strings"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
)

// Authenticate resolves the credential of a connect call.
func (s *Service) Authenticate(
	ctx context.Context,
	header http.Header,
	procedure string,
) (actor.Principal, db.AccessToken, error) {
	token := requestCredential(header)
	p, tok, err := s.AuthenticateToken(ctx, token)
	if err != nil {
		return actor.Principal{}, db.AccessToken{}, err
	}
	if p.Kind == actor.KindSCIM {
		return actor.Principal{}, db.AccessToken{}, errInvalidCredentials
	}
	if tok.Binding != "" {
		if err := s.verifySessionProof(ctx, header, procedure, token, tok.Binding); err != nil {
			return actor.Principal{}, db.AccessToken{}, err
		}
	}
	s.noteSeen(ctx, tok)
	return p, tok, nil
}

// AuthenticateToken loads the account for user and CLI sessions, so inactive accounts fail closed.
func (s *Service) AuthenticateToken(
	ctx context.Context,
	token string,
) (actor.Principal, db.AccessToken, error) {
	tok, err := s.verifyToken(ctx, token)
	if err != nil {
		return actor.Principal{}, db.AccessToken{}, err
	}
	p := actor.Principal{ID: deref(tok.SubjectID), Kind: actor.Kind(tok.Kind)}
	switch p.Kind {
	case actor.KindUser, actor.KindCLI:
		u, err := s.getUser(ctx, p.ID)
		if err != nil {
			return actor.Principal{}, db.AccessToken{}, err
		}
		if !u.Active {
			return actor.Principal{}, db.AccessToken{}, ErrInactive
		}
		p.Email = u.Email
		p.Role = u.Role
	case actor.KindServiceAccount:
		sa, err := s.conn.Tenant().GetServiceAccount(ctx, p.ID)
		if err != nil {
			return actor.Principal{}, db.AccessToken{}, errInvalidCredentials
		}
		p.Name = sa.Name
		p.Role = sa.Role
	case actor.KindSCIM:
		p.ID = tok.ID
	case actor.KindDaemon:
	}
	return p, tok, nil
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

// AdvertiseDPoPNonce also sends the canonical API URL, so a recovering client corrects the htu it signs.
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
