package iam

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/crypto"
)

// The Service has no connection, so a token past its check would panic.

func TestAWrongTokenNeverReachesTheDatabase(t *testing.T) {
	s := &Service{}
	session, _ := crypto.NewToken(crypto.TokenSession)
	scim, _ := crypto.NewToken(crypto.TokenSCIM)
	login, _ := crypto.NewToken(crypto.TokenLogin)
	for name, c := range map[string]struct {
		token string
		kinds []crypto.TokenKind
	}{
		"a SCIM key on the RPC API": {scim, []crypto.TokenKind{
			crypto.TokenSession, crypto.TokenCLI, crypto.TokenDaemon, crypto.TokenServiceAccount,
		}},
		"a session on the SCIM API":   {session, []crypto.TokenKind{crypto.TokenSCIM}},
		"a sign-in link as a session": {login, []crypto.TokenKind{crypto.TokenSession}},
		"a typo":                      {typo(session), []crypto.TokenKind{crypto.TokenSession}},
		"the old format":              {crypto.RandomString(32), []crypto.TokenKind{crypto.TokenSession}},
	} {
		_, err := s.verifyToken(t.Context(), c.token, c.kinds...)
		assert.ErrorIs(t, err, errInvalidCredentials, name)
	}
}

func TestAWrongLinkNeverReachesTheDatabase(t *testing.T) {
	s := &Service{}
	invite, _ := crypto.NewToken(crypto.TokenInvite)
	session, _ := crypto.NewToken(crypto.TokenSession)
	for _, raw := range []string{invite, session, "", "0199f3a1-7c2e-7d4b-9a10-3f2c1b0e8d7a_" + crypto.RandomString(32)} {
		_, _, err := s.ConsumeMagicLink(t.Context(), raw)
		require.ErrorIs(t, err, ErrInvalidToken, "%q", raw)
	}
}

func TestAWrongDeviceCodeNeverReachesTheDatabase(t *testing.T) {
	flow := &DeviceFlow{svc: &Service{}}
	login, _ := crypto.NewToken(crypto.TokenLogin)
	for _, code := range []string{login, crypto.RandomString(32)} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/device/token",
			strings.NewReader(url.Values{"device_code": {code}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		flow.Poll(w, r)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "expired_token")
	}
}

func TestAPollWithoutSSHKeyNeverReachesTheDatabase(t *testing.T) {
	flow := &DeviceFlow{svc: &Service{}}
	code, _ := crypto.NewToken(crypto.TokenDeviceCode)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/device/token",
		strings.NewReader(url.Values{"device_code": {code}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	flow.Poll(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "update nk")
}

// typo changes the last character, so only the checksum can tell.
func typo(raw string) string {
	last := byte('A')
	if raw[len(raw)-1] == last {
		last = 'B'
	}
	return raw[:len(raw)-1] + string(last)
}
