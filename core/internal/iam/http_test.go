package iam

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Over https a sibling host can plant the plain name, never the prefixed one.
func TestSecureCookiesAreHostOnly(t *testing.T) {
	s := &Service{secure: true}
	c := s.newCookie(sessionCookieName, "tok", time.Now().Add(time.Hour))
	const rules = "the cookie breaks the __Host- rules"
	require.Equal(t, "__Host-"+sessionCookieName, c.Name, rules)
	require.True(t, c.Secure, rules)
	require.Equal(t, "/", c.Path, rules)
	require.Empty(t, c.Domain, rules)

	h := http.Header{"Cookie": {sessionCookieName + "=planted; " + c.Name + "=tok"}}
	require.Equal(t, "tok", s.cookieValue(h, sessionCookieName))
	h = http.Header{"Cookie": {sessionCookieName + "=planted"}}
	require.Empty(t, s.cookieValue(h, sessionCookieName), "cookieValue() took the plain cookie")
}

// Browsers drop Secure cookies on plain http, so dev keeps the plain names.
func TestPlainCookiesOverHTTP(t *testing.T) {
	s := &Service{}
	require.Equal(t, sessionCookieName, s.newCookie(sessionCookieName, "tok", time.Now().Add(time.Hour)).Name)
}
