package iam

import (
	"net/http"
	"testing"
	"time"
)

// Over https a sibling host can plant the plain name, never the prefixed one.
func TestSecureCookiesAreHostOnly(t *testing.T) {
	s := &Service{secure: true}
	c := s.newCookie(sessionCookieName, "tok", time.Now().Add(time.Hour))
	if c.Name != "__Host-"+sessionCookieName || !c.Secure || c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie %+v breaks the __Host- rules", c)
	}

	h := http.Header{"Cookie": {sessionCookieName + "=planted; " + c.Name + "=tok"}}
	if got := s.cookieValue(h, sessionCookieName); got != "tok" {
		t.Fatalf("cookieValue() = %q, want tok", got)
	}
	h = http.Header{"Cookie": {sessionCookieName + "=planted"}}
	if got := s.cookieValue(h, sessionCookieName); got != "" {
		t.Fatalf("cookieValue() took the plain cookie %q", got)
	}
}

// Browsers drop Secure cookies on plain http, so dev keeps the plain names.
func TestPlainCookiesOverHTTP(t *testing.T) {
	s := &Service{}
	if c := s.newCookie(sessionCookieName, "tok", time.Now().Add(time.Hour)); c.Name != sessionCookieName {
		t.Fatalf("cookie name = %q, want %q", c.Name, sessionCookieName)
	}
}
