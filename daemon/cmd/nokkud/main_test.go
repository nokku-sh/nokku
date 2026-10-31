package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/nktoken"
)

func TestCheckAPIURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		url string
		ok  bool
	}{
		{"https://app.nokku.sh", true},
		{"https://10.0.0.5:8443", true},
		{"http://localhost:3000", true},
		{"http://127.0.0.1:3000", true},
		{"http://[::1]:3000", true},
		{"http://nokku.example.com", false},
		{"http://10.0.0.5:3000", false},
		{"http://localhost.example.com", false},
		{"nokku.example.com", false},
		{"ftp://localhost", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.ok, checkAPIURL(tt.url) == nil, "accepted is wrong for %q", tt.url)
		})
	}
}

func TestCheckEnrollToken(t *testing.T) {
	t.Parallel()
	token := nktoken.New("enroll")
	require.NoError(t, checkEnrollToken(token))
	for _, bad := range []string{
		"0199f3a1-7c2e-7d4b-9a10-3f2c1b0e8d7a_" + strings.Repeat("a", 43), // the format before
		nktoken.New("invite"),
		token[:len(token)-1],
		"nk_enroll_",
	} {
		assert.ErrorContains(t, checkEnrollToken(bad), "nk_enroll_", "%q", bad)
	}
}
