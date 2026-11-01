package namegen

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var namePattern = regexp.MustCompile(`^[a-z]+-[a-z]+$`)

func TestGenerate(t *testing.T) {
	seen := make(map[string]bool)
	for range 1000 {
		name := Generate()
		require.Regexp(t, namePattern, name, "want adjective-noun")
		seen[name] = true
	}
	require.GreaterOrEqual(t, len(seen), 100, "too few distinct names in 1000 draws")
}

func TestNoDuplicateWords(t *testing.T) {
	check := func(name string, list []string) {
		t.Helper()
		seen := make(map[string]bool, len(list))
		for _, w := range list {
			require.False(t, seen[w], "duplicate word %q in %s", w, name)
			seen[w] = true
		}
	}
	check("adjectives", adjectives)
	check("nouns", nouns)
}

func TestFromHostname(t *testing.T) {
	t.Parallel()
	cases := []struct {
		host string
		want string
		ok   bool
	}{
		{"alice", "alice", true},
		{"web-1", "web-1", true},
		{"WEB_1.internal.example.com", "web-1", true},
		{"web-7d9f8c6b5-x2k4p", "web-7d9f8c6b5-x2k4p", true},
		{"db-0", "db-0", true},
		{"ip-10-0-1-23", "", false},
		{"3f2a9c1b7e4d", "", false},
		{"instance-1", "", false},
		{"ubuntu", "", false},
		{"localhost", "", false},
		{"localhost.localdomain", "", false},
		{"vps-12345", "", false},
		{"srv123456", "", false},
		{"node3", "", false},
		{"1a2b3c4d5e6", "", false},
		{"", "", false},
		{"-dash-", "dash", true},
		{"has space", "", false},
		{strings.Repeat("a", 64), "", false},
	}
	for _, tc := range cases {
		got, ok := FromHostname(tc.host)
		assert.Equal(t, tc.want, got, "FromHostname(%q)", tc.host)
		assert.Equal(t, tc.ok, ok, "FromHostname(%q)", tc.host)
	}
}
