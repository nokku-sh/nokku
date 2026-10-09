package namegen

import (
	"regexp"
	"strings"
	"testing"
)

var namePattern = regexp.MustCompile(`^[a-z]+-[a-z]+$`)

func TestGenerate(t *testing.T) {
	seen := make(map[string]bool)
	for range 1000 {
		name := Generate()
		if !namePattern.MatchString(name) {
			t.Fatalf("Generate() = %q, want adjective-noun", name)
		}
		seen[name] = true
	}
	if len(seen) < 100 {
		t.Fatalf("generated only %d distinct names in 1000 draws", len(seen))
	}
}

func TestNoDuplicateWords(t *testing.T) {
	check := func(name string, list []string) {
		t.Helper()
		seen := make(map[string]bool, len(list))
		for _, w := range list {
			if seen[w] {
				t.Fatalf("duplicate word %q in %s", w, name)
			}
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
		if got != tc.want || ok != tc.ok {
			t.Errorf("FromHostname(%q) = %q, %v, want %q, %v", tc.host, got, ok, tc.want, tc.ok)
		}
	}
}
