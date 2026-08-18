package namegen

import (
	"regexp"
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
