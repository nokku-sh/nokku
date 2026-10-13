package recording

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The result must be a non-empty single filename component that fits NAME_MAX.
func FuzzToSnakeCase(f *testing.F) {
	f.Add("")
	f.Add("untitled")
	f.Add("../../etc/passwd")
	f.Add("a_b")
	f.Add("-")
	f.Add("日本語タイトル")
	f.Add(strings.Repeat("x", 300))
	f.Add("İstanbul")

	f.Fuzz(func(t *testing.T, s string) {
		res := toSnakeCase(s)

		if res == "" {
			t.Fatalf("toSnakeCase(%q) returned empty string", s)
		}
		if strings.ContainsAny(res, "/\\\x00") {
			t.Fatalf("toSnakeCase(%q) = %q contains a path separator or NUL", s, res)
		}
		if res == "." || res == ".." {
			t.Fatalf("toSnakeCase(%q) = %q is a traversal component", s, res)
		}
		if !utf8.ValidString(res) {
			t.Fatalf("toSnakeCase(%q) = %q is not valid UTF-8", s, res)
		}
		// The result becomes part of a filename. 255 is NAME_MAX on Linux.
		if len(res) > 255 {
			t.Fatalf("toSnakeCase(%q) produced a %d-byte name, exceeds NAME_MAX", s, len(res))
		}
	})
}
