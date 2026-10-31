// Package nktoken is the one format of every secret the core hands out: nk_<kind>_, a random part from
// [crypto/rand.Text] in lowercase, and the CRC32 of all that in 8 hex digits. The core checks it before any lookup,
// nk and nokkud before they send a token.
package nktoken

import (
	"crypto/rand"
	"fmt"
	"hash/crc32"
	"strings"
)

const (
	// minRandomLen is what [rand.Text] gives today. A later Go may give more, and older clients must still accept it.
	minRandomLen = 26
	checkLen     = 8
)

// The kinds nk and nokkud check before they send a token. The core holds the full list.
const (
	KindServiceAccount = "sa"
	KindEnroll         = "enroll"
)

const base32 = "abcdefghijklmnopqrstuvwxyz234567"

// New makes a token of kind, like "sa" for nk_sa_.
func New(kind string) string {
	body := "nk_" + kind + "_" + strings.ToLower(rand.Text())
	return body + check(body)
}

// Valid tells a whole token of kind from anything else: a typo, a token of another kind, one of an older format.
// It is a format check, not authentication.
func Valid(raw, kind string) bool {
	rest, ok := strings.CutPrefix(raw, "nk_"+kind+"_")
	if !ok || len(rest) < minRandomLen+checkLen || strings.Trim(rest[:len(rest)-checkLen], base32) != "" {
		return false
	}
	body, sum := raw[:len(raw)-checkLen], raw[len(raw)-checkLen:]
	return check(body) == sum
}

func check(body string) string {
	return fmt.Sprintf("%08x", crc32.ChecksumIEEE([]byte(body)))
}
