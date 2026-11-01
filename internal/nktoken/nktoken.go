// Package nktoken is the format of every core secret: nk_<kind>_, a lowercase
// [crypto/rand.Text], and the CRC32 of that in 8 hex digits.
package nktoken

import (
	"crypto/rand"
	"fmt"
	"hash/crc32"
	"strings"
)

const (
	// What [rand.Text] gives today, a later Go may give more.
	minRandomLen = 26
	checkLen     = 8
)

// The kinds nk and nokkud check. The core holds the full list.
const (
	KindServiceAccount = "sa"
	KindEnroll         = "enroll"
)

const base32 = "abcdefghijklmnopqrstuvwxyz234567"

func New(kind string) string {
	body := "nk_" + kind + "_" + strings.ToLower(rand.Text())
	return body + check(body)
}

// Valid is a format check, not authentication.
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
