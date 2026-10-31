//go:build integration

package api_test

import (
	"errors"
	"fmt"
	"hash/crc32"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"uuid"

	"connectrpc.com/connect/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertGolden compares lines with testdata/name. UPDATE_GOLDEN=1 writes the file instead.
func assertGolden(t *testing.T, name string, lines []string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	got := strings.Join(lines, "\n") + "\n"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.MkdirAll("testdata", 0o750))
		require.NoError(t, os.WriteFile(path, []byte(got), 0o600))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "no golden file yet, run with UPDATE_GOLDEN=1")
	assert.Equal(t, string(want), got, "rerun with UPDATE_GOLDEN=1 if the change is meant")
}

const (
	base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	base32Alphabet    = "abcdefghijklmnopqrstuvwxyz234567"
	userCodeAlphabet  = "BCDFGHJKLMNPQRSTVWXZ23456789"
	checksumLen       = 8
)

var (
	// The lazy match stops at the first underscore, a random body may hold more.
	keyPrefix = regexp.MustCompile(`^nk_[a-z]+?_`)
	userCode  = regexp.MustCompile(`^[` + userCodeAlphabet + `]{4}-[` + userCodeAlphabet + `]{4}$`)
)

// shape describes a token or a link without its secret. The base URL of the workspace reads as <base>.
func shape(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return tokenShape(raw)
	}
	var params []string
	for pair := range strings.SplitSeq(u.RawQuery, "&") {
		key, value, _ := strings.Cut(pair, "=")
		if key == "token" {
			value = tokenShape(value)
		}
		params = append(params, key+"="+value)
	}
	out := "<base>" + u.Path
	if len(params) > 0 {
		out += "?" + strings.Join(params, "&")
	}
	return out
}

// tokenShape reads the structure off the token itself, so a new format shows up as a diff.
func tokenShape(raw string) string {
	var b strings.Builder
	rest := raw
	prefix := keyPrefix.FindString(rest)
	if prefix != "" {
		b.WriteString(prefix)
		rest = rest[len(prefix):]
	}
	if id, secret, ok := strings.Cut(rest, "_"); ok {
		if parsed, err := uuid.Parse(id); err == nil {
			fmt.Fprintf(&b, "<uuidv%d>_", parsed[6]>>4)
			rest = secret
		}
	}
	if hasChecksum(raw) {
		// The random part of a checksummed token is base32, which a base64url alphabet run would also match.
		random := rest[:len(rest)-checksumLen]
		if within(random, base32Alphabet) {
			fmt.Fprintf(&b, "<base32:%d>", len(random))
		} else {
			b.WriteString(alphabetRun(random))
		}
		fmt.Fprintf(&b, "<crc32 hex:%d>", checksumLen)
	} else {
		b.WriteString(alphabetRun(rest))
	}
	fmt.Fprintf(&b, " (%d chars)", len(raw))
	return b.String()
}

func alphabetRun(s string) string {
	switch {
	case userCode.MatchString(s):
		return "<" + userCodeAlphabet + ":4>-<" + userCodeAlphabet + ":4>"
	case within(s, base64urlAlphabet):
		return fmt.Sprintf("<base64url:%d>", len(s))
	default:
		return fmt.Sprintf("<other:%d>", len(s))
	}
}

func within(s, alphabet string) bool {
	return s != "" && strings.Trim(s, alphabet) == ""
}

// hasChecksum is true when the last eight characters are the crc32 of the rest, in hex.
func hasChecksum(raw string) bool {
	if len(raw) <= checksumLen {
		return false
	}
	body, check := raw[:len(raw)-checksumLen], raw[len(raw)-checksumLen:]
	return fmt.Sprintf("%08x", crc32.ChecksumIEEE([]byte(body))) == check
}

// tamper changes one character in the middle of the random part to another of its kind, so only the checksum or
// the lookup can catch it.
func tamper(raw string) string {
	start := len(keyPrefix.FindString(raw))
	if id, _, ok := strings.Cut(raw[start:], "_"); ok {
		if _, err := uuid.Parse(id); err == nil {
			start += len(id) + 1
		}
	}
	i := start + (len(raw)-start)/2
	if raw[i] == '-' {
		i++
	}
	swap := byte('B')
	switch c := raw[i]; {
	case c >= 'a' && c <= 'z':
		swap = 'b'
	case c >= '0' && c <= '9':
		swap = '2'
	}
	if raw[i] == swap {
		swap++
	}
	return raw[:i] + string(swap) + raw[i+1:]
}

// errText is the code and message of an RPC error, the way a golden file records it.
func errText(err error) string {
	if ce, ok := errors.AsType[*connect.Error](err); ok {
		return fmt.Sprintf("error %s %q", ce.Code(), ce.Message())
	}
	return fmt.Sprintf("error %s %q", connect.CodeOf(err), err.Error())
}
