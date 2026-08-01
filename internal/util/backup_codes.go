package util

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

const (
	codeBytes  = 10 // 80 bits of entropy
	codeCount  = 10
	codeLength = 16 // 10 bytes Base32-encoded = 16 characters
)

var backupEncoding = base32.NewEncoding("ABCDEFGHJKLMNPQRSTUVWXYZ23456789").
	WithPadding(base32.NoPadding)

// GenerateBackupCodes creates 10 cryptographically secure random backup codes.
func GenerateBackupCodes() ([]string, error) {
	b := make([]byte, codeCount*codeBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	codes := make([]string, codeCount)
	for i := range codes {
		offset := i * codeBytes
		raw := backupEncoding.EncodeToString(b[offset : offset+codeBytes])

		codes[i] = raw[0:4] + "-" + raw[4:8] + "-" + raw[8:12] + "-" + raw[12:16]
	}

	return codes, nil
}

// NormalizeBackupCode formats the code and maps common visual typos.
func NormalizeBackupCode(code string) string {
	code = strings.ToUpper(code)
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")

	// Correct lookalike typos: 1/I -> L, 0/O -> Q.
	replacements := strings.NewReplacer(
		"1", "L",
		"I", "L",
		"0", "Q",
		"O", "Q",
	)
	code = replacements.Replace(code)

	if len(code) == codeLength {
		return code[0:4] + "-" + code[4:8] + "-" + code[8:12] + "-" + code[12:16]
	}

	return code
}
