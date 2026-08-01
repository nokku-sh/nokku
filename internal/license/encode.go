package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
)

const (
	prefix  = "NOKKU-" // lets the verifier reject non-keys without decoding.
	version = byte(1)  // key format version; bump when the payload encoding changes.
)

// encodeKey renders version + payload + signature as a dash-grouped base64 string.
func encodeKey(payload, sig []byte) string {
	data := make([]byte, 0, 1+len(payload)+len(sig))
	data = append(data, version)
	data = append(data, payload...)
	data = append(data, sig...)

	s := base64.RawStdEncoding.EncodeToString(data)

	var b strings.Builder
	b.Grow(len(prefix) + len(s) + len(s)/5)
	b.WriteString(prefix)
	for i := 0; i < len(s); i += 5 {
		if i > 0 {
			b.WriteByte('-')
		}
		end := min(i+5, len(s))
		b.WriteString(s[i:end])
	}
	return b.String()
}

func decodeKey(key string) (payload, sig []byte, err error) {
	enc, ok := strings.CutPrefix(key, prefix)
	if !ok {
		return nil, nil, ErrInvalid
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.ReplaceAll(enc, "-", ""))
	if err != nil || len(raw) < 1+ed25519.SignatureSize+1 {
		return nil, nil, ErrInvalid
	}
	if raw[0] != version {
		return nil, nil, ErrInvalid
	}
	sigLen := ed25519.SignatureSize
	return raw[1 : len(raw)-sigLen], raw[len(raw)-sigLen:], nil
}
