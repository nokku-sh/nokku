package ssh

import (
	"bytes"

	"golang.org/x/crypto/ssh"
)

// ParsePublicKey parses a single authorized-key line.
func ParsePublicKey(line string) (ssh.PublicKey, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, err
	}
	return key, nil
}

// HostKeyMatches reports whether the submitted authorized-key line is the
// same key as the pinned one. Keys are compared canonically so formatting
// and comments do not matter.
func HostKeyMatches(pinned, submitted string) bool {
	p, err := ParsePublicKey(pinned)
	if err != nil {
		return false
	}
	s, err := ParsePublicKey(submitted)
	if err != nil {
		return false
	}
	return bytes.Equal(p.Marshal(), s.Marshal())
}
