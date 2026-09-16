package ssh

import (
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
