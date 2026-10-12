package ssh

import (
	"golang.org/x/crypto/ssh"
)

func ParsePublicKey(line string) (ssh.PublicKey, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, err
	}
	return key, nil
}
