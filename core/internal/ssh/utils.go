package ssh

import (
	"crypto/x509"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// getSigner reads a CA key, which the core only ever stores as PKCS#8.
func getSigner(der []byte) (ssh.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH signer: %w", err)
	}
	return signer, nil
}

func MarshalPubKey(key any) (string, error) {
	pub, err := ssh.NewPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to convert public key: %w", err)
	}
	return MarshalKey(pub), nil
}

func MarshalKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}
