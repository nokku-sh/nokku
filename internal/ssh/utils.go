package ssh

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// GetSigner creates a signer from private key bytes.
func GetSigner(privDER []byte) (ssh.Signer, error) {
	key, err := parsePrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH signer: %w", err)
	}
	return signer, nil
}

func parsePrivateKey(keyBytes []byte) (any, error) {
	parsers := []func([]byte) (any, error){
		x509.ParsePKCS8PrivateKey,
		func(data []byte) (any, error) {
			return x509.ParsePKCS1PrivateKey(data)
		},
		func(data []byte) (any, error) {
			return x509.ParseECPrivateKey(data)
		},
		ssh.ParseRawPrivateKey,
	}

	for _, parse := range parsers {
		key, err := parse(keyBytes)
		if err == nil {
			return key, nil
		}
	}

	if block, _ := pem.Decode(keyBytes); block != nil {
		for _, parse := range parsers[:3] {
			key, err := parse(block.Bytes)
			if err == nil {
				return key, nil
			}
		}
	}

	return nil, errors.New("unsupported private key format")
}

// MarshalPubKey converts a public key to an authorized key string.
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
