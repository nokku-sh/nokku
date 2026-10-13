package sshd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// OpenSSH dropped these from its defaults, so a client that offers nothing else is refused.
func TestServerRefusesLegacyAlgorithms(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()
	auth := userCert(t, ca, testPrincipal)

	for name, config := range map[string]ssh.Config{
		"sha1 key exchange": {KeyExchanges: []string{ssh.InsecureKeyExchangeDH14SHA1}},
		// An AEAD cipher skips the MAC negotiation, so the client has to ask for a CTR one.
		"truncated sha1 mac": {Ciphers: []string{ssh.CipherAES128CTR}, MACs: []string{ssh.InsecureHMACSHA196}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &ssh.ClientConfig{
				Config:          config,
				User:            currentUser(t),
				Auth:            []ssh.AuthMethod{auth},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 - test server
				Timeout:         10 * time.Second,
			}
			client, err := ssh.Dial("tcp", addr, cfg)
			if err == nil {
				_ = client.Close()
			}
			require.Error(t, err, "legacy algorithm was negotiated")
		})
	}
}
