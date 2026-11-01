package sshd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// OpenSSH dropped these defaults, so a client offering only them is refused.
func TestServerRefusesLegacyAlgorithms(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()
	auth := userCert(t, ca, testPrincipal)

	for name, config := range map[string]ssh.Config{
		"sha1 key exchange": {KeyExchanges: []string{ssh.InsecureKeyExchangeDH14SHA1}},
		// An AEAD cipher skips MAC negotiation, so the client asks for CTR.
		"truncated sha1 mac": {Ciphers: []string{ssh.CipherAES128CTR}, MACs: []string{ssh.InsecureHMACSHA196}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &ssh.ClientConfig{
				Config:          config,
				User:            currentUser(t),
				Auth:            []ssh.AuthMethod{auth},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106
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
