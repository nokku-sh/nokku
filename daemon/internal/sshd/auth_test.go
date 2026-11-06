package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const skApplication = "ssh:nokku"

// skSigner signs like an ed25519-sk security key, x/crypto has no such signer.
type skSigner struct {
	pub     ssh.PublicKey
	priv    ed25519.PrivateKey
	touched bool
}

func newSKSigner(t *testing.T, touched bool) skSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Name        string
		Key         []byte
		Application string
	}{ssh.KeyAlgoSKED25519, pub, skApplication}))
	require.NoError(t, err)
	return skSigner{pub: key, priv: priv, touched: touched}
}

func (s skSigner) PublicKey() ssh.PublicKey { return s.pub }

// The key signs its flags and counter along with the data, the touch is flag 0x01.
func (s skSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	var flags byte
	if s.touched {
		flags = 0x01
	}
	flagsAndCounter := []byte{flags, 0, 0, 0, 1}
	app, digest := sha256.Sum256([]byte(skApplication)), sha256.Sum256(data)
	return &ssh.Signature{
		Format: ssh.KeyAlgoSKED25519,
		Blob:   ed25519.Sign(s.priv, slices.Concat(app[:], flagsAndCounter, digest[:])),
		Rest:   flagsAndCounter,
	}, nil
}

// nk's security keys: x/crypto refuses a signature nobody touched the key for.
func TestServerSecurityKeyNeedsATouch(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), certAuth(t, ca, newSKSigner(t, true), nil, testPrincipal))
	require.NoError(t, err, "a touched security key")
	_ = client.Close()

	_, err = dial(t, addr, currentUser(t), certAuth(t, ca, newSKSigner(t, false), nil, testPrincipal))
	assert.Error(t, err, "a security key signed without a touch")
}

func TestServerSourceAddress(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	withSource := func(cidr string) ssh.AuthMethod {
		return userCertOpts(t, ca, func(c *ssh.Certificate) {
			c.CriticalOptions = map[string]string{"source-address": cidr}
		}, testPrincipal)
	}

	client, err := dial(t, addr, currentUser(t), withSource("127.0.0.0/8"))
	must.NoError(err, "dial from allowed source")
	_ = client.Close()

	_, err = dial(t, addr, currentUser(t), withSource("203.0.113.0/24"))
	is.Error(err, "dial from disallowed source succeeded")
}

func TestServerRejectsHostCert(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	hostCert := userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.CertType = ssh.HostCert
	}, testPrincipal)

	_, err := dial(t, addr, currentUser(t), hostCert)
	is.Error(err, "host certificate authenticated a user")
}

func TestServerCertExtensionPTY(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.Extensions = nil
	}, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err)
	defer sess.Close()

	err = sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{})
	is.Error(err, "pty-req succeeded without permit-pty")
}

func TestServerCertExtensionForwarding(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.Extensions = nil
	}, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	_, err = client.Dial("tcp", "127.0.0.1:9")
	is.Error(err, "direct-tcpip succeeded without permit-port-forwarding")
}

func TestServerCertExtensionAgent(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.Extensions = nil
	}, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err)
	defer sess.Close()

	err = agent.RequestAgentForwarding(sess)
	is.Error(err, "agent forwarding succeeded without permit-agent-forwarding")
}
