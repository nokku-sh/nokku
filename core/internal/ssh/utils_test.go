package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestGetSigner(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(ed)
	require.NoError(t, err)
	signer, err := getSigner(der)
	require.NoError(t, err)
	assert.Equal(t, ssh.KeyAlgoED25519, signer.PublicKey().Type())
}

// The core stores CA keys as PKCS#8 DER, anything else is not one of its keys.
func TestGetSigner_RejectsOtherForms(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(ed)
	require.NoError(t, err)
	openssh, err := ssh.MarshalPrivateKey(ed, "")
	require.NoError(t, err)
	for name, raw := range map[string][]byte{
		"nil":         nil,
		"garbage":     []byte("not a key"),
		"pkcs8 pem":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"openssh pem": pem.EncodeToMemory(openssh),
	} {
		_, err := getSigner(raw)
		assert.Error(t, err, "getSigner(%s)", name)
	}
}

func TestMarshalPubKey_RoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	line, err := MarshalPubKey(priv.Public())
	require.NoError(t, err)
	require.NotEmpty(t, line)

	// The output must parse back as an authorized key matching the original.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	require.NoError(t, err, "output %q does not parse as authorized key", line)
	want, err := ssh.NewPublicKey(priv.Public())
	require.NoError(t, err)
	assert.Equal(t, want.Marshal(), pub.Marshal(), "round-tripped key does not match original")
}

func TestParsePublicKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub, err := ssh.NewPublicKey(priv.Public())
	require.NoError(t, err)
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n") + " x"

	_, err = ParsePublicKey(line)
	require.NoError(t, err, "parse valid key")
	_, err = ParsePublicKey("garbage")
	require.Error(t, err, "parse garbage should fail")
}
