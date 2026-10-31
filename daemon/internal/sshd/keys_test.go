package sshd

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

// presentedHostKey is the host key a client sees in the handshake.
func presentedHostKey(t *testing.T, addr string) ssh.PublicKey {
	t.Helper()
	var got ssh.PublicKey
	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "nobody",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errors.New("seen")
		},
		Timeout: 10 * time.Second,
	})
	require.ErrorContains(t, err, "seen")
	require.NotNil(t, got, "no host key presented")
	return got
}

func TestHostKeyIsARootOnlyFile(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	addr, closeFn := startTestServer(t, newTestCA(t))
	defer closeFn()

	info, err := os.Stat(paths.HostKey())
	must.NoError(err, "the server started without a host key file")
	is.Equal(os.FileMode(0o600), info.Mode().Perm())
	data, err := os.ReadFile(paths.HostKey())
	must.NoError(err)
	is.True(strings.HasPrefix(string(data), "-----BEGIN OPENSSH PRIVATE KEY-----"), "not an OpenSSH key file")
	key, err := ssh.ParsePrivateKey(data)
	must.NoError(err)

	is.Equal(key.PublicKey().Marshal(), presentedHostKey(t, addr).Marshal(), "the handshake signed with another key")
	pub, err := os.ReadFile(paths.HostKeyPub())
	must.NoError(err)
	is.Equal(string(ssh.MarshalAuthorizedKey(key.PublicKey())), string(pub))
}

// If the host key changed, every known_hosts entry would break on daemon restart.
func TestHostKeysStable(t *testing.T) {
	must := require.New(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())

	first, err := loadHostKey()
	must.NoError(err, "load host key")
	second, err := loadHostKey()
	must.NoError(err, "reload host key")
	assert.Equal(t, first.PublicKey().Marshal(), second.PublicKey().Marshal())
}

// An enrollment starts with a new key, and the certificate of the old one goes with it.
func TestCreateHostKeyReplacesTheKeyAndItsCert(t *testing.T) {
	must := require.New(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	before, err := loadHostKey()
	must.NoError(err)
	must.NoError(os.WriteFile(paths.HostKeyCert(), []byte("cert of the old key"), 0o644))

	must.NoError(CreateHostKey())
	after, err := loadHostKey()
	must.NoError(err)
	assert.NotEqual(t, before.PublicKey().Marshal(), after.PublicKey().Marshal(), "the key stayed the same")
	_, err = os.Stat(paths.HostKeyCert())
	assert.ErrorIs(t, err, os.ErrNotExist, "the certificate of the previous key must be dropped")
}

func TestHostKeyReadableByOthersIsRefused(t *testing.T) {
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	require.NoError(t, CreateHostKey())
	require.NoError(t, os.Chmod(paths.HostKey(), 0o644))

	_, err := New(nil)
	assert.ErrorContains(t, err, "readable by others")
}

// The TPM holds only the daemon's identity, so a flood of handshakes can never queue up in front of it.
func TestHandshakeNeedsNoTPM(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not installed")
	}
	cmd := exec.Command("go", "list", "-deps", ".")
	out, err := cmd.Output()
	require.NoError(t, err, "go list")
	deps := strings.Fields(string(out))
	require.Contains(t, deps, "golang.org/x/crypto/ssh", "go list did not list the dependencies")
	assert.False(t, slices.Contains(deps, "github.com/nokku-sh/nokku/internal/tpm"), "the SSH server reaches the TPM")
}
