package ssh

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/cli/internal/paths"
)

// fakeKeygen acts like ssh-keygen with a security key plugged in, FAKE_KEYGEN_MODE picks a failure.
const fakeKeygen = `#!/bin/sh
echo "$@" >> "$FAKE_KEYGEN_LOG"
while [ $# -gt 0 ]; do
  case "$1" in
    -t) type=$2; shift ;;
    -f) file=$2; shift ;;
  esac
  shift
done
case "$FAKE_KEYGEN_MODE" in
  no-provider)
    echo "No FIDO SecurityKeyProvider specified" >&2
    echo "Key enrollment failed: invalid format" >&2
    exit 255 ;;
  no-ed25519)
    if [ "$type" = ed25519-sk ]; then
      echo "Key enrollment failed: requested feature not supported" >&2
      exit 255
    fi ;;
esac
echo handle > "$file"
echo "$FAKE_KEYGEN_PUB" > "$file.pub"
`

// useFakeKeygen returns the calls the fake ssh-keygen got so far.
func useFakeKeygen(t *testing.T, mode string) (calls func() []string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake ssh-keygen is a shell script")
	}
	setupSSHDir(t)
	bin := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "ssh-keygen"), []byte(fakeKeygen), 0o700)) // #nosec G306
	log := filepath.Join(t.TempDir(), "calls")
	t.Setenv("PATH", bin)
	t.Setenv("FAKE_KEYGEN_LOG", log)
	t.Setenv("FAKE_KEYGEN_MODE", mode)
	t.Setenv("FAKE_KEYGEN_PUB", securityKeyLine(t)+" x@nokku")
	return func() []string {
		data, err := os.ReadFile(log)
		if os.IsNotExist(err) {
			return nil
		}
		require.NoError(t, err)
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
}

func TestEnrollSecurityKey(t *testing.T) {
	calls := useFakeKeygen(t, "ok")

	require.NoError(t, EnrollSecurityKey(t.Context()))
	assert.FileExists(t, paths.SecurityKeyFile())
	assert.FileExists(t, paths.SecurityKeyFile()+".pub")
	require.Len(t, calls(), 1)
	assert.Contains(t, calls()[0], "-t ed25519-sk -O application=ssh:nokku")

	require.NoError(t, EnrollSecurityKey(t.Context()))
	assert.Len(t, calls(), 1, "a handle that exists is kept, no second touch")
}

func TestEnrollSecurityKeyFallsBackToECDSA(t *testing.T) {
	calls := useFakeKeygen(t, "no-ed25519")

	require.NoError(t, EnrollSecurityKey(t.Context()))
	require.Len(t, calls(), 2)
	assert.Contains(t, calls()[1], "-t ecdsa-sk")
	assert.FileExists(t, paths.SecurityKeyFile()+".pub")
}

func TestEnrollSecurityKeyWithoutFIDOSupport(t *testing.T) {
	calls := useFakeKeygen(t, "no-provider")

	err := EnrollSecurityKey(t.Context())
	require.ErrorContains(t, err, "can't use security keys")
	assert.Len(t, calls(), 1, "another key type would fail the same way")
	assert.NoFileExists(t, paths.SecurityKeyFile()+".pub")
}
