//go:build integration

package sshd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The image the daemon ships on, so the accounts and tools are the ones a container user has.
const asRootImage = "debian:13.7-slim"

// Docker is rootful here and in CI, so the root-only test of asuser_test.go runs as root inside a throwaway container.
func TestSessionsRunAsTheUserInAContainer(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "sshd.test")
	build := exec.CommandContext(t.Context(), "go", "test", "-c", "-tags", "asroot", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build the test binary: %s", out)
	require.NoError(t, os.Chmod(bin, 0o755))

	run := exec.CommandContext(t.Context(), "docker", "run", "--rm",
		"--volume", bin+":/usr/local/bin/sshd.test:ro",
		asRootImage, "/usr/local/bin/sshd.test", "-test.run", "^TestSessionsRunAsTheUser$", "-test.v",
	)
	out, err = run.CombinedOutput()
	t.Logf("in the container:\n%s", out)
	require.NoError(t, err, "a session feature did not run as the user")
}
