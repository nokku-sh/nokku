//go:build integration

package sshd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The image the daemon ships on, with the accounts and tools users have.
const asRootImage = "debian:13.7-slim"

// Docker is rootful here and in CI, so the root-only test of asuser_test.go
// runs in a throwaway container. The binary goes in with docker cp, a bind
// mount finds nothing under dind.
func TestSessionsRunAsTheUserInAContainer(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "sshd.test")
	build := exec.CommandContext(t.Context(), "go", "test", "-c", "-tags", "asroot", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build the test binary: %s", out)
	require.NoError(t, os.Chmod(bin, 0o755))

	created, err := exec.CommandContext(t.Context(), "docker", "create", asRootImage,
		"/usr/local/bin/sshd.test", "-test.run", "^TestSessionsRunAsTheUser$", "-test.v",
	).Output()
	require.NoError(t, err, "create the container")
	id := strings.TrimSpace(string(created))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "--force", id).Run() })

	out, err = exec.CommandContext(t.Context(), "docker", "cp", bin, id+":/usr/local/bin/sshd.test").CombinedOutput()
	require.NoError(t, err, "copy the test binary in: %s", out)

	out, err = exec.CommandContext(t.Context(), "docker", "start", "--attach", id).CombinedOutput()
	t.Logf("in the container:\n%s", out)
	require.NoError(t, err, "a session feature did not run as the user")
}
