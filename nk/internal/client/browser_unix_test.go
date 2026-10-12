//go:build !windows

package client

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The link comes from the backend, so it must reach the opener as one
// argument and never pass through a shell.
func TestOpenBrowserPassesTheLinkAsOneArgument(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "args")
	script := []byte("#!/bin/sh\nprintf '%s\\n' \"$#\" \"$1\" > \"$NK_TEST_OUT\"\n")
	for _, opener := range []string{"open", "xdg-open"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, opener), script, 0o700))
	}
	t.Setenv("PATH", dir)
	t.Setenv("NK_TEST_OUT", out)

	link := `https://app.nokku.sh/device?user_code=AB-CD&next=$(id);'"`
	require.NoError(t, openBrowser(t.Context(), link))

	got, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "1\n"+link+"\n", string(got))
}
