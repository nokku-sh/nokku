//go:build linux

package id

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadMachineIDSkipsMissingSources(t *testing.T) {
	dir := t.TempDir()
	idFile := filepath.Join(dir, "machine-id")
	require.NoError(t, os.WriteFile(idFile, []byte("ABC123\n"), 0o600))

	id, err := readMachineID([]string{filepath.Join(dir, "missing"), idFile})
	require.NoError(t, err)
	assert.Equal(t, "abc123", id)
}

// A source that fails to read must not hand the key over to the next one.
func TestReadMachineIDFailsOnABrokenSource(t *testing.T) {
	dir := t.TempDir()
	idFile := filepath.Join(dir, "machine-id")
	require.NoError(t, os.WriteFile(idFile, []byte("abc123"), 0o600))

	_, err := readMachineID([]string{dir, idFile})
	require.Error(t, err, "a directory read as an ID source fell through to the next")
}
