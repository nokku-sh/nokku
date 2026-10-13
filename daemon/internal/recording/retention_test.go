package recording

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Files that are not recordings, and recordings still being written, are never touched.
func TestEnforceRetention(t *testing.T) {
	dir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	// Truncate makes the big files sparse, so they take no real disk space.
	write := func(name string, size int64, age time.Duration) {
		path := filepath.Join(dir, name)
		must.NoError(os.WriteFile(path, nil, 0o600))
		must.NoError(os.Truncate(path, size))
		mod := time.Now().Add(-age)
		must.NoError(os.Chtimes(path, mod, mod))
	}
	write("expired.cast.gz", 1, maxAge+time.Hour)
	write("oldest.cast.gz", maxTotalSpace/2+1, 3*time.Hour)
	write("older.cast.gz", maxTotalSpace/2+1, 2*time.Hour)
	write("newest.cast.gz", 1, time.Hour)
	write("notes.txt", 1, maxAge+time.Hour)
	write("active.cast.gz", 1, maxAge+time.Hour)
	activePath := filepath.Join(dir, "active.cast.gz")
	active.Store(activePath, struct{}{})
	t.Cleanup(func() { active.Delete(activePath) })

	must.NoError(enforceRetention())

	entries, err := os.ReadDir(dir)
	must.NoError(err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	is.Equal([]string{"active.cast.gz", "newest.cast.gz", "notes.txt", "older.cast.gz"}, names)
}
