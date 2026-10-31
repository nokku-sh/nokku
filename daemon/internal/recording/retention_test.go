package recording

import (
	"os"
	"path/filepath"
	"syscall"
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
	write("expired.part", 1, maxAge+time.Hour)
	write("oldest.cast.gz", maxTotalSpace/2+1, 3*time.Hour)
	write("older.cast.gz", maxTotalSpace/2+1, 2*time.Hour)
	write("newest.part", 1, time.Hour)
	write("notes.txt", 1, maxAge+time.Hour)
	write("written.part", 1, maxAge+time.Hour)
	// The lock a recorder holds while it writes.
	f, err := os.Open(filepath.Join(dir, "written.part"))
	must.NoError(err)
	defer f.Close()
	must.NoError(syscall.Flock(int(f.Fd()), syscall.LOCK_EX))

	must.NoError(enforceRetention())

	entries, err := os.ReadDir(dir)
	must.NoError(err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	is.Equal([]string{"newest.part", "notes.txt", "older.cast.gz", "written.part"}, names)
}
