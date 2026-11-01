package storage

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateWriterRoundtrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NOKKU_STORAGE_URL", "file://"+dir)

	s, err := New(t.Context())
	require.NoError(t, err)

	key := RecordingPath("ws-1", "00000000-0000-0000-0000-000000000001")
	w, err := s.CreateWriter(t.Context(), key)
	require.NoError(t, err)

	// Simulate the daemon streaming gzip bytes in batches.
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write([]byte(`{"version":2}` + "\n"))
	_ = gw.Flush()
	batch1 := append([]byte(nil), gz.Bytes()...)
	_, _ = gw.Write([]byte("[0.1, \"o\", \"hello\\r\\n\"]\n"))
	_ = gw.Flush()
	after := gz.Len()
	batch2 := append([]byte(nil), gz.Bytes()[len(batch1):after]...)
	_ = gw.Close()
	// The daemon's recorder Close flushes the gzip footer as one last batch.
	batch3 := append([]byte(nil), gz.Bytes()[after:]...)

	_, err = w.Write(batch1)
	require.NoError(t, err, "write batch 1")
	_, err = w.Write(batch2)
	require.NoError(t, err, "write batch 2")
	_, err = w.Write(batch3)
	require.NoError(t, err, "write batch 3")
	require.NoError(t, w.Close())

	// The object must be a single file containing the whole stream.
	_, err = os.Stat(filepath.Join(dir, filepath.FromSlash(key)))
	require.NoError(t, err)

	rc, err := s.Reader(t.Context(), key)
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.Equal(t, gz.Bytes(), got)

	// Partial stream (daemon died) must still commit.
	key2 := RecordingPath("ws-1", "00000000-0000-0000-0000-000000000002")
	w2, err := s.CreateWriter(t.Context(), key2)
	require.NoError(t, err)
	_, err = w2.Write(batch1)
	require.NoError(t, err)
	require.NoError(t, w2.Close())
	_, err = s.Reader(t.Context(), key2)
	require.NoError(t, err, "partial object unreadable")

	require.NoError(t, s.Delete(t.Context(), key))
	_, err = os.Stat(filepath.Join(dir, filepath.FromSlash(key)))
	require.ErrorIs(t, err, os.ErrNotExist, "object still present after delete")
}
