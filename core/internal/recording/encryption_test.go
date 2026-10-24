package recording

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/storage"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	t.Setenv("NOKKU_STORAGE_URL", "file://"+t.TempDir())
	st, err := storage.New(t.Context())
	require.NoError(t, err)
	return &Service{store: st}
}

func testRecording() *db.Recording {
	return &db.Recording{ID: "rec1", WorkspaceID: "ws1", Key: NewKey(), Complete: true}
}

// writeRecording stores plaintext in small chunks, the way a daemon streams it.
func writeRecording(t *testing.T, s *Service, rec *db.Recording, plaintext []byte) {
	t.Helper()
	w, err := s.NewWriter(t.Context(), rec)
	require.NoError(t, err)
	for chunk := range slices.Chunk(plaintext, 1000) {
		require.NoError(t, w.WriteChunk(chunk))
	}
	require.NoError(t, w.Close())
}

func storedObject(t *testing.T, s *Service, rec *db.Recording) []byte {
	t.Helper()
	rc, err := s.store.Reader(t.Context(), storage.RecordingPath(rec.WorkspaceID, rec.ID))
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	raw, err := io.ReadAll(rc)
	require.NoError(t, err)
	return raw
}

// storeObject overwrites rec's object, the way someone with write access to the bucket could.
func storeObject(t *testing.T, s *Service, rec *db.Recording, raw []byte) {
	t.Helper()
	w, err := s.store.CreateWriter(t.Context(), storage.RecordingPath(rec.WorkspaceID, rec.ID))
	require.NoError(t, err)
	_, err = w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())
}

func readAll(t *testing.T, s *Service, rec *db.Recording) ([]byte, error) {
	t.Helper()
	r, err := s.OpenReader(t.Context(), rec)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return io.ReadAll(r)
}

func TestRecordingRoundTrip(t *testing.T) {
	s := newTestService(t)
	rec := testRecording()
	want := []byte(strings.Repeat("a line of a terminal\n", 2000))
	writeRecording(t, s, rec, want)

	assert.False(t, bytes.Contains(storedObject(t, s, rec), []byte("a line of a terminal")), "stored in the clear")
	got, err := readAll(t, s, rec)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// Someone with write access to the bucket must not change what a recording shows without the reader noticing.
func TestRecordingIsBoundToItsObject(t *testing.T) {
	s := newTestService(t)
	rec := testRecording()
	writeRecording(t, s, rec, []byte(strings.Repeat("x", 5*segmentSize)))
	raw := storedObject(t, s, rec)
	require.Greater(t, len(raw), 4*segmentSize)

	for name, tamper := range map[string]func([]byte) []byte{
		"cut at a segment":     func(b []byte) []byte { return b[:2*segmentSize] },
		"cut inside a segment": func(b []byte) []byte { return b[:len(b)-10] },
		"a flipped bit":        func(b []byte) []byte { c := bytes.Clone(b); c[segmentSize+7] ^= 1; return c },
		"two segments swapped": func(b []byte) []byte {
			c := bytes.Clone(b)
			first, second := c[segmentSize:2*segmentSize], c[2*segmentSize:3*segmentSize]
			tmp := bytes.Clone(first)
			copy(first, second)
			copy(second, tmp)
			return c
		},
	} {
		t.Run(name, func(t *testing.T) {
			storeObject(t, s, rec, tamper(raw))
			_, err := readAll(t, s, rec)
			require.Error(t, err)
		})
	}

	t.Run("the object of another recording with the same key", func(t *testing.T) {
		other := &db.Recording{ID: "rec2", WorkspaceID: rec.WorkspaceID, Key: rec.Key}
		storeObject(t, s, other, raw)
		_, err := readAll(t, s, other)
		require.Error(t, err)
	})

	t.Run("another recording's key", func(t *testing.T) {
		storeObject(t, s, rec, raw)
		_, err := readAll(t, s, &db.Recording{ID: rec.ID, WorkspaceID: rec.WorkspaceID, Key: NewKey()})
		require.Error(t, err)
	})
}
