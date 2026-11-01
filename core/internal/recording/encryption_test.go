package recording

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/crypto/kms"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/storage"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	t.Setenv("NOKKU_STORAGE_URL", "file://"+t.TempDir())
	st, err := storage.New(t.Context())
	require.NoError(t, err)
	keys, err := kms.Ephemeral()
	require.NoError(t, err)
	return &Service{store: st, keys: keys}
}

// newRecording seals key for the recording id, the way an upload stores it.
func newRecording(t *testing.T, s *Service, id string, key []byte) *db.Recording {
	t.Helper()
	sealed, err := s.keys.Seal(KeyAAD("ws1", id), key)
	require.NoError(t, err)
	return &db.Recording{ID: id, ObjectID: new(id), WorkspaceID: "ws1", Key: sealed, Complete: true}
}

// writeRecording stores plaintext in small chunks, the way a daemon streams it.
func writeRecording(t *testing.T, s *Service, rec *db.Recording, plaintext []byte) {
	t.Helper()
	w, err := s.NewWriter(t.Context(), rec, *rec.ObjectID)
	require.NoError(t, err)
	for chunk := range slices.Chunk(plaintext, 1000) {
		require.NoError(t, w.WriteChunk(chunk))
	}
	require.NoError(t, w.Close())
}

func storedObject(t *testing.T, s *Service, rec *db.Recording) []byte {
	t.Helper()
	rc, err := s.store.Reader(t.Context(), storage.RecordingPath(rec.WorkspaceID, *rec.ObjectID))
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	raw, err := io.ReadAll(rc)
	require.NoError(t, err)
	return raw
}

// storeObject overwrites rec's object, as bucket write access could.
func storeObject(t *testing.T, s *Service, rec *db.Recording, raw []byte) {
	t.Helper()
	w, err := s.store.CreateWriter(t.Context(), storage.RecordingPath(rec.WorkspaceID, *rec.ObjectID))
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
	rec := newRecording(t, s, "rec1", NewKey())
	want := []byte(strings.Repeat("a line of a terminal\n", 2000))
	writeRecording(t, s, rec, want)

	assert.False(t, bytes.Contains(storedObject(t, s, rec), []byte("a line of a terminal")), "stored in the clear")
	got, err := readAll(t, s, rec)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// Bucket write access must not change what a recording shows unnoticed.
func TestRecordingIsBoundToItsObject(t *testing.T) {
	s := newTestService(t)
	key := NewKey()
	rec := newRecording(t, s, "rec1", key)
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
		other := newRecording(t, s, "rec2", key)
		storeObject(t, s, other, raw)
		_, err := readAll(t, s, other)
		require.Error(t, err)
	})

	t.Run("another recording's key", func(t *testing.T) {
		storeObject(t, s, rec, raw)
		_, err := readAll(t, s, newRecording(t, s, rec.ID, NewKey()))
		require.Error(t, err)
	})

	t.Run("an older upload of the same recording", func(t *testing.T) {
		older := *rec
		older.ObjectID = new("older")
		writeRecording(t, s, &older, []byte("the start of the session"))
		storeObject(t, s, rec, storedObject(t, s, &older))
		_, err := readAll(t, s, rec)
		require.Error(t, err)
	})
}

func TestRecordingWithoutAnObjectIsNotStored(t *testing.T) {
	s := newTestService(t)
	rec := newRecording(t, s, "rec1", NewKey())
	rec.ObjectID = nil
	_, err := s.OpenReader(t.Context(), rec)
	require.ErrorIs(t, err, ErrNotStored)
}
