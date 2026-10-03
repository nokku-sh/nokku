package recording

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/storage"
)

// rawObject returns the stored bytes of rec, split into frames.
func rawFrames(t *testing.T, s *Service, rec *db.Recording) [][]byte {
	t.Helper()
	rc, err := s.store.Reader(context.Background(), storage.RecordingPath(rec.WorkspaceID, rec.ID))
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()
	raw, err := io.ReadAll(rc)
	require.NoError(t, err)

	var frames [][]byte
	for len(raw) > 0 {
		size := 5 + int(binary.BigEndian.Uint32(raw[1:5]))
		frames = append(frames, raw[:size])
		raw = raw[size:]
	}
	return frames
}

// storeFrames overwrites rec's object with frames, the way someone with
// write access to the bucket could.
func storeFrames(t *testing.T, s *Service, rec *db.Recording, frames [][]byte) {
	t.Helper()
	w, err := s.store.CreateWriter(context.Background(),
		storage.RecordingPath(rec.WorkspaceID, rec.ID),
		storage.StoreOptions{ContentType: "application/octet-stream"})
	require.NoError(t, err)
	_, err = w.Write(bytes.Join(frames, nil))
	require.NoError(t, err)
	require.NoError(t, w.Close())
}

func readAll(t *testing.T, s *Service, rec *db.Recording) ([]byte, error) {
	t.Helper()
	fr, err := s.OpenReader(context.Background(), rec)
	require.NoError(t, err)
	defer func() { _ = fr.Close() }()
	return io.ReadAll(iotestSmallReads{fr})
}

// iotestSmallReads reads seven bytes at a time, to cross frame boundaries.
type iotestSmallReads struct{ r io.Reader }

func (s iotestSmallReads) Read(p []byte) (int, error) {
	return s.r.Read(p[:min(7, len(p))])
}

func TestFramesRoundTrip(t *testing.T) {
	s := newScrubTestService(t)
	rec := testRecording()
	want := []byte(strings.Repeat("frame\n", 500))
	writeFrames(t, s, rec, want)

	got, err := readAll(t, s, rec)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// Someone with write access to the bucket must not be able to change what a
// recording shows without the reader noticing.
func TestFramesAreBoundToTheirRecording(t *testing.T) {
	s := newScrubTestService(t)
	rec := testRecording()
	writeFrames(t, s, rec, []byte(strings.Repeat("frame\n", 50)))
	frames := rawFrames(t, s, rec)
	require.Greater(t, len(frames), 3)

	t.Run("cut at a frame boundary", func(t *testing.T) {
		storeFrames(t, s, rec, frames[:2])
		_, err := readAll(t, s, rec)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("a frame removed from the middle", func(t *testing.T) {
		storeFrames(t, s, rec, append([][]byte{frames[0]}, frames[2:]...))
		_, err := readAll(t, s, rec)
		require.Error(t, err)
	})

	t.Run("frames reordered", func(t *testing.T) {
		swapped := append([][]byte{frames[1], frames[0]}, frames[2:]...)
		storeFrames(t, s, rec, swapped)
		_, err := readAll(t, s, rec)
		require.Error(t, err)
	})

	t.Run("frames from another recording with the same key", func(t *testing.T) {
		other := &db.Recording{ID: "rec2", WorkspaceID: rec.WorkspaceID, Key: rec.Key}
		storeFrames(t, s, other, frames)
		_, err := readAll(t, s, other)
		require.Error(t, err)
	})

	t.Run("another recording's key", func(t *testing.T) {
		storeFrames(t, s, rec, frames)
		wrongKey := &db.Recording{ID: rec.ID, WorkspaceID: rec.WorkspaceID, Key: NewKey()}
		_, err := readAll(t, s, wrongKey)
		require.Error(t, err)
	})
}
