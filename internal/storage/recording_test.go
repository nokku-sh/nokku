package storage

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateWriterRoundtrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NOKKU_STORAGE", modeLocal)
	t.Setenv("NOKKU_LOCAL_STORAGE_PATH", dir)

	s, err := New(t.Context(), "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key := RecordingPath("ws-1", "00000000-0000-0000-0000-000000000001")
	w, err := s.CreateWriter(
		t.Context(),
		key,
		StoreOptions{ContentType: "application/octet-stream"},
	)
	if err != nil {
		t.Fatalf("CreateWriter: %v", err)
	}

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

	if _, err = w.Write(batch1); err != nil {
		t.Fatalf("write batch 1: %v", err)
	}
	if _, err = w.Write(batch2); err != nil {
		t.Fatalf("write batch 2: %v", err)
	}
	if _, err = w.Write(batch3); err != nil {
		t.Fatalf("write batch 3: %v", err)
	}
	if err = w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	// The object must be a single file containing the whole stream.
	if _, err = os.Stat(filepath.Join(dir, filepath.FromSlash(key))); err != nil {
		t.Fatalf("object file: %v", err)
	}

	rc, err := s.Reader(t.Context(), key)
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read object: %v", err)
	}
	if !bytes.Equal(got, gz.Bytes()) {
		t.Fatalf("object bytes mismatch: got %d bytes, want %d", len(got), gz.Len())
	}

	// Partial stream (daemon died) must still commit.
	key2 := RecordingPath("ws-1", "00000000-0000-0000-0000-000000000002")
	w2, err := s.CreateWriter(t.Context(), key2, StoreOptions{})
	if err != nil {
		t.Fatalf("CreateWriter 2: %v", err)
	}
	if _, err = w2.Write(batch1); err != nil {
		t.Fatalf("write partial: %v", err)
	}
	if err = w2.Close(); err != nil {
		t.Fatalf("close partial writer: %v", err)
	}
	if _, err = s.Reader(t.Context(), key2); err != nil {
		t.Fatalf("partial object unreadable: %v", err)
	}

	// Deletion removes the object.
	if err = s.Delete(t.Context(), key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err = os.Stat(filepath.Join(dir, filepath.FromSlash(key))); !os.IsNotExist(err) {
		t.Fatalf("object still present after delete (err=%v)", err)
	}
}

// A workspace purge must never reach another workspace's recordings, even one
// whose id shares a prefix.
func TestDeletePrefixStaysInsideWorkspace(t *testing.T) {
	t.Setenv("NOKKU_STORAGE", modeLocal)
	t.Setenv("NOKKU_LOCAL_STORAGE_PATH", t.TempDir())
	s, err := New(t.Context(), "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	gone := []string{RecordingPath("ws-1", "rec-a"), RecordingPath("ws-1", "rec-b")}
	kept := []string{RecordingPath("ws-10", "rec-c"), RecordingPath("ws-2", "rec-d"), AvatarPath("ws-1")}
	for _, key := range append(gone, kept...) {
		if _, err := s.Store(t.Context(), key, []byte("x"), StoreOptions{}); err != nil {
			t.Fatalf("Store %s: %v", key, err)
		}
	}

	if err := s.DeletePrefix(t.Context(), RecordingPrefix("ws-1")); err != nil {
		t.Fatalf("DeletePrefix: %v", err)
	}
	for _, key := range gone {
		if ok, _ := s.bucket.Exists(t.Context(), key); ok {
			t.Errorf("%s survived the purge", key)
		}
	}
	for _, key := range kept {
		if ok, _ := s.bucket.Exists(t.Context(), key); !ok {
			t.Errorf("%s was deleted by another workspace's purge", key)
		}
	}
	if err := s.DeletePrefix(t.Context(), "videos"); err == nil {
		t.Error("a prefix without a trailing slash must be refused")
	}
	if err := s.DeletePrefix(t.Context(), "/"); err == nil {
		t.Error("the bucket root must be refused")
	}
}
