package recording

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"

	"github.com/nokku-sh/nokku/core/internal/crypto"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/storage"
)

// A recording uses Tink's AES-GCM-HKDF streaming format, under a key of its own
// with its id and object id as associated data. Segments are authenticated and
// the last is marked, so a cut, a swap, an object from another recording or an
// older upload fails to read. The parameters are Tink's AES256_GCM_HKDF_4KB.
const (
	hkdfHash       = "SHA256"
	derivedKeySize = 32
	segmentSize    = 4096
)

var ErrNotStored = errors.New("nothing of this recording is stored yet")

// Writer commits on Close, so a dead daemon leaves a partial recording.
type Writer struct {
	enc io.WriteCloser
	obj io.WriteCloser
}

type Reader struct {
	io.Reader

	obj io.ReadCloser
}

// NewKey makes the key for one recording, stored on the row sealed to KeyAAD.
func NewKey() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}

// KeyAAD is where the key of a recording is sealed.
func KeyAAD(workspaceID, recordingID string) crypto.AAD {
	return crypto.AAD{Table: "recordings", Column: "key", Workspace: workspaceID, Row: recordingID}
}

// NewWriter gives one upload try its own object, the row names the largest try.
func (s *Service) NewWriter(ctx context.Context, rec *db.Recording, objectID string) (*Writer, error) {
	aead, err := s.streamingAEAD(rec)
	if err != nil {
		return nil, err
	}
	obj, err := s.store.CreateWriter(ctx, storage.RecordingPath(rec.WorkspaceID, objectID))
	if err != nil {
		return nil, fmt.Errorf("open recording object: %w", err)
	}
	// On an error the caller cancels ctx, which drops the object.
	enc, err := aead.NewEncryptingWriter(obj, objectAAD(rec.ID, objectID))
	if err != nil {
		return nil, fmt.Errorf("encrypt recording: %w", err)
	}
	return &Writer{enc: enc, obj: obj}, nil
}

func (s *Service) streamingAEAD(rec *db.Recording) (*subtle.AESGCMHKDF, error) {
	key, err := s.keys.Open(KeyAAD(rec.WorkspaceID, rec.ID), rec.Key)
	if err != nil {
		return nil, err
	}
	aead, err := subtle.NewAESGCMHKDF(key, hkdfHash, derivedKeySize, segmentSize, 0)
	if err != nil {
		return nil, fmt.Errorf("recording key: %w", err)
	}
	return aead, nil
}

func objectAAD(recordingID, objectID string) []byte {
	return []byte(recordingID + "/" + objectID)
}

func (w *Writer) WriteChunk(plaintext []byte) error {
	if _, err := w.enc.Write(plaintext); err != nil {
		return fmt.Errorf("write recording object: %w", err)
	}
	return nil
}

// Close seals the last segment, then commits. Tink leaves the object to us.
func (w *Writer) Close() error {
	return errors.Join(w.enc.Close(), w.obj.Close())
}

func (s *Service) OpenReader(ctx context.Context, rec *db.Recording) (*Reader, error) {
	if rec.ObjectID == nil {
		return nil, ErrNotStored
	}
	aead, err := s.streamingAEAD(rec)
	if err != nil {
		return nil, err
	}
	obj, err := s.store.Reader(ctx, storage.RecordingPath(rec.WorkspaceID, *rec.ObjectID))
	if err != nil {
		return nil, fmt.Errorf("open recording object: %w", err)
	}
	dec, err := aead.NewDecryptingReader(obj, objectAAD(rec.ID, *rec.ObjectID))
	if err != nil {
		_ = obj.Close()
		return nil, fmt.Errorf("decrypt recording: %w", err)
	}
	return &Reader{Reader: dec, obj: obj}, nil
}

func (r *Reader) Close() error {
	return r.obj.Close()
}
