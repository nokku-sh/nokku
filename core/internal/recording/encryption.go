package recording

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/storage"
)

// A recording is stored in Tink's AES-GCM-HKDF streaming format, under a key of its own and with its id as the
// associated data. Every segment is authenticated, the last one is marked as last, so a cut, a swap or an object
// from another recording fails to read. These are the parameters of Tink's AES256_GCM_HKDF_4KB template.
const (
	hkdfHash       = "SHA256"
	derivedKeySize = 32
	segmentSize    = 4096
)

// NewKey makes the key for one recording. It is stored on the row, encrypted like every other secret.
func NewKey() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}

func streamingAEAD(key []byte) (*subtle.AESGCMHKDF, error) {
	aead, err := subtle.NewAESGCMHKDF(key, hkdfHash, derivedKeySize, segmentSize, 0)
	if err != nil {
		return nil, fmt.Errorf("recording key: %w", err)
	}
	return aead, nil
}

// Writer commits on Close, so a dead daemon still leaves a partial recording. A canceled ctx drops the object.
type Writer struct {
	enc io.WriteCloser
	obj io.WriteCloser
}

func (s *Service) NewWriter(ctx context.Context, rec *db.Recording) (*Writer, error) {
	aead, err := streamingAEAD(rec.Key)
	if err != nil {
		return nil, err
	}
	obj, err := s.store.CreateWriter(ctx, storage.RecordingPath(rec.WorkspaceID, rec.ID))
	if err != nil {
		return nil, fmt.Errorf("open recording object: %w", err)
	}
	// On an error the caller cancels ctx, which drops the object instead of committing a header.
	enc, err := aead.NewEncryptingWriter(obj, []byte(rec.ID))
	if err != nil {
		return nil, fmt.Errorf("encrypt recording: %w", err)
	}
	return &Writer{enc: enc, obj: obj}, nil
}

func (w *Writer) WriteChunk(plaintext []byte) error {
	if _, err := w.enc.Write(plaintext); err != nil {
		return fmt.Errorf("write recording object: %w", err)
	}
	return nil
}

// Close seals the last segment, then commits the object. Tink leaves the object to its owner.
func (w *Writer) Close() error {
	return errors.Join(w.enc.Close(), w.obj.Close())
}

// Reader decrypts a recording into its plaintext stream.
type Reader struct {
	io.Reader

	obj io.ReadCloser
}

func (s *Service) OpenReader(ctx context.Context, rec *db.Recording) (*Reader, error) {
	aead, err := streamingAEAD(rec.Key)
	if err != nil {
		return nil, err
	}
	obj, err := s.store.Reader(ctx, storage.RecordingPath(rec.WorkspaceID, rec.ID))
	if err != nil {
		return nil, fmt.Errorf("open recording object: %w", err)
	}
	dec, err := aead.NewDecryptingReader(obj, []byte(rec.ID))
	if err != nil {
		_ = obj.Close()
		return nil, fmt.Errorf("decrypt recording: %w", err)
	}
	return &Reader{Reader: dec, obj: obj}, nil
}

func (r *Reader) Close() error {
	return r.obj.Close()
}
