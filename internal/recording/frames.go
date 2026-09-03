package recording

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/storage"
)

// maxRecordingFrame bounds a single stored frame so a corrupted object cannot
// force an unbounded allocation.
const maxRecordingFrame = 256 << 20

// Reader streams a recording object as decrypted plaintext: each
// [len(4 BE) || ciphertext] frame decrypts to one gzip slice, and reads
// walk the concatenated plaintext. Playback clients and the scrubber only
// append or scan the stream, so frame boundaries do not need to survive.
type Reader struct {
	rc     io.ReadCloser
	cipher crypto.Cipher

	lenBuf [4]byte
	buf    []byte
	off    int
}

// OpenReader opens a recording for decrypted streaming playback.
func (s *Service) OpenReader(
	ctx context.Context,
	workspaceID, recordingID string,
) (*Reader, error) {
	return s.openReader(ctx, storage.RecordingPath(workspaceID, recordingID))
}

func (s *Service) openReader(ctx context.Context, path string) (*Reader, error) {
	rc, err := s.store.Reader(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("open recording object: %w", err)
	}
	cipher, err := crypto.Encryptor()
	if err != nil {
		_ = rc.Close()
		return nil, fmt.Errorf("recording decryptor unavailable: %w", err)
	}
	return &Reader{rc: rc, cipher: cipher}, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	for r.off >= len(r.buf) {
		if err := r.nextFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

func (r *Reader) nextFrame() error {
	if _, err := io.ReadFull(r.rc, r.lenBuf[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(r.lenBuf[:])
	if size > maxRecordingFrame {
		return fmt.Errorf("recording frame of %d bytes exceeds limit", size)
	}

	ct := make([]byte, size)
	if _, err := io.ReadFull(r.rc, ct); err != nil {
		return err
	}
	plain, err := r.cipher.Decrypt(ct)
	if err != nil {
		return fmt.Errorf("decrypt recording frame: %w", err)
	}
	r.buf = plain
	r.off = 0
	return nil
}

func (r *Reader) Close() error {
	return r.rc.Close()
}
