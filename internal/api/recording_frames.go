package api

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/nokku-sh/nokku/internal/crypto"
)

// maxRecordingFrame bounds a single stored frame so a corrupted object cannot
// force an unbounded allocation.
const maxRecordingFrame = 256 << 20

// frameReader streams a framed recording object as its decrypted plaintext:
// each [len(4 BE) || ciphertext] frame decrypts to one gzip slice, and reads
// walk the concatenated plaintext. Playback clients and the scrubber only
// append or scan the stream, so frame boundaries do not need to survive.
type frameReader struct {
	rc     io.ReadCloser
	cipher crypto.Cipher

	lenBuf [4]byte
	buf    []byte
	off    int
}

// openFrameReader opens a recording object for framed, encrypted reading.
func (s *RecordingService) openFrameReader(ctx context.Context, path string) (*frameReader, error) {
	rc, err := s.cfg.Storage.Reader(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("open recording object: %w", err)
	}
	cipher, err := crypto.Encryptor()
	if err != nil {
		_ = rc.Close()
		return nil, fmt.Errorf("recording decryptor unavailable: %w", err)
	}
	return &frameReader{rc: rc, cipher: cipher}, nil
}

func (r *frameReader) Read(p []byte) (int, error) {
	if r.off >= len(r.buf) {
		if err := r.nextFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

// nextFrame decrypts the next frame into r.buf. [io.EOF] marks the end of
// the object; a truncated final frame surfaces as [io.ErrUnexpectedEOF].
func (r *frameReader) nextFrame() error {
	if _, err := io.ReadFull(r.rc, r.lenBuf[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		return fmt.Errorf("read recording frame length: %w", err)
	}
	length := binary.BigEndian.Uint32(r.lenBuf[:])
	if length > maxRecordingFrame {
		return fmt.Errorf("recording frame too large: %d", length)
	}
	ct := make([]byte, length)
	if _, err := io.ReadFull(r.rc, ct); err != nil {
		return fmt.Errorf("read recording frame body: %w", err)
	}
	plain, err := r.cipher.Decrypt(ct)
	if err != nil {
		return fmt.Errorf("decrypt recording chunk: %w", err)
	}
	r.buf = plain
	r.off = 0
	return nil
}

func (r *frameReader) Close() error {
	return r.rc.Close()
}
