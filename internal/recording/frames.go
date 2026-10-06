package recording

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/storage"
)

// A recording object is a run of frames:
//
//	kind(1) || len(4 BE) || nonce || ciphertext || tag
//
// Each recording has its own key. A frame is sealed with the recording id,
// its position and its kind as associated data, so frames cannot be moved
// between recordings or reordered. The object ends with an end frame, so a
// cut is not mistaken for a clean end.
const (
	frameData byte = 0
	frameEnd  byte = 1

	// maxRecordingFrame stops a corrupted object from forcing a huge allocation.
	maxRecordingFrame = 256 << 20
)

// NewKey makes the key for one recording. It is stored on the recording row,
// encrypted like every other secret.
func NewKey() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}

func frameAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("recording key: %w", err)
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func frameAAD(recordingID string, index uint64, kind byte) []byte {
	return binary.BigEndian.AppendUint64(append([]byte(recordingID), kind), index)
}

// Writer commits on Close, so a dead daemon still leaves a partial recording.
// A canceled ctx drops the object, an upload must not hand in the request's.
type Writer struct {
	w     io.WriteCloser
	aead  cipher.AEAD
	id    string
	index uint64
}

func (s *Service) NewWriter(ctx context.Context, rec *db.Recording) (*Writer, error) {
	aead, err := frameAEAD(rec.Key)
	if err != nil {
		return nil, err
	}
	w, err := s.store.CreateWriter(
		ctx,
		storage.RecordingPath(rec.WorkspaceID, rec.ID),
		storage.StoreOptions{ContentType: "application/octet-stream"},
	)
	if err != nil {
		return nil, fmt.Errorf("open recording object: %w", err)
	}
	return &Writer{w: w, aead: aead, id: rec.ID}, nil
}

func (w *Writer) WriteChunk(plaintext []byte) error {
	return w.writeFrame(frameData, plaintext)
}

func (w *Writer) Close() error {
	if err := w.writeFrame(frameEnd, nil); err != nil {
		_ = w.w.Close()
		return err
	}
	return w.w.Close()
}

func (w *Writer) writeFrame(kind byte, plaintext []byte) error {
	// #nosec G407 -- the AEAD draws a random nonce itself and takes none.
	sealed := w.aead.Seal(nil, nil, plaintext, frameAAD(w.id, w.index, kind))
	if len(sealed) > math.MaxUint32 {
		return errors.New("recording chunk too large")
	}
	// #nosec G115 -- len(sealed) is bounded by the MaxUint32 check above.
	frame := binary.BigEndian.AppendUint32([]byte{kind}, uint32(len(sealed)))
	if _, err := w.w.Write(append(frame, sealed...)); err != nil {
		return fmt.Errorf("write recording object: %w", err)
	}
	w.index++
	return nil
}

// Reader decrypts the frames into one plaintext stream.
type Reader struct {
	rc    io.ReadCloser
	aead  cipher.AEAD
	id    string
	index uint64
	ended bool

	header [5]byte
	buf    []byte
	off    int
}

func (s *Service) OpenReader(ctx context.Context, rec *db.Recording) (*Reader, error) {
	aead, err := frameAEAD(rec.Key)
	if err != nil {
		return nil, err
	}
	rc, err := s.store.Reader(ctx, storage.RecordingPath(rec.WorkspaceID, rec.ID))
	if err != nil {
		return nil, fmt.Errorf("open recording object: %w", err)
	}
	return &Reader{rc: rc, aead: aead, id: rec.ID}, nil
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
	if r.ended {
		return io.EOF
	}
	if _, err := io.ReadFull(r.rc, r.header[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("recording object has no end frame: %w", io.ErrUnexpectedEOF)
		}
		return err
	}
	kind := r.header[0]
	size := binary.BigEndian.Uint32(r.header[1:])
	if size > maxRecordingFrame {
		return fmt.Errorf("recording frame of %d bytes exceeds limit", size)
	}

	sealed := make([]byte, size)
	if _, err := io.ReadFull(r.rc, sealed); err != nil {
		// ReadFull reports a cut right after the header as a plain EOF.
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("recording frame %d is cut short: %w", r.index, io.ErrUnexpectedEOF)
		}
		return err
	}
	plain, err := r.aead.Open(nil, nil, sealed, frameAAD(r.id, r.index, kind))
	if err != nil {
		return fmt.Errorf("decrypt recording frame %d: %w", r.index, err)
	}
	r.index++
	if kind == frameEnd {
		r.ended = true
		return io.EOF
	}
	r.buf = plain
	r.off = 0
	return nil
}

func (r *Reader) Close() error {
	return r.rc.Close()
}
