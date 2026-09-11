// Package recording owns the session recording lifecycle: the encrypted
// on-disk format, secret scrubbing, storage-cap eviction, and retention
// deletion. Transport concerns (Connect handlers, proto mapping) stay in
// internal/api; this package never sees a request or response type.
package recording

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/storage"
)

// Limits is the entitlement view recording needs: how long a workspace
// keeps its recordings and how much recording storage it may hold.
// internal/entitlement.Service satisfies it.
type Limits interface {
	RetentionDays(ctx context.Context, workspaceID string) int64
	RecordingStorageBytes(ctx context.Context, workspaceID string) int64
}

// EventSink records background failures that have no request to surface them
// on. *audit.Service satisfies it.
type EventSink interface {
	Append(ctx context.Context, event *audit.Event) error
}

// Service owns recording storage operations. Safe for concurrent use.
type Service struct {
	conn   *db.Connection
	store  *storage.Storage
	limits Limits
	events EventSink
}

// Writer appends encrypted frames to one recording object.
// The writer commits on Close, so a died daemon still leaves a partial recording.
type Writer struct {
	w   io.WriteCloser
	svc *Service
}

func New(
	ctx context.Context,
	conn *db.Connection,
	store *storage.Storage,
	limits Limits,
	events EventSink,
) *Service {
	s := &Service{conn: conn, store: store, limits: limits, events: events}
	go s.runSweeper(ctx)
	return s
}

// NewWriter opens a recording object for writing.
func (s *Service) NewWriter(ctx context.Context, workspaceID, recordingID string) (*Writer, error) {
	w, err := s.store.CreateWriter(
		ctx,
		storage.RecordingPath(workspaceID, recordingID),
		storage.StoreOptions{ContentType: "application/octet-stream"},
	)
	if err != nil {
		return nil, fmt.Errorf("open recording object: %w", err)
	}
	return &Writer{w: w, svc: s}, nil
}

// WriteChunk encrypts one plaintext chunk and appends it as a frame.
func (w *Writer) WriteChunk(plaintext []byte) error {
	framed, err := w.svc.frameEncrypted(plaintext)
	if err != nil {
		return err
	}
	if _, err := w.w.Write(framed); err != nil {
		return fmt.Errorf("write recording object: %w", err)
	}
	return nil
}

// Close commits the object.
func (w *Writer) Close() error {
	return w.w.Close()
}

// frameEncrypted encrypts one plaintext chunk with the server's cipher and
// prefixes it with a 4-byte length so a stream of frames can be walked and
// decrypted independently on playback.
func (s *Service) frameEncrypted(plaintext []byte) ([]byte, error) {
	cipher, err := crypto.Encryptor()
	if err != nil {
		return nil, err
	}
	ct, err := cipher.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	if len(ct) > math.MaxUint32 {
		return nil, errors.New("recording chunk too large")
	}
	framed := make([]byte, 0, 4+len(ct))
	// #nosec G115 -- len(ct) is bounded by the MaxUint32 check above.
	framed = binary.BigEndian.AppendUint32(framed, uint32(len(ct)))
	return append(framed, ct...), nil
}
