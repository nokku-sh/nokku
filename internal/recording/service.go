// Package recording owns the recording lifecycle. It never sees a request or
// response type.
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

type Limits interface {
	RetentionDays(ctx context.Context, workspaceID string) int64
	RecordingStorageBytes(ctx context.Context, workspaceID string) int64
}

type EventSink interface {
	Append(ctx context.Context, event *audit.Event) error
}

type Service struct {
	conn   *db.Connection
	store  *storage.Storage
	limits Limits
	events EventSink
}

// Writer commits on Close, so a dead daemon still leaves a partial recording.
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

func (w *Writer) Close() error {
	return w.w.Close()
}

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
