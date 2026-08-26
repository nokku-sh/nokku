package api

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/mizuchilabs/kagi"

	"github.com/nokku-sh/nokku/internal/auth"
	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/storage"
)

// quotaCheckInterval bounds how often the storage quota is re-checked during
// one upload.
const quotaCheckInterval = 1 << 20 // 1 MiB

// maxRecordingFrame bounds a single stored frame so a corrupted object cannot
// force an unbounded allocation on playback.
const maxRecordingFrame = 256 << 20

type RecordingService struct {
	cfg *config.Config
}

func NewRecordingService(cfg *config.Config) *RecordingService {
	return &RecordingService{cfg: cfg}
}

// frameEncrypted encrypts one plaintext chunk with the server's cipher and
// prefixes it with a 4-byte length so a stream of frames can be walked and
// decrypted independently on playback.
func (s *RecordingService) frameEncrypted(plaintext []byte) ([]byte, error) {
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

// UploadRecording receives a session recording streamed by a daemon. Chunks
// are plaintext gzip slices; the backend encrypts each at rest with its own
// key so the object store never holds plaintext. The stream is drained even
// when the storage cap is exceeded so the daemon is never blocked, the
// oldest recordings are evicted to make room, and a recording larger than the
// whole cap is still accepted.
func (s *RecordingService) UploadRecording(
	ctx context.Context,
	stream *connect.ClientStream[nokkuv1.UploadRecordingRequest],
) (*nokkuv1.UploadRecordingResponse, error) {
	daemonID := auth.DaemonIDFromContext(ctx)
	if daemonID == "" {
		return nil, NewError(connect.CodePermissionDenied, "only daemons can upload recordings")
	}

	if !stream.Receive() {
		return nil, NewError(connect.CodeInvalidArgument, "missing recording metadata")
	}
	rm := stream.Msg().GetMeta()
	if rm == nil || rm.GetRecordingId() == "" {
		return nil, NewError(connect.CodeInvalidArgument, "missing recording metadata")
	}

	rec, workspaceID, err := s.resolveUpload(ctx, daemonID, rm)
	if err != nil {
		return nil, err
	}

	// Stream the session into a single object. The writer commits on Close
	// so a died daemon still leaves a partial recording.
	w, err := s.cfg.Storage.CreateWriter(
		ctx,
		storage.RecordingPath(workspaceID, rec.ID),
		storage.StoreOptions{ContentType: "application/octet-stream"},
	)
	if err != nil {
		slog.Error("open recording object", "recording_id", rec.ID, "error", err)
		return nil, ErrInternal
	}

	var size int64
	var complete bool
	lastChecked := int64(0)
	for stream.Receive() {
		switch m := stream.Msg().GetMsg().(type) {
		case *nokkuv1.UploadRecordingRequest_Chunk:
			data := m.Chunk
			if len(data) == 0 {
				continue
			}
			// Sweep past recordings so the workspace stays within its cap.
			// Never blocks the stream, the oldest recordings are evicted.
			if size-lastChecked >= quotaCheckInterval {
				lastChecked = size
				if err := s.evictForBytes(ctx, workspaceID, rec.ID, size); err != nil {
					slog.Warn(
						"recording eviction sweep failed",
						"workspace_id", workspaceID,
						"recording_id", rec.ID,
						"error", err,
					)
				}
			}
			framed, encErr := s.frameEncrypted(data)
			if encErr != nil {
				_ = w.Close()
				slog.Error("encrypt recording chunk", "recording_id", rec.ID, "error", encErr)
				return nil, ErrInternal
			}
			_, writeErr := w.Write(framed)
			size += int64(len(data))
			if writeErr != nil {
				_ = w.Close()
				slog.Error("write recording object", "recording_id", rec.ID, "error", writeErr)
				return nil, ErrInternal
			}
		case *nokkuv1.UploadRecordingRequest_Final:
			complete = true
		}
	}
	if err = stream.Err(); err != nil && !errors.Is(err, io.EOF) {
		_ = w.Close()
		return nil, NewError(connect.CodeUnknown, "recording stream interrupted")
	}
	if err = w.Close(); err != nil {
		slog.Error("commit recording object", "recording_id", rec.ID, "error", err)
		return nil, ErrInternal
	}

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		var err error
		rec, err = q.SetRecordingComplete(ctx, &db.SetRecordingCompleteParams{
			ID:        rec.ID,
			SizeBytes: size,
			Complete:  complete,
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	return &nokkuv1.UploadRecordingResponse{
		RecordingId: &rec.ID,
		SizeBytes:   &size,
	}, nil
}

// evictForBytes keeps a workspace within its recording storage cap by
// deleting the oldest recordings (rows and objects) until the workspace
// fits, counting `inFlight` bytes for the upload in progress. The in-flight
// recording itself is never evicted. An overage that cannot be cleared (a
// single recording larger than the whole cap) is simply accepted.
func (s *RecordingService) evictForBytes(
	ctx context.Context,
	workspaceID, recordingID string,
	inFlight int64,
) error {
	over, err := s.cfg.Billing.OverBytes(ctx, workspaceID, billing.ResourceRecordings, inFlight)
	if err != nil {
		return err
	}
	for over > 0 {
		var victims []*db.Recording
		if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
			victims, err = q.OldestRecordings(ctx, &db.OldestRecordingsParams{
				WorkspaceID: workspaceID,
				Limit:       &[]int32{100}[0],
			})
			return err
		}); err != nil {
			return err
		}
		var freed int64
		for _, v := range victims {
			if v.ID == recordingID {
				continue
			}
			if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
				return q.DeleteRecording(ctx, v.ID)
			}); err != nil {
				return err
			}
			// The object is best-effort: a stray object without a row is
			// invisible and swept by the workspace wipe.
			if err := s.cfg.Storage.Delete(
				ctx,
				storage.RecordingPath(workspaceID, v.ID),
			); err != nil {
				slog.Warn("delete evicted recording object", "recording_id", v.ID, "error", err)
			}
			freed += v.SizeBytes
			slog.Info(
				"evicted recording over storage cap",
				"recording_id",
				v.ID,
				"size",
				v.SizeBytes,
			)
		}
		if freed == 0 {
			return nil
		}
		over -= freed
	}
	return nil
}

// resolveUpload validates the metadata against the daemon's workspace and
// returns the recording row to append chunks to. Uploads are always accepted:
// the backend encrypts the stream at rest, so a daemon needs no workspace key.
// A recording may resume when the daemon uploads its id again.
func (s *RecordingService) resolveUpload(
	ctx context.Context,
	daemonID string,
	rm *nokkuv1.RecordingMeta,
) (*db.Recording, string, error) {
	var rec *db.Recording
	var workspaceID string
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		daemon, err := q.GetDaemon(ctx, daemonID)
		if err != nil {
			return err
		}
		workspaceID = daemon.WorkspaceID

		existing, err := q.GetRecording(ctx, rm.GetRecordingId())
		if err == nil {
			if existing.DaemonID != daemonID {
				return errors.New("recording belongs to another daemon")
			}
			rec = existing
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		rec, err = q.CreateRecording(ctx, &db.CreateRecordingParams{
			ID:          rm.GetRecordingId(),
			WorkspaceID: workspaceID,
			DaemonID:    daemonID,
			Username:    rm.GetUsername(),
		})
		return err
	}); err != nil {
		return nil, "", DBError(err)
	}
	return rec, workspaceID, nil
}

func (s *RecordingService) ListRecordings(
	ctx context.Context,
	req *nokkuv1.ListRecordingsRequest,
) (*nokkuv1.ListRecordingsResponse, error) {
	params := &db.ListRecordingsParams{
		WorkspaceID: req.GetWorkspaceId(),
		DaemonID:    req.DaemonId,
		Username:    req.Username,
		Limit:       req.Limit,
		Offset:      req.Offset,
	}

	var rows []*db.ListRecordingsRow
	var totalBytes int64
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		rows, err = q.ListRecordings(ctx, params)
		if err != nil {
			return err
		}
		totalBytes, err = q.SumRecordingBytes(ctx, req.GetWorkspaceId())
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	recordings := make([]*nokkuv1.Recording, 0, len(rows))
	var total int32
	for _, r := range rows {
		if total == 0 {
			total = r.TotalCount
		}
		recordings = append(recordings, (&db.Recording{
			ID:          r.ID,
			WorkspaceID: r.WorkspaceID,
			DaemonID:    r.DaemonID,
			Username:    r.Username,
			StartedAt:   r.StartedAt,
			EndedAt:     r.EndedAt,
			SizeBytes:   r.SizeBytes,
			Complete:    r.Complete,
			CreatedAt:   r.CreatedAt,
		}).ToProto())
	}
	return &nokkuv1.ListRecordingsResponse{
		Recordings: recordings,
		Total:      &total,
		TotalBytes: &totalBytes,
	}, nil
}

func (s *RecordingService) GetRecording(
	ctx context.Context,
	req *nokkuv1.GetRecordingRequest,
	stream *connect.ServerStream[nokkuv1.GetRecordingResponse],
) error {
	// Streaming RPCs get no tenant from the auth interceptor (kagi passes a
	// nil message at auth time), so a global user principal's workspace must
	// be pinned here from the request. WithWorkspace then checks membership
	// and scopes row-level security.
	kagi.AnnotateTenant(ctx, kagi.TenantID(req.GetWorkspaceId()))

	var rec *db.Recording
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		rec, err = q.GetRecording(ctx, req.GetRecordingId())
		return err
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return DBError(err)
	}

	if err := stream.Send(&nokkuv1.GetRecordingResponse{
		Msg: &nokkuv1.GetRecordingResponse_Meta{
			Meta: &nokkuv1.RecordingMeta{
				RecordingId: &rec.ID,
				Username:    &rec.Username,
			},
		},
	}); err != nil {
		return err
	}

	rc, err := s.cfg.Storage.Reader(ctx, storage.RecordingPath(req.GetWorkspaceId(), rec.ID))
	if err != nil {
		slog.Error("open recording object", "recording_id", rec.ID, "error", err)
		return ErrInternal
	}
	defer func() { _ = rc.Close() }()

	cipher, err := crypto.Encryptor()
	if err != nil {
		slog.Error("recording decryptor unavailable", "recording_id", rec.ID, "error", err)
		return ErrInternal
	}

	// The object is a stream of [len(4 BE) || ciphertext] frames, each
	// decrypting to one plaintext gzip slice. Reading frame-by-frame keeps
	// playback streaming and multi-hundred-MB sessions off the heap.
	var lenBuf [4]byte
	for {
		if _, err = io.ReadFull(rc, lenBuf[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			slog.Error("read recording frame", "recording_id", rec.ID, "error", err)
			return ErrInternal
		}
		length := binary.BigEndian.Uint32(lenBuf[:])
		if length > maxRecordingFrame {
			slog.Error("recording frame too large", "recording_id", rec.ID, "size", length)
			return ErrInternal
		}
		ct := make([]byte, length)
		if _, err = io.ReadFull(rc, ct); err != nil {
			slog.Error("read recording frame body", "recording_id", rec.ID, "error", err)
			return ErrInternal
		}
		plain, decryptErr := cipher.Decrypt(ct)
		if decryptErr != nil {
			slog.Error("decrypt recording chunk", "recording_id", rec.ID, "error", decryptErr)
			return ErrInternal
		}
		if err = stream.Send(&nokkuv1.GetRecordingResponse{
			Msg: &nokkuv1.GetRecordingResponse_Chunk{Chunk: plain},
		}); err != nil {
			return err
		}
	}
}

func (s *RecordingService) DeleteRecording(
	ctx context.Context,
	req *nokkuv1.DeleteRecordingRequest,
) (*nokkuv1.DeleteRecordingResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteRecording(ctx, req.GetRecordingId())
	}); err != nil {
		return nil, DBError(err)
	}
	// The object is best-effort: a stray object without a row is invisible
	// and swept by the workspace wipe. Rows are gone first so listings are
	// right.
	path := storage.RecordingPath(req.GetWorkspaceId(), req.GetRecordingId())
	if err := s.cfg.Storage.Delete(ctx, path); err != nil {
		slog.Warn("delete recording object", "recording_id", req.GetRecordingId(), "error", err)
	}
	return &nokkuv1.DeleteRecordingResponse{}, nil
}
