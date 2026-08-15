package api

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/billing"
	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/meta"
	"github.com/nokku-sh/nokku/internal/storage"
)

// quotaCheckInterval bounds how often the storage quota is re-checked during
// one upload.
const quotaCheckInterval = 1 << 20 // 1 MiB

var (
	errNoRecordingKey    = errors.New("no recording key configured")
	errStaleRecordingKey = errors.New("stale recording key")
)

type RecordingService struct {
	cfg *config.Config
}

func NewRecordingService(cfg *config.Config) *RecordingService {
	return &RecordingService{cfg: cfg}
}

// UploadRecording receives a session recording streamed by a daemon. Chunks
// are opaque sealed ciphertext, the backend never inspects them. The stream
// is drained even when the storage cap is exceeded so the daemon is never
// blocked, the oldest recordings are evicted to make room, and a recording
// larger than the whole cap is still accepted.
func (s *RecordingService) UploadRecording(
	ctx context.Context,
	stream *connect.ClientStream[nokkuv1.UploadRecordingRequest],
) (*nokkuv1.UploadRecordingResponse, error) {
	daemonID := meta.DaemonIDFromContext(ctx)
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
			n, writeErr := w.Write(data)
			size += int64(n)
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
// returns the recording row to append chunks to. Uploads are only accepted
// when the workspace has a recording key, encryption is mandatory so a
// keyless workspace cannot receive recordings and daemons keep them local.
// A recording may resume only when its fingerprint matches the workspace's
// current key, after a key regeneration the daemon re-syncs and restarts.
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

		workspace, err := q.GetWorkspace(ctx, daemon.WorkspaceID)
		if err != nil {
			return err
		}
		expectedFP := workspace.Settings.GetRecordingKeyFingerprint()
		if expectedFP == "" {
			return errNoRecordingKey
		}
		if rm.GetKeyFingerprint() != expectedFP {
			return errStaleRecordingKey
		}

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
			ID:             rm.GetRecordingId(),
			WorkspaceID:    workspaceID,
			DaemonID:       daemonID,
			Username:       rm.GetUsername(),
			KeyFingerprint: rm.GetKeyFingerprint(),
		})
		return err
	}); err != nil {
		if errors.Is(err, errNoRecordingKey) {
			return nil, "", NewError(
				connect.CodeFailedPrecondition,
				"recording encryption is required: set a workspace recording key",
			)
		}
		if errors.Is(err, errStaleRecordingKey) {
			return nil, "", NewError(
				connect.CodeFailedPrecondition,
				"recording sealed with an outdated key, re-sync and retry",
			)
		}
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
			ID:             r.ID,
			WorkspaceID:    r.WorkspaceID,
			DaemonID:       r.DaemonID,
			Username:       r.Username,
			StartedAt:      r.StartedAt,
			EndedAt:        r.EndedAt,
			SizeBytes:      r.SizeBytes,
			KeyFingerprint: r.KeyFingerprint,
			Complete:       r.Complete,
			CreatedAt:      r.CreatedAt,
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
				RecordingId:    &rec.ID,
				Username:       &rec.Username,
				KeyFingerprint: &rec.KeyFingerprint,
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

	// Stream the object in slices so playback starts before the download
	// finishes and multi-hundred-MB sessions stay off the heap.
	buf := make([]byte, 256<<10)
	for {
		n, readErr := rc.Read(buf)
		if n > 0 {
			if err = stream.Send(&nokkuv1.GetRecordingResponse{
				Msg: &nokkuv1.GetRecordingResponse_Chunk{Chunk: buf[:n]},
			}); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			slog.Error("read recording object", "recording_id", rec.ID, "error", readErr)
			return ErrInternal
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

func (s *RecordingService) SetRecordingKey(
	ctx context.Context,
	req *nokkuv1.SetRecordingKeyRequest,
) (*nokkuv1.SetRecordingKeyResponse, error) {
	pub, err := crypto.ParseX25519PublicKey(req.GetPublicKey())
	if err != nil {
		return nil, NewError(connect.CodeInvalidArgument, err.Error())
	}
	fingerprint := crypto.PublicKeyFingerprint(pub)

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		base, err := q.GetWorkspace(ctx, req.GetWorkspaceId())
		if err != nil {
			return err
		}
		base.Settings.RecordingPublicKey = req.PublicKey
		base.Settings.RecordingKeyFingerprint = &fingerprint
		_, err = q.UpdateWorkspace(ctx, &db.UpdateWorkspaceParams{
			WorkspaceID: base.ID,
			Settings:    base.Settings,
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	if err := s.wipeRecordings(ctx, req.GetWorkspaceId()); err != nil {
		return nil, err
	}
	s.cfg.Pool.NotifyChange(req.GetWorkspaceId())

	return &nokkuv1.SetRecordingKeyResponse{}, nil
}

func (s *RecordingService) ClearRecordingKey(
	ctx context.Context,
	req *nokkuv1.ClearRecordingKeyRequest,
) (*nokkuv1.ClearRecordingKeyResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		base, err := q.GetWorkspace(ctx, req.GetWorkspaceId())
		if err != nil {
			return err
		}
		base.Settings.RecordingPublicKey = nil
		_, err = q.UpdateWorkspace(ctx, &db.UpdateWorkspaceParams{
			WorkspaceID: base.ID,
			Settings:    base.Settings,
		})
		return err
	}); err != nil {
		return nil, DBError(err)
	}

	if err := s.wipeRecordings(ctx, req.GetWorkspaceId()); err != nil {
		return nil, err
	}
	s.cfg.Pool.NotifyChange(req.GetWorkspaceId())

	return &nokkuv1.ClearRecordingKeyResponse{}, nil
}

func (s *RecordingService) wipeRecordings(ctx context.Context, workspaceID string) error {
	if err := s.cfg.Storage.DeletePrefix(ctx, storage.RecordingsPrefix(workspaceID)); err != nil {
		slog.Warn("wipe recording objects", "workspace_id", workspaceID, "error", err)
	}
	return s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteWorkspaceRecordings(ctx, workspaceID)
	})
}
