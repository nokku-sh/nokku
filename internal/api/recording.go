package api

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/audit"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/storage"
)

const quotaCheckInterval = 1 << 20 // 1 MiB

type recordingService struct {
	cfg *config.Config
}

func newRecordingService(cfg *config.Config) *recordingService {
	return &recordingService{cfg: cfg}
}

func (s *recordingService) UploadRecording(
	ctx context.Context,
	stream *connect.ClientStream[nokkuv1.UploadRecordingRequest],
) (*nokkuv1.UploadRecordingResponse, error) {
	daemonID := actor.DaemonIDFromContext(ctx)
	if daemonID == "" {
		return nil, newError(connect.CodePermissionDenied, "only daemons can upload recordings")
	}

	if !stream.Receive() {
		return nil, newError(connect.CodeInvalidArgument, "missing recording metadata")
	}
	meta := stream.Msg().GetMeta()
	if meta == nil || meta.GetRecordingId() == "" {
		return nil, newError(connect.CodeInvalidArgument, "missing recording metadata")
	}

	rec, workspaceID, err := s.resolveUpload(ctx, daemonID, meta)
	if err != nil {
		return nil, err
	}

	w, err := s.cfg.Record.NewWriter(ctx, workspaceID, rec.ID)
	if err != nil {
		slog.Error("open recording object", "recording_id", rec.ID, "error", err)
		return nil, errInternal
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
			// Evict the oldest recordings instead of blocking the stream.
			if size-lastChecked >= quotaCheckInterval {
				lastChecked = size
				if err := s.cfg.Record.EvictForBytes(ctx, workspaceID, rec.ID, size); err != nil {
					slog.Warn(
						"recording eviction sweep failed",
						"workspace_id", workspaceID,
						"recording_id", rec.ID,
						"error", err,
					)
				}
			}
			if err := w.WriteChunk(data); err != nil {
				_ = w.Close()
				slog.Error("write recording chunk", "recording_id", rec.ID, "error", err)
				return nil, errInternal
			}
			size += int64(len(data))
		case *nokkuv1.UploadRecordingRequest_Final:
			complete = true
		}
	}
	if err = stream.Err(); err != nil && !errors.Is(err, io.EOF) {
		_ = w.Close()
		return nil, newError(connect.CodeUnknown, "recording stream interrupted")
	}
	if err = w.Close(); err != nil {
		slog.Error("commit recording object", "recording_id", rec.ID, "error", err)
		return nil, errInternal
	}

	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		rec, err = q.SetRecordingComplete(ctx, &db.SetRecordingCompleteParams{
			ID:        rec.ID,
			SizeBytes: size,
			Complete:  complete,
		})
		return err
	}); err != nil {
		return nil, err
	}

	if complete {
		s.cfg.Record.ScrubRecording(rec)
	}

	return &nokkuv1.UploadRecordingResponse{
		RecordingId: &rec.ID,
		SizeBytes:   &size,
	}, nil
}

// resolveUpload resumes the recording when the daemon uploads its id again.
func (s *recordingService) resolveUpload(
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
			if existing.Complete {
				return newError(connect.CodeInvalidArgument, "recording is already finalized")
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
		return nil, "", err
	}
	return rec, workspaceID, nil
}

func (s *recordingService) ListRecordings(
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
		return nil, err
	}

	recordings := make([]*nokkuv1.Recording, 0, len(rows))
	var total int32
	for _, r := range rows {
		if total == 0 {
			total = r.TotalCount
		}
		recordings = append(recordings, r.Recording.ToProto())
	}
	return &nokkuv1.ListRecordingsResponse{
		Recordings: recordings,
		Total:      &total,
		TotalBytes: &totalBytes,
	}, nil
}

func (s *recordingService) GetRecording(
	ctx context.Context,
	req *nokkuv1.GetRecordingRequest,
	stream *connect.ServerStream[nokkuv1.GetRecordingResponse],
) error {
	// Streams get no workspace from the interceptors, so pin and check here.
	ctx = actor.AnnotateTenant(ctx, req.GetWorkspaceId())
	ctx, err := actorHasRole(ctx, s.cfg.Conn, db.RoleViewer)
	if err != nil {
		return err
	}

	var rec *db.Recording
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) (err error) {
		rec, err = q.GetRecording(ctx, req.GetRecordingId())
		return err
	}); err != nil {
		return err
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

	s.cfg.Audit.Log(ctx, &audit.Event{
		Action: "GetRecording", Target: rec.ID, Details: map[string]any{"daemon_id": rec.DaemonID},
	})

	fr, err := s.cfg.Record.OpenReader(ctx, req.GetWorkspaceId(), rec.ID)
	if err != nil {
		slog.Error("open recording object", "recording_id", rec.ID, "error", err)
		return errInternal
	}
	defer func() { _ = fr.Close() }()

	buf := make([]byte, 32<<10)
	for {
		n, readErr := fr.Read(buf)
		if n > 0 {
			if err = stream.Send(&nokkuv1.GetRecordingResponse{
				Msg: &nokkuv1.GetRecordingResponse_Chunk{Chunk: buf[:n]},
			}); err != nil {
				return err
			}
		}
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		slog.Error("read recording frame", "recording_id", rec.ID, "error", readErr)
		return errInternal
	}
}

func (s *recordingService) DeleteRecording(
	ctx context.Context,
	req *nokkuv1.DeleteRecordingRequest,
) (*nokkuv1.DeleteRecordingResponse, error) {
	if err := s.cfg.Conn.WithWorkspace(ctx, func(q *db.Queries) error {
		return q.DeleteRecording(ctx, req.GetRecordingId())
	}); err != nil {
		return nil, err
	}
	// Best effort, a stray object goes with the workspace purge.
	if err := s.cfg.Storage.Delete(
		ctx,
		storage.RecordingPath(req.GetWorkspaceId(), req.GetRecordingId()),
	); err != nil {
		slog.Warn("delete recording object", "recording_id", req.GetRecordingId(), "error", err)
	}
	return &nokkuv1.DeleteRecordingResponse{}, nil
}
