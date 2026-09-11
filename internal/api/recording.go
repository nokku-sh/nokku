package api

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	nokkuv1 "github.com/nokku-sh/nokku/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokku/internal/iam"
	"github.com/nokku-sh/nokku/internal/storage"
)

const quotaCheckInterval = 1 << 20 // 1 MiB

type RecordingService struct {
	cfg *config.Config
}

func NewRecordingService(cfg *config.Config) *RecordingService {
	return &RecordingService{cfg: cfg}
}

func (s *RecordingService) UploadRecording(
	ctx context.Context,
	stream *connect.ClientStream[nokkuv1.UploadRecordingRequest],
) (*nokkuv1.UploadRecordingResponse, error) {
	daemonID := iam.DaemonIDFromContext(ctx)
	if daemonID == "" {
		return nil, NewError(connect.CodePermissionDenied, "only daemons can upload recordings")
	}

	if !stream.Receive() {
		return nil, NewError(connect.CodeInvalidArgument, "missing recording metadata")
	}
	meta := stream.Msg().GetMeta()
	if meta == nil || meta.GetRecordingId() == "" {
		return nil, NewError(connect.CodeInvalidArgument, "missing recording metadata")
	}

	rec, workspaceID, err := s.resolveUpload(ctx, daemonID, meta)
	if err != nil {
		return nil, err
	}

	w, err := s.cfg.Record.NewWriter(ctx, workspaceID, rec.ID)
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
				return nil, ErrInternal
			}
			size += int64(len(data))
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

	if complete {
		s.cfg.Record.ScrubRecording(rec)
	}

	return &nokkuv1.UploadRecordingResponse{
		RecordingId: &rec.ID,
		SizeBytes:   &size,
	}, nil
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
			if existing.Complete {
				return NewError(connect.CodeInvalidArgument, "recording is already finalized")
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
		recordings = append(recordings, r.Recording.ToProto())
	}
	s.logRecordingEvent(ctx, "recording.list", req.GetWorkspaceId(), "", "")
	return &nokkuv1.ListRecordingsResponse{
		Recordings: recordings,
		Total:      &total,
		TotalBytes: &totalBytes,
	}, nil
}

// logRecordingEvent records a recording read. The audit interceptor only
// covers mutating procedures, so reads that expose session content (which can
// contain credentials) emit their own rows. WithoutCancel keeps the row when
// the peer hangs up and the request context dies first.
func (s *RecordingService) logRecordingEvent(
	ctx context.Context,
	action, workspaceID, recordingID, daemonID string,
) {
	actor, _ := iam.PrincipalFromContext(ctx)
	appendAuditRow(ctx, s.cfg.Audit, action, workspaceID, actor,
		map[string]any{"recording_id": recordingID, "daemon_id": daemonID})
}

func (s *RecordingService) GetRecording(
	ctx context.Context,
	req *nokkuv1.GetRecordingRequest,
	stream *connect.ServerStream[nokkuv1.GetRecordingResponse],
) error {
	// Streaming RPCs get no tenant from the auth interceptor (streaming
	// requests have no single message to resolve one from; the stream
	// carries no message at all), so a global user principal's workspace must
	// be pinned here from the request. WithWorkspace then checks membership
	// and scopes row-level security.
	ctx = iam.AnnotateTenant(ctx, req.GetWorkspaceId())

	// Streaming RPCs bypass the unary permission interceptor, so the
	// ProcedurePermissions gate for this procedure is inert and must run here.
	if err := actorHasPermission(ctx, s.cfg.Conn, db.PermDaemonsView); err != nil {
		return DBError(err)
	}

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

	s.logRecordingEvent(ctx, "recording.download", req.GetWorkspaceId(), rec.ID, rec.DaemonID)

	fr, err := s.cfg.Record.OpenReader(ctx, req.GetWorkspaceId(), rec.ID)
	if err != nil {
		slog.Error("open recording object", "recording_id", rec.ID, "error", err)
		return ErrInternal
	}
	defer func() { _ = fr.Close() }()

	// Bounded 32 KiB sends keep memory flat on long sessions.
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
		return ErrInternal
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
	if err := s.cfg.Storage.Delete(
		ctx,
		storage.RecordingPath(req.GetWorkspaceId(), req.GetRecordingId()),
	); err != nil {
		slog.Warn("delete recording object", "recording_id", req.GetRecordingId(), "error", err)
	}
	return &nokkuv1.DeleteRecordingResponse{}, nil
}
