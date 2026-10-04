package api

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/audit"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/config"
	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/storage"
)

type recordingService struct {
	cfg *config.Config
}

func newRecordingService(cfg *config.Config) *recordingService {
	return &recordingService{cfg: cfg}
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

	fr, err := s.cfg.Record.OpenReader(ctx, rec)
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
