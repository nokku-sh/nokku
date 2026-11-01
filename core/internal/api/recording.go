package api

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/audit"

	"connectrpc.com/connect/v2"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/core/internal/config"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/recording"
)

type recordingService struct {
	cfg *config.Config
}

func (s *recordingService) ListRecordings(
	ctx context.Context,
	req *nokkuv1.ListRecordingsRequest,
) (*nokkuv1.ListRecordingsResponse, error) {
	params := &db.ListRecordingsParams{
		Connected: s.cfg.Pool.ConnectedIn(actor.WorkspaceIDFromContext(ctx)),
		DaemonID:  req.DaemonId,
		Username:  req.Username,
		SubjectID: req.SubjectId,
		Limit:     req.Limit,
		Offset:    req.Offset,
	}

	var rows []*db.ListRecordingsRow
	var totalBytes int64
	if err := s.cfg.Conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		rows, err = q.ListRecordings(ctx, params)
		if err != nil {
			return err
		}
		totalBytes, err = q.SumRecordingBytes(ctx)
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
		rec := r.Recording.ToProto()
		rec.Live = &r.Live
		recordings = append(recordings, rec)
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
	stream nokkuv1connect.RecordingServiceGetRecordingServerStream,
) error {
	rec, err := s.cfg.Conn.Tenant().GetRecording(ctx, req.GetRecordingId())
	if err != nil {
		return err
	}

	// A playback leaves no other trace, so it starts once the log has it.
	if err := s.cfg.Audit.Confirm(ctx, &audit.Event{
		Action: "GetRecording", Target: rec.ID, Details: map[string]any{"daemon_id": rec.DaemonID},
	}); err != nil {
		return err
	}

	if err := stream.Send(&nokkuv1.GetRecordingResponse{
		Msg: &nokkuv1.GetRecordingResponse_Meta{
			Meta: &nokkuv1.RecordingMeta{
				RecordingId: &rec.ID,
				Username:    &rec.Username,
				Principal:   &rec.Principal,
			},
		},
	}); err != nil {
		return err
	}

	fr, err := s.cfg.Record.OpenReader(ctx, rec)
	if errors.Is(err, recording.ErrNotStored) {
		return connect.NewError(connect.CodeFailedPrecondition, err.Error())
	}
	if err != nil {
		return err
	}
	defer func() { _ = fr.Close() }()

	buf := make([]byte, 32<<10)
	for {
		// Tink reads one 4 KiB segment at a time, ReadFull fills the chunk.
		n, readErr := io.ReadFull(fr, buf)
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
		if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
			return nil
		}
		// What was sent verified, the rest was cut off or changed.
		slog.Error("read recording", "recording_id", rec.ID, "error", readErr)
		return connect.NewError(connect.CodeDataLoss, "the recording is damaged or was cut short, it ends here")
	}
}

func (s *recordingService) DeleteRecording(
	ctx context.Context,
	req *nokkuv1.DeleteRecordingRequest,
) (*nokkuv1.DeleteRecordingResponse, error) {
	// The delete queue takes the object, unreadable without the row's key.
	if _, err := s.cfg.Conn.Tenant().DeleteRecording(ctx, req.GetRecordingId()); err != nil {
		return nil, err
	}
	return &nokkuv1.DeleteRecordingResponse{}, nil
}
