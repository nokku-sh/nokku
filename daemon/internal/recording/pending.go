package recording

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

const castSuffix = ".cast.gz"

// active holds the paths of recordings still being written or live uploaded.
var active sync.Map

// With uploaded copies gone, every file left in the records dir is active or pending.
func removeUploaded(path string) {
	if err := os.Remove(path); err != nil {
		slog.Warn("remove uploaded recording", "path", path, "error", err)
	}
}

// UploadPending stops at the first failure, the next call retries.
func UploadPending(ctx context.Context, client nokkuv1connect.DaemonControlServiceClient) error {
	// Filenames start with the timestamp, so Glob's order is oldest first.
	matches, err := filepath.Glob(filepath.Join(paths.RecordsDir(), "*"+castSuffix))
	if err != nil {
		return err
	}
	for _, path := range matches {
		if _, busy := active.Load(path); busy {
			continue
		}
		err = uploadFile(ctx, client, path)
		if connect.CodeOf(err) == connect.CodeInvalidArgument {
			// Already finalized, or a file the core will never take.
			slog.Warn("recording not accepted by the core, not retrying", "path", path, "error", err)
			err = nil
		}
		if err != nil {
			return fmt.Errorf("upload %s: %w", filepath.Base(path), err)
		}
		removeUploaded(path)
	}
	return nil
}

func uploadFile(ctx context.Context, client nokkuv1connect.DaemonControlServiceClient, path string) error {
	hdr, err := readHeader(path)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	f, err := os.Open(path) // #nosec G304 - a file from the recordings dir
	if err != nil {
		return err
	}
	defer f.Close()

	stream, err := client.UploadRecording(ctx)
	if err != nil {
		return err
	}
	send := func(req *nokkuv1.UploadRecordingRequest) error {
		if sendErr := stream.Send(req); sendErr != nil {
			_, recvErr := stream.CloseAndReceive()
			return errors.Join(sendErr, recvErr)
		}
		return nil
	}
	meta := &nokkuv1.RecordingMeta{RecordingId: &hdr.SessionID, Username: &hdr.User, Principal: &hdr.Principal}
	// The session is over, so the core is told when it began.
	if hdr.Timestamp > 0 {
		meta.StartedAt = timestamppb.New(time.Unix(hdr.Timestamp, 0))
	}
	if err = send(&nokkuv1.UploadRecordingRequest{Msg: &nokkuv1.UploadRecordingRequest_Meta{Meta: meta}}); err != nil {
		return err
	}
	buf := make([]byte, 32<<10)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if err = send(&nokkuv1.UploadRecordingRequest{
				Msg: &nokkuv1.UploadRecordingRequest_Chunk{Chunk: buf[:n]},
			}); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_, _ = stream.CloseAndReceive()
			return readErr
		}
	}
	if err = send(&nokkuv1.UploadRecordingRequest{
		Msg: &nokkuv1.UploadRecordingRequest_Final{Final: &nokkuv1.RecordingFinal{}},
	}); err != nil {
		return err
	}
	_, err = stream.CloseAndReceive()
	return err
}

func readHeader(path string) (header, error) {
	var hdr header
	f, err := os.Open(path) // #nosec G304 - a file from the recordings dir
	if err != nil {
		return hdr, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return hdr, err
	}
	line, err := bufio.NewReader(gz).ReadBytes('\n')
	if err != nil {
		return hdr, fmt.Errorf("read recording header: %w", err)
	}
	if err = json.Unmarshal(line, &hdr); err != nil {
		return hdr, fmt.Errorf("parse recording header: %w", err)
	}
	if hdr.SessionID == "" {
		return hdr, errors.New("recording header has no session id")
	}
	return hdr, nil
}
