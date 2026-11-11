package recording

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nokku-sh/nokku/daemon/internal/safe"

	"connectrpc.com/connect/v2"
	"github.com/cenkalti/backoff/v7"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

const (
	chunkSize = 32 << 10
	// Empty chunks, which the core skips, beat the 60 s proxy idle cut.
	keepAliveInterval = 30 * time.Second
	// The core takes a cut reason up to this long.
	maxCutReason   = 200
	leftoverReason = "the daemon stopped before the recording was closed"
)

// Tests shorten them.
var (
	firstRetry = time.Second
	lastRetry  = 5 * time.Minute
	// Each refused upload is a failed call in a full workspace's audit log.
	retryWhenFull = time.Hour
)

// No recording header to name the file by. Retrying cannot help.
var errUnreadable = errors.New("no readable recording header")

// Uploads runs one goroutine per recording. It follows the file while written,
// retries until the core holds all of it, then deletes it.
type Uploads struct {
	// ctx ends the retries. A running upload goes on, Wait bounds it.
	ctx    context.Context
	client nokkuv1connect.DaemonControlServiceClient
	wg     sync.WaitGroup
}

type upload struct {
	path string
	meta *nokkuv1.RecordingMeta
	// rec writes the file, nil for one an earlier run left.
	rec *Recorder
	// f stays open while rec writes, so its rename can't break a read.
	f *os.File
}

// NewUploads treats all files as leftovers. Call it before the first session.
func NewUploads(ctx context.Context, client nokkuv1connect.DaemonControlServiceClient) *Uploads {
	u := &Uploads{ctx: ctx, client: client}
	entries, err := os.ReadDir(paths.RecordsDir())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("list recordings left to upload", "error", err)
	}
	for _, e := range entries {
		if !e.IsDir() && isRecording(e.Name()) {
			u.wg.Go(safe.Func("recording upload", func() {
				u.run(&upload{path: filepath.Join(paths.RecordsDir(), e.Name())})
			}))
		}
	}
	return u
}

// Wait waits up to grace. What is left stays on disk for the next start.
func (u *Uploads) Wait(grace time.Duration) bool {
	done := make(chan struct{})
	go safe.Func("wait for uploads", func() {
		u.wg.Wait()
		close(done)
	})()
	select {
	case <-done:
		return true
	case <-time.After(grace):
		return false
	}
}

func (u *Uploads) follow(rec *Recorder) {
	f, err := os.Open(rec.path)
	if err != nil {
		slog.Warn("recording not uploaded live, the next start sends it", "path", rec.path, "error", err)
		return
	}
	up := &upload{path: rec.path, rec: rec, f: f, meta: rec.header.meta()}
	u.wg.Go(safe.Func("recording upload", func() {
		defer f.Close()
		u.run(up)
	}))
}

func (u *Uploads) run(up *upload) {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = firstRetry
	b.MaxInterval = lastRetry
	for failures := 0; ; failures++ {
		err := u.send(up)
		code := connect.CodeOf(err)
		switch {
		// Only the core's own answer deletes the file, no error code does.
		case err == nil && up.written():
			if up.rec != nil {
				up.path = up.rec.path
			}
			if err = os.Remove(up.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				slog.Warn("remove uploaded recording", "path", up.path, "error", err)
			}
			return
		case err == nil:
			// Complete, says the core, about a session that still writes.
			slog.Warn("recording not taken, it stays on disk", "path", up.path)
			return
		case errors.Is(err, fs.ErrNotExist):
			// Retention dropped it.
			return
		case errors.Is(err, errUnreadable), code == connect.CodeInvalidArgument:
			slog.Warn("recording not taken, it stays on disk", "path", up.path, "error", err)
			return
		}
		wait := b.NextBackOff()
		if code == connect.CodeResourceExhausted {
			wait = retryWhenFull
		}
		if failures == 0 {
			slog.Warn("recording upload failed, trying again", "path", up.path, "error", err, "retry_in", wait)
		} else {
			slog.Debug("recording upload failed", "path", up.path, "error", err, "retry_in", wait)
		}
		select {
		case <-u.ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (up *upload) written() bool {
	if up.rec == nil {
		return true
	}
	select {
	case <-up.rec.done:
		return true
	default:
		return false
	}
}

// Every try starts at byte 0, the core keeps the larger copy. No error means
// the core is done with the recording: it holds every byte, or calls it complete.
func (u *Uploads) send(up *upload) error {
	f := up.f
	if f == nil {
		var err error
		if f, err = os.Open(up.path); err != nil {
			return err
		}
		defer f.Close()
		if up.meta == nil {
			if up.meta, err = readMeta(f); err != nil {
				return err
			}
		}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// The last try at shutdown still has to get through. Wait bounds it.
	ctx, cancel := context.WithCancel(context.WithoutCancel(u.ctx))
	defer cancel()
	stream, err := u.client.UploadRecording(ctx)
	if err != nil {
		return err
	}
	if err = stream.Send(&nokkuv1.UploadRecordingRequest{
		Msg: &nokkuv1.UploadRecordingRequest_Meta{Meta: up.meta},
	}); err != nil {
		return answer(stream, err)
	}

	keepAlive := time.NewTicker(keepAliveInterval)
	defer keepAlive.Stop()
	live := up.rec != nil
	buf := make([]byte, chunkSize)
	var sent int64
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if err = stream.Send(&nokkuv1.UploadRecordingRequest{
				Msg: &nokkuv1.UploadRecordingRequest_Chunk{Chunk: buf[:n]},
			}); err != nil {
				return answer(stream, err)
			}
			sent += int64(n)
		}
		if readErr == nil {
			continue
		}
		if !errors.Is(readErr, io.EOF) {
			_, _ = stream.CloseAndReceive()
			return readErr
		}
		if !live {
			break
		}
		// EOF on a live file only means the recorder has not flushed more yet.
		select {
		case <-up.rec.flushed:
		case <-up.rec.done:
			live = false
		case <-keepAlive.C:
			if err = stream.Send(&nokkuv1.UploadRecordingRequest{
				Msg: &nokkuv1.UploadRecordingRequest_Chunk{},
			}); err != nil {
				return answer(stream, err)
			}
		}
	}

	if err = stream.Send(&nokkuv1.UploadRecordingRequest{
		Msg: &nokkuv1.UploadRecordingRequest_Final{Final: up.final(f)},
	}); err != nil {
		return answer(stream, err)
	}
	res, err := stream.CloseAndReceive()
	if err != nil {
		return err
	}
	if !res.GetComplete() && res.GetSizeBytes() < sent {
		return fmt.Errorf("the core holds %d of %d bytes", res.GetSizeBytes(), sent)
	}
	return nil
}

// The recorder knows size, end and cut reason. For a leftover the file tells.
func (up *upload) final(f *os.File) *nokkuv1.RecordingFinal {
	var size int64
	var reason string
	var ended time.Time
	if up.rec != nil {
		size, ended = up.rec.cw.written, up.rec.ended
		if up.rec.cut != nil {
			reason = up.rec.cut.Error()
		}
	} else {
		if info, err := f.Stat(); err == nil {
			size, ended = info.Size(), info.ModTime()
		}
		if strings.HasSuffix(up.path, partSuffix) {
			reason = leftoverReason
		}
	}
	if len(reason) > maxCutReason {
		reason = strings.ToValidUTF8(reason[:maxCutReason], "")
	}
	return &nokkuv1.RecordingFinal{SizeBytes: &size, CutReason: &reason, EndedAt: timestamppb.New(ended)}
}

// answer gets why the core ended the stream, a failed Send only says it did.
// A core that holds the whole recording answers before the file is sent.
func answer(stream nokkuv1connect.DaemonControlServiceUploadRecordingClientStream, sendErr error) error {
	res, err := stream.CloseAndReceive()
	if err != nil {
		return err
	}
	if res.GetComplete() {
		return nil
	}
	return sendErr
}

func (h header) meta() *nokkuv1.RecordingMeta {
	meta := &nokkuv1.RecordingMeta{RecordingId: &h.SessionID, Username: &h.User, Principal: &h.Principal}
	if h.Timestamp > 0 {
		meta.StartedAt = timestamppb.New(time.Unix(h.Timestamp, 0))
	}
	return meta
}

func readMeta(f *os.File) (*nokkuv1.RecordingMeta, error) {
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnreadable, err)
	}
	line, err := bufio.NewReader(gz).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnreadable, err)
	}
	var hdr header
	if err = json.Unmarshal(line, &hdr); err != nil {
		return nil, fmt.Errorf("%w: %w", errUnreadable, err)
	}
	if hdr.SessionID == "" {
		return nil, fmt.Errorf("%w: no session id", errUnreadable)
	}
	return hdr.meta(), nil
}
