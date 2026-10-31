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

	"connectrpc.com/connect/v2"
	"github.com/cenkalti/backoff/v7"
	"google.golang.org/protobuf/types/known/timestamppb"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

const (
	chunkSize = 32 << 10
	// Proxies close a stream idle for 60 s. An empty chunk, which the core skips, keeps a quiet session's open.
	keepAliveInterval = 30 * time.Second
	// The core takes a cut reason up to this long.
	maxCutReason = 200
	// A .part file nobody writes any more lost its writer before the recording closed.
	leftoverReason = "the daemon stopped before the recording was closed"
)

// Tests shorten them.
var (
	firstRetry = time.Second
	lastRetry  = 5 * time.Minute
	// A full workspace refuses every upload, and each one is a failed call in its audit log.
	retryWhenFull = time.Hour
)

// errUnreadable marks a file with no recording header to name it by. Trying again cannot help.
var errUnreadable = errors.New("no readable recording header")

// Uploads sends every recording to the core, always from its file. One goroutine per recording follows the file
// while its session writes it, tries again until the core holds all of it, and then deletes it.
type Uploads struct {
	// ctx ends the retries. An upload already under way runs on, Wait bounds it.
	ctx    context.Context
	client nokkuv1connect.DaemonControlServiceClient
	wg     sync.WaitGroup
}

// upload is one recording on its way to the core.
type upload struct {
	path string
	meta *nokkuv1.RecordingMeta
	// rec is the recorder that writes the file, nil for a file an earlier run left.
	rec *Recorder
	// f stays open while a recorder writes, so its rename never gets in the way of a read.
	f *os.File
}

// NewUploads also picks up the recordings an earlier run left. Call it before the first session starts, every file
// in the directory is a leftover then.
func NewUploads(ctx context.Context, client nokkuv1connect.DaemonControlServiceClient) *Uploads {
	u := &Uploads{ctx: ctx, client: client}
	entries, err := os.ReadDir(paths.RecordsDir())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("list recordings left to upload", "error", err)
	}
	for _, e := range entries {
		if !e.IsDir() && isRecording(e.Name()) {
			u.wg.Go(func() { u.run(&upload{path: filepath.Join(paths.RecordsDir(), e.Name())}) })
		}
	}
	return u
}

// Wait waits up to grace for the uploads under way. What is left stays on disk for the next start.
func (u *Uploads) Wait(grace time.Duration) bool {
	done := make(chan struct{})
	go func() {
		u.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(grace):
		return false
	}
}

// follow starts the upload of a recording New just made, with the header already in the file.
func (u *Uploads) follow(rec *Recorder) {
	f, err := os.Open(rec.path)
	if err != nil {
		slog.Warn("recording not uploaded live, the next start sends it", "path", rec.path, "error", err)
		return
	}
	up := &upload{path: rec.path, rec: rec, f: f, meta: rec.header.meta()}
	u.wg.Go(func() {
		defer f.Close()
		u.run(up)
	})
}

func (u *Uploads) run(up *upload) {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = firstRetry
	b.MaxInterval = lastRetry
	for failures := 0; ; failures++ {
		err := u.send(up)
		code := connect.CodeOf(err)
		switch {
		// AlreadyExists: an earlier try got the whole file through and its answer was lost.
		case err == nil, code == connect.CodeAlreadyExists && up.written():
			if up.rec != nil {
				up.path = up.rec.path
			}
			if err = os.Remove(up.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				slog.Warn("remove uploaded recording", "path", up.path, "error", err)
			}
			return
		case errors.Is(err, fs.ErrNotExist):
			// Retention dropped it.
			return
		case errors.Is(err, errUnreadable), code == connect.CodeInvalidArgument, code == connect.CodeAlreadyExists:
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

// written reports whether the file is final, its recorder is done with it.
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

// send streams the file from its first byte, the core keeps the larger copy. While the recorder writes, it waits at
// the end of the file for more. A nil error means the core holds all of it.
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

	// The last try of a session that ends at shutdown still has to get through. Wait bounds it.
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
		// While the session runs, the end of the file only means the recorder has not flushed more yet.
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
	if res.GetSizeBytes() < sent {
		return fmt.Errorf("the core holds %d of %d bytes", res.GetSizeBytes(), sent)
	}
	return nil
}

// final names the size the file has, when the session ended and why it was cut. The recorder knows all three, for a
// leftover the file tells.
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

// answer is why the core ended the stream. A failed Send only says that it did.
func answer(stream nokkuv1connect.DaemonControlServiceUploadRecordingClientStream, sendErr error) error {
	if _, err := stream.CloseAndReceive(); err != nil {
		return err
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

// readMeta reads the header the recorder wrote first. A file that has none wraps errUnreadable.
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
