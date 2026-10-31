package recording

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

const (
	// Recording stops at this compressed size and calls OnCut.
	maxSize     = 50 << 20
	maxIdleTime = 2 * time.Second
	// A crash loses at most this much of the tail of a recording. Every flush ends a gzip block, so a shorter one costs
	// a shell recording twice the size and a progress bar eight times.
	maxFlushInterval = time.Second

	// A recording is written to <id>.part. Only one that closed whole is renamed to <id>.cast.gz.
	partSuffix = ".part"
	castSuffix = ".cast.gz"
)

// ErrSizeLimit is why a recording that reached its size limit stopped.
var ErrSizeLimit = errors.New("size limit reached")

type header struct {
	Version   int    `json:"version"`
	Term      term   `json:"term"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Title     string `json:"title,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	User      string `json:"user,omitempty"`
	Principal string `json:"principal,omitempty"`
}

type term struct {
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
	Type string `json:"type,omitempty"`
}

type Options struct {
	Width  int
	Height int
	Title  string
	// SessionID names the file and the recording in the core. It has to be a canonical UUID.
	SessionID string
	User      string // the local account
	Principal string // the certificate principal auth matched, names who was logged in
	Term      string
	// OnCut runs once when the recording stops before its session, with ErrSizeLimit or the write error.
	OnCut func(error)
	// MaxSize defaults to 50 MB. Tests shrink it.
	MaxSize int64
	// Uploads sends the recording to the core while it is written. Nil leaves it on disk.
	Uploads *Uploads
}

type Recorder struct {
	mu        sync.Mutex
	path      string
	header    header
	onCut     func(error)
	maxSize   int64
	cw        *countingWriter
	gw        *gzip.Writer
	lastEvent time.Time
	// msCarry carries the rounding error to the next interval, so the written intervals sum to the real time.
	msCarry float64
	// partial holds, per event type, the head of a multi-byte character the last event ended in.
	partial map[string][]byte
	// exitCode is written last, so the x event stays the final event.
	exitCode *int
	dirty    bool
	// broken is set by a failed write, the gzip stream is cut there.
	broken bool
	closed bool
	// cut is why the recording stopped early, nil for a whole one. Final once done is closed.
	cut error
	// ended is when it stopped. Final once done is closed.
	ended time.Time

	// flushed wakes the upload when more of the file is on disk. done closes once the file is final.
	flushed chan struct{}
	done    chan struct{}
}

type countingWriter struct {
	w       *os.File
	written int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.written += int64(n)
	return n, err
}

// New may return a nil Recorder, which is a valid no-op, so callers can keep going after an error.
func New(opts Options) (*Recorder, error) {
	if !login.ValidID(opts.SessionID) {
		return nil, fmt.Errorf("recording id %q is no canonical UUID", opts.SessionID)
	}
	if err := checkDiskSpace(paths.RecordsDir()); err != nil {
		return nil, err
	}
	if err := enforceRetention(); err != nil {
		return nil, err
	}

	// A second session under the same id must not write into the first one's file, nor replace it at the rename.
	path := filepath.Join(paths.RecordsDir(), opts.SessionID+partSuffix)
	if _, err := os.Lstat(strings.TrimSuffix(path, partSuffix) + castSuffix); err == nil {
		return nil, fmt.Errorf("a recording %s waits for its upload already", opts.SessionID)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 - the id is a UUID
	if err != nil {
		return nil, fmt.Errorf("create recording file: %w", err)
	}
	// The lock tells retention a session still writes the file. It ends with the descriptor, in a crash too.
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("lock recording file: %w", err)
	}

	now := time.Now()
	hdr := header{
		Version:   3,
		Term:      term{Cols: opts.Width, Rows: opts.Height, Type: cmp.Or(opts.Term, "xterm-256color")},
		Timestamp: now.Unix(),
		Title:     opts.Title,
		SessionID: opts.SessionID,
		User:      opts.User,
		Principal: opts.Principal,
	}
	cw := &countingWriter{w: f}
	gw := gzip.NewWriter(cw)
	enc := json.NewEncoder(gw)
	enc.SetEscapeHTML(false)
	if err = enc.Encode(hdr); err == nil {
		err = gw.Flush()
	}
	if err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write header: %w", err)
	}

	rec := &Recorder{
		path:      path,
		header:    hdr,
		onCut:     opts.OnCut,
		maxSize:   cmp.Or(opts.MaxSize, maxSize),
		cw:        cw,
		gw:        gw,
		lastEvent: now,
		partial:   map[string][]byte{},
		flushed:   make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	if opts.Uploads != nil {
		opts.Uploads.follow(rec)
	}
	go rec.flushLoop()
	return rec, nil
}

func (r *Recorder) flushLoop() {
	ticker := time.NewTicker(maxFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
		case <-r.done:
			return
		}
		r.mu.Lock()
		var cut error
		if !r.closed && r.dirty {
			r.dirty = false
			if err := r.gw.Flush(); err != nil {
				r.broken = true
				cut = fmt.Errorf("write failed: %w", err)
				r.closeLocked(cut)
			} else {
				select {
				case r.flushed <- struct{}{}:
				default:
				}
			}
		}
		r.mu.Unlock()
		r.report(cut)
	}
}

func (r *Recorder) event(eventType string, data []byte) {
	if r == nil {
		return
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	cut := ErrSizeLimit
	if r.cw.written < r.maxSize {
		// A read can end inside a multi-byte character. Its head waits for the next event of its type.
		if head := r.partial[eventType]; len(head) > 0 {
			data = append(head, data...)
		}
		end := len(data) - incompleteTail(data)
		r.partial[eventType] = bytes.Clone(data[end:])
		cut = r.emit(eventType, data[:end])
	}
	if cut != nil {
		r.closeLocked(cut)
	}
	r.mu.Unlock()
	r.report(cut)
}

// report runs OnCut outside the lock, it may end the session and so close the recorder.
func (r *Recorder) report(cut error) {
	if cut == nil {
		return
	}
	slog.Warn("recording stopped early", "path", filepath.Base(r.path), "reason", cut)
	if r.onCut != nil {
		r.onCut(cut)
	}
}

// Caller holds r.mu and has checked not closed. A failed write cuts the gzip stream, so it ends the recording.
func (r *Recorder) emit(eventType string, data []byte) error {
	// asciicast v3 timestamps are intervals. Gaps over maxIdleTime are clamped so playback skips idle time.
	now := time.Now()
	gap := min(now.Sub(r.lastEvent), maxIdleTime)
	r.lastEvent = now

	encodedData := marshalEventData(string(data))

	line := fmt.Sprintf("[%s, %q, %s]\n", r.roundInterval(gap), eventType, encodedData)

	r.dirty = true
	if _, err := r.gw.Write([]byte(line)); err != nil {
		r.broken = true
		return fmt.Errorf("write failed: %w", err)
	}
	return nil
}

// Length of the multi-byte character p ends in the middle of, 0 on a character boundary.
func incompleteTail(p []byte) int {
	for i := 1; i < utf8.UTFMax && i <= len(p); i++ {
		if tail := p[len(p)-i:]; utf8.RuneStart(tail[0]) {
			if utf8.FullRune(tail) {
				return 0
			}
			return i
		}
	}
	return 0
}

// No HTML escaping, so terminal output stays readable in the raw cast.
func marshalEventData(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return []byte(`""`)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

func (r *Recorder) roundInterval(gap time.Duration) string {
	r.msCarry += gap.Seconds() * 1000
	ms := int64(math.Round(r.msCarry))
	r.msCarry -= float64(ms)
	return fmt.Sprintf("%d.%03d", ms/1000, ms%1000)
}

func (r *Recorder) RecordOutput(data []byte) {
	r.event("o", data)
}

func (r *Recorder) RecordInput(data []byte) {
	r.event("i", data)
}

func (r *Recorder) RecordResize(width, height int) {
	r.event("r", fmt.Appendf(nil, "%dx%d", width, height))
}

func (r *Recorder) RecordExit(status int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.exitCode = new(status)
}

// closeLocked makes the file final. Only a recording nothing cut is synced and renamed to its whole name, so a
// .part file is always a cut one once its writer is gone.
func (r *Recorder) closeLocked(cut error) {
	if r.closed {
		return
	}
	r.closed = true

	// After a failed write the gzip stream is cut there, nothing more goes in.
	if !r.broken {
		// A character the stream never completed is recorded as it stands.
		for _, eventType := range []string{"o", "i"} {
			if tail := r.partial[eventType]; len(tail) > 0 {
				cut = cmp.Or(cut, r.emit(eventType, tail))
			}
		}
		if cut == nil && r.exitCode != nil {
			cut = r.emit("x", []byte(strconv.Itoa(*r.exitCode)))
		}
	}
	// gw.Close writes the gzip footer. A whole recording is synced before its name says so.
	err := r.gw.Close()
	if err == nil && cut == nil {
		err = r.cw.w.Sync()
	}
	if err = errors.Join(err, r.cw.w.Close()); err != nil {
		cut = cmp.Or(cut, fmt.Errorf("write failed: %w", err))
	}
	if cut == nil {
		whole := strings.TrimSuffix(r.path, partSuffix) + castSuffix
		if err = os.Rename(r.path, whole); err != nil {
			cut = fmt.Errorf("write failed: %w", err)
		} else {
			r.path = whole
		}
	}
	r.cut, r.ended = cut, time.Now()
	close(r.done)
}

func (r *Recorder) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	wasOpen := !r.closed
	r.closeLocked(nil)
	cut := r.cut
	r.mu.Unlock()
	if wasOpen {
		r.report(cut)
	}
}
