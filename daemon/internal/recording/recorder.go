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

	"github.com/nokku-sh/nokku/daemon/internal/safe"

	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

const (
	// Recording stops at this compressed size and calls OnCut.
	maxSize     = 50 << 20
	maxIdleTime = 2 * time.Second
	// A crash loses at most this. Flushing more often bloats the gzip stream.
	maxFlushInterval = time.Second

	// Written to .part. Only one that closed whole is renamed to .cast.gz.
	partSuffix = ".part"
	castSuffix = ".cast.gz"
)

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
	// SessionID names the file, so it has to be a canonical UUID.
	SessionID string
	User      string // the local account
	Principal string // the cert principal auth matched
	Term      string
	// OnCut runs once on an early stop, with ErrSizeLimit or the write error.
	OnCut func(error)
	// Zero means maxSize.
	MaxSize int64
	// Uploads streams it to the core while written. Nil leaves it on disk.
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
	// Rounding error for the next interval, so intervals sum to the real time.
	msCarry float64
	// Per event type, the head of a multi-byte character the last event cut.
	partial map[string][]byte
	// exitCode is written last, so the x event stays the final event.
	exitCode *int
	dirty    bool
	// broken is set by a failed write, the gzip stream is cut there.
	broken bool
	closed bool
	// Why it stopped early, nil for a whole one. Final once done is closed.
	cut error
	// Final once done is closed.
	ended time.Time

	// flushed wakes the upload. done closes once the file is final.
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

// New returns a nil Recorder on error. It's a no-op, so callers can keep going.
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

	// A reused id must neither write into the first file nor replace it.
	path := filepath.Join(paths.RecordsDir(), opts.SessionID+partSuffix)
	if _, err := os.Lstat(strings.TrimSuffix(path, partSuffix) + castSuffix); err == nil {
		return nil, fmt.Errorf("a recording %s waits for its upload already", opts.SessionID)
	}
	// #nosec G304 - the id is a UUID
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create recording file: %w", err)
	}
	// The lock tells retention a session writes this. A crash releases it too.
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
	go safe.Func("recording flush", rec.flushLoop)()
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
		r.report(r.flushDirty())
	}
}

func (r *Recorder) flushDirty() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.dirty {
		return nil
	}
	r.dirty = false
	if err := r.gw.Flush(); err != nil {
		r.broken = true
		cut := fmt.Errorf("write failed: %w", err)
		r.closeLocked(cut)
		return cut
	}
	select {
	case r.flushed <- struct{}{}:
	default:
	}
	return nil
}

// Outside the lock, as OnCut may end the session and so close the recorder.
func (r *Recorder) report(cut error) {
	if cut == nil {
		return
	}
	slog.Warn("recording stopped early", "path", filepath.Base(r.path), "reason", cut)
	if r.onCut != nil {
		r.onCut(cut)
	}
}

// Caller holds r.mu and checked not closed. A failed write ends the recording.
func (r *Recorder) emit(eventType string, data []byte) error {
	// asciicast v3 times are intervals. Clamped so playback skips idle time.
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

// Length of the multi-byte character cut off at the end of p, 0 if none.
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

// Only an uncut recording is renamed, so a .part with no writer is always cut.
func (r *Recorder) closeLocked(cut error) {
	if r.closed {
		return
	}
	r.closed = true

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
	// A whole recording is synced before its name says so.
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
		// A read can end inside a character. Its head waits for the next event.
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
