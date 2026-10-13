package recording

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

const (
	// Recording stops at this compressed size and OnLimit ends the session.
	maxSize     = 50 << 20
	maxIdleTime = 2 * time.Second
	// A crash loses at most this much of the tail of a recording.
	maxFlushInterval = 100 * time.Millisecond
)

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
	Width     int
	Height    int
	Title     string
	SessionID string
	User      string // the local account, labels the file and is needed to upload it later
	Principal string // the certificate principal auth matched, names who was logged in
	Term      string
	// A nil error from Sink's Close confirms the upload.
	Sink    io.WriteCloser
	OnLimit func()
	// MaxSize defaults to 50 MB. Tests shrink it.
	MaxSize int64
}

type Recorder struct {
	mu        sync.Mutex
	path      string
	onLimit   func()
	maxSize   int64
	cw        *countingWriter
	gw        *gzip.Writer
	sink      io.WriteCloser
	lastEvent time.Time
	// msCarry carries the rounding error to the next interval, so the written intervals sum to the real time.
	msCarry float64
	// partial holds, per event type, the head of a multi-byte character the last event ended in.
	partial map[string][]byte
	// exitCode is written last, so the x event stays the final event.
	exitCode *int
	dirty    bool
	done     chan struct{}
	closed   bool
}

type countingWriter struct {
	w       *os.File
	written int64
}

// A sink failure is logged once and the sink is dropped, the file is never affected.
type sinkTee struct {
	w    io.Writer
	sink io.WriteCloser
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.written += int64(n)
	return n, err
}

func (t *sinkTee) Write(p []byte) (int, error) {
	if t.sink != nil {
		if _, err := t.sink.Write(p); err != nil {
			slog.Warn("recording sink failed, keeping local copy", "error", err)
			_ = t.sink.Close()
			t.sink = nil
		}
	}
	return t.w.Write(p)
}

// New may return a nil Recorder, which is a valid no-op, so callers can keep going after an error.
func New(opts Options) (*Recorder, error) {
	if err := checkDiskSpace(paths.RecordsDir()); err != nil {
		return nil, err
	}

	// CreateTemp adds a random part, so sessions started in the same second never collide. The file is 0600.
	pattern := recordingPattern(time.Now(), toSnakeCase(opts.User), opts.SessionID)
	f, err := os.CreateTemp(paths.RecordsDir(), pattern)
	if err != nil {
		return nil, fmt.Errorf("create recording file: %w", err)
	}
	path := f.Name()

	if err = enforceRetention(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}

	cw := &countingWriter{w: f}
	var w io.Writer = cw
	if opts.Sink != nil {
		w = &sinkTee{w: cw, sink: opts.Sink}
	}
	gw := gzip.NewWriter(w)
	enc := json.NewEncoder(gw)
	enc.SetEscapeHTML(false)

	if err = enc.Encode(header{
		Version: 3,
		Term: term{
			Cols: opts.Width,
			Rows: opts.Height,
			Type: cmp.Or(opts.Term, "xterm-256color"),
		},
		Timestamp: time.Now().Unix(),
		Title:     opts.Title,
		SessionID: opts.SessionID,
		User:      opts.User,
		Principal: opts.Principal,
	}); err != nil {
		_ = gw.Close()
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write header: %w", err)
	}

	if err = gw.Flush(); err != nil {
		_ = gw.Close()
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("flush header: %w", err)
	}

	rec := &Recorder{
		path:      path,
		onLimit:   opts.OnLimit,
		maxSize:   cmp.Or(opts.MaxSize, maxSize),
		cw:        cw,
		gw:        gw,
		sink:      opts.Sink,
		lastEvent: time.Now(),
		partial:   map[string][]byte{},
		done:      make(chan struct{}),
	}
	active.Store(path, struct{}{})
	go rec.flushLoop()
	return rec, nil
}

func (r *Recorder) flushLoop() {
	ticker := time.NewTicker(maxFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.mu.Lock()
			if r.closed {
				r.mu.Unlock()
				return
			}
			if r.dirty {
				_ = r.gw.Flush()
				r.dirty = false
			}
			r.mu.Unlock()
		case <-r.done:
			return
		}
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
	if r.cw.written < r.maxSize {
		// A read can end inside a multi-byte character. Its head waits for the next event of its type.
		if head := r.partial[eventType]; len(head) > 0 {
			data = append(head, data...)
		}
		cut := len(data) - incompleteTail(data)
		r.partial[eventType] = bytes.Clone(data[cut:])
		r.emit(eventType, data[:cut])
		r.mu.Unlock()
		return
	}
	r.closeLocked()
	r.mu.Unlock()

	slog.Warn("recording size limit reached, stopping", "size", r.maxSize)
	if r.onLimit != nil {
		r.onLimit()
	}
}

// Caller holds r.mu and has checked not closed.
func (r *Recorder) emit(eventType string, data []byte) {
	// asciicast v3 timestamps are intervals. Gaps over maxIdleTime are clamped so playback skips idle time.
	now := time.Now()
	gap := min(now.Sub(r.lastEvent), maxIdleTime)
	r.lastEvent = now

	encodedData := marshalEventData(string(data))

	line := fmt.Sprintf("[%s, %q, %s]\n", r.roundInterval(gap), eventType, encodedData)

	if _, err := r.gw.Write([]byte(line)); err != nil {
		slog.Error("write recording event", "error", err)
	}
	r.dirty = true
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

func (r *Recorder) closeLocked() {
	if r.closed {
		return
	}
	r.closed = true
	close(r.done)

	// A character the stream never completed is recorded as it stands.
	for _, eventType := range []string{"o", "i"} {
		if tail := r.partial[eventType]; len(tail) > 0 {
			r.emit(eventType, tail)
		}
	}
	if r.exitCode != nil {
		r.emit("x", []byte(strconv.Itoa(*r.exitCode)))
	}

	// gw.Close writes the gzip footer, so the file is complete. The sink gets the tail through the tee.
	if err := r.gw.Close(); err != nil {
		slog.Error("close gzip writer", "error", err)
	}
	if err := r.cw.w.Close(); err != nil {
		slog.Error("close recording file", "error", err)
	}
	if r.sink == nil {
		active.Delete(r.path)
		return
	}
	// The sink's Close waits for the backend, so it runs off the session path and never holds the client.
	go func() {
		defer active.Delete(r.path)
		if err := r.sink.Close(); err != nil {
			slog.Warn("recording upload incomplete, retrying later", "error", err)
			return
		}
		removeUploaded(r.path)
	}()
}

func (r *Recorder) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeLocked()
}
