package recording

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/nokkud/internal/paths"
)

func newRecordsDir(t *testing.T) string {
	t.Helper()
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	dir := paths.RecordsDir()
	must := require.New(t)
	must.NoError(os.MkdirAll(dir, 0o700))
	return dir
}

func TestRecorderCorrelatesSessionID(t *testing.T) {
	recordsDir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	sessionID := "0123456789abcdef0123456789abcdef"
	rec, err := New(Options{Width: 80, Height: 24, Title: "t", SessionID: sessionID})
	must.NoError(err, "new recorder")
	rec.RecordOutput([]byte("hello"))
	rec.Close()

	entries, err := os.ReadDir(recordsDir)
	must.NoError(err)
	must.Len(entries, 1)
	is.Contains(entries[0].Name(), sessionID)

	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	must.NoError(err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	must.NoError(err)
	defer gz.Close()

	var hdr map[string]any
	must.NoError(json.NewDecoder(gz).Decode(&hdr))
	is.Equal(sessionID, hdr["session_id"])
}

func TestRecorderV3Schema(t *testing.T) {
	recordsDir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	rec, err := New(Options{Width: 100, Height: 40, Title: "t", SessionID: "sess-1"})
	must.NoError(err, "new recorder")
	rec.RecordOutput([]byte("hi"))
	rec.RecordExit(7)
	rec.Close()

	entries, err := os.ReadDir(recordsDir)
	must.NoError(err)
	must.Len(entries, 1)
	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	must.NoError(err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	must.NoError(err)
	defer gz.Close()

	lines := strings.Split(strings.TrimSuffix(string(mustReadAll(t, gz)), "\n"), "\n")

	var hdr struct {
		Version int `json:"version"`
		Term    struct {
			Cols int    `json:"cols"`
			Rows int    `json:"rows"`
			Type string `json:"type"`
		} `json:"term"`
	}
	must.NoError(json.Unmarshal([]byte(lines[0]), &hdr))
	is.Equal(3, hdr.Version)
	is.Equal(100, hdr.Term.Cols)
	is.Equal(40, hdr.Term.Rows)
	is.NotEmpty(hdr.Term.Type)

	last := lines[len(lines)-1]
	var exit []any
	must.NoError(json.Unmarshal([]byte(last), &exit), "last event %q is not valid JSON", last)
	must.Len(exit, 3)
	is.Equal("x", exit[1])
	is.Equal("7", exit[2])
}

// eventLine is a decoded asciicast event: [interval, code, data].
type eventLine struct {
	Interval float64
	Code     string
	Data     []byte
}

func recRecordAndReadEvents(
	t *testing.T,
	recordsDir string,
	rec *Recorder,
	check func([]eventLine),
) {
	t.Helper()
	must := require.New(t)
	rec.Close()

	entries, err := os.ReadDir(recordsDir)
	must.NoError(err)
	must.Len(entries, 1)
	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	must.NoError(err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	must.NoError(err)
	defer gz.Close()

	lines := strings.Split(strings.TrimSuffix(string(mustReadAll(t, gz)), "\n"), "\n")
	events := make([]eventLine, 0, len(lines)-1)
	for _, line := range lines[1:] {
		var ev []json.RawMessage
		must.NoError(json.Unmarshal([]byte(line), &ev))
		var code string
		var data string
		if len(ev) >= 3 {
			_ = json.Unmarshal(ev[1], &code)
			_ = json.Unmarshal(ev[2], &data)
		}
		events = append(events, eventLine{Code: code, Data: []byte(data)})
	}
	check(events)
}

func TestRecorderKeepsSplitCharacters(t *testing.T) {
	recordsDir := newRecordsDir(t)
	rec, err := New(Options{Width: 80, Height: 24, SessionID: "s1"})
	require.NoError(t, err, "new recorder")

	euro := []byte("€")
	rec.RecordOutput(append([]byte("a"), euro[:2]...))
	rec.RecordOutput(append([]byte{euro[2]}, 'b'))
	rec.RecordOutput(euro[:1])

	recRecordAndReadEvents(t, recordsDir, rec, func(events []eventLine) {
		var out strings.Builder
		for _, ev := range events {
			if ev.Code == "o" {
				out.Write(ev.Data)
			}
		}
		assert.Equal(t, "a€b�", out.String())
	})
}

func TestRecorderNoHTMLEscape(t *testing.T) {
	recordsDir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	rec, err := New(Options{Width: 80, Height: 24, SessionID: "s1"})
	must.NoError(err, "new recorder")
	rec.RecordOutput([]byte("a < b & c > d\n"))
	rec.Close()

	entries, err := os.ReadDir(recordsDir)
	must.NoError(err)
	must.Len(entries, 1)
	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	must.NoError(err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	must.NoError(err)
	defer gz.Close()

	raw := string(mustReadAll(t, gz))
	is.Contains(raw, "<")
	is.Contains(raw, "&")
	is.Contains(raw, ">")
	is.NotContains(raw, `\u003c`)
	is.NotContains(raw, `\u0026`)
}

// A previous HTML-unescape pass turned a literal < into invalid JSON and broke the whole cast.
func TestRecorderEscapedUnicodeRoundTrips(t *testing.T) {
	recordsDir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	rec, err := New(Options{Width: 80, Height: 24, SessionID: "s1"})
	must.NoError(err, "new recorder")
	input := `echo '\u003c \u003e \u0026'`
	rec.RecordOutput([]byte(input))
	recRecordAndReadEvents(t, recordsDir, rec, func(events []eventLine) {
		var found bool
		for _, e := range events {
			if string(e.Data) == input {
				found = true
			}
		}
		is.True(found, "event data %q did not round trip", input)
	})
}

func mustReadAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	data, err := io.ReadAll(r)
	require.NoError(t, err, "read gzip")
	return data
}

func TestRecorderFlushesWithoutClose(t *testing.T) {
	recordsDir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	rec, err := New(Options{Width: 80, Height: 24, Title: "t"})
	must.NoError(err, "new recorder")
	defer rec.Close()

	rec.RecordOutput([]byte("first"))
	rec.RecordOutput([]byte("second"))

	// Generous slack over the flush interval. The file must hold the events though Close never ran.
	time.Sleep(3 * maxFlushInterval)

	entries, err := os.ReadDir(recordsDir)
	must.NoError(err)
	must.Len(entries, 1)

	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	must.NoError(err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	must.NoError(err)
	defer gz.Close()

	data, err := io.ReadAll(gz)
	// An unclosed recording has no gzip footer, so ErrUnexpectedEOF is the intended crash behavior.
	is.True(err == nil || errors.Is(err, io.ErrUnexpectedEOF),
		"read recording before close: %v", err)
	body := string(data)
	is.Contains(body, "first")
	is.Contains(body, "second")
}

// New returns a nil Recorder when recording is unavailable, and sessions rely on it being a safe no-op.
func TestNilRecorderIsNoOp(t *testing.T) {
	t.Parallel()

	var rec *Recorder
	rec.RecordOutput([]byte("out"))
	rec.RecordInput([]byte("in"))
	rec.RecordResize(80, 24)
	rec.Close()
	rec.Close()

	// The typed-nil trap: this interface is non-nil though rec is, so the methods themselves must be nil-safe.
	var iface interface{ RecordResize(int, int) } = rec
	iface.RecordResize(80, 24)
}

// slowSink blocks in Close until released, like an upload stream waiting on the backend.
type slowSink struct {
	release chan struct{}
	done    chan struct{}
}

func (s *slowSink) Write(p []byte) (int, error) { return len(p), nil }

func (s *slowSink) Close() error {
	<-s.release
	close(s.done)
	return nil
}

func TestRecorderCloseDoesNotBlockOnSink(t *testing.T) {
	recordsDir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	sink := &slowSink{release: make(chan struct{}), done: make(chan struct{})}
	rec, err := New(Options{Width: 80, Height: 24, Title: "t", Sink: sink})
	must.NoError(err, "new recorder")
	rec.RecordOutput([]byte("hello"))

	start := time.Now()
	rec.Close()
	is.Less(time.Since(start), time.Second, "Close blocked on the sink")

	// The local file is complete and readable while the sink is still open.
	entries, err := os.ReadDir(recordsDir)
	must.NoError(err)
	must.Len(entries, 1)
	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	must.NoError(err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	must.NoError(err)
	defer gz.Close()
	data, err := io.ReadAll(gz)
	must.NoError(err, "local recording must be complete after Close")
	is.Contains(string(data), "hello")

	close(sink.release)
	<-sink.done
}
