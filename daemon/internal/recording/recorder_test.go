package recording

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testID = "0199aaaa-0000-7000-8000-0000000000a1"

// eventLine is a decoded asciicast event: [interval, code, data].
type eventLine struct {
	Interval float64
	Code     string
	Data     []byte
}

func TestRecorderCorrelatesSessionID(t *testing.T) {
	recordsDir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	sessionID := "0199aaaa-0000-7000-8000-0000000000c1"
	rec, err := New(Options{Width: 80, Height: 24, Title: "t", SessionID: sessionID})
	must.NoError(err, "new recorder")
	rec.RecordOutput([]byte("hello"))
	rec.Close()

	entries, err := os.ReadDir(recordsDir)
	must.NoError(err)
	must.Len(entries, 1)
	is.Equal(sessionID+castSuffix, entries[0].Name(), "a whole recording is named by its id")

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

	rec, err := New(Options{Width: 100, Height: 40, Title: "t", SessionID: testID})
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

func closeAndReadEvents(
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
	rec, err := New(Options{Width: 80, Height: 24, SessionID: testID})
	require.NoError(t, err, "new recorder")

	euro := []byte("€")
	rec.RecordOutput(append([]byte("a"), euro[:2]...))
	rec.RecordOutput(append([]byte{euro[2]}, 'b'))
	rec.RecordOutput(euro[:1])

	closeAndReadEvents(t, recordsDir, rec, func(events []eventLine) {
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

	rec, err := New(Options{Width: 80, Height: 24, SessionID: testID})
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

// An HTML-unescape pass once turned a literal < into JSON that broke the cast.
func TestRecorderEscapedUnicodeRoundTrips(t *testing.T) {
	recordsDir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	rec, err := New(Options{Width: 80, Height: 24, SessionID: testID})
	must.NoError(err, "new recorder")
	input := `echo '\u003c \u003e \u0026'`
	rec.RecordOutput([]byte(input))
	closeAndReadEvents(t, recordsDir, rec, func(events []eventLine) {
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

	rec, err := New(Options{Width: 80, Height: 24, Title: "t", SessionID: testID})
	must.NoError(err, "new recorder")
	defer rec.Close()

	rec.RecordOutput([]byte("first"))
	rec.RecordOutput([]byte("second"))

	path := rec.path
	must.Eventually(func() bool {
		raw, _ := os.ReadFile(path)
		text, _ := unzipCast(raw)
		return strings.Contains(text, "second")
	}, 3*maxFlushInterval, 10*time.Millisecond, "the flush loop never reached the file")

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
	// An unclosed recording has no gzip footer, so ErrUnexpectedEOF is fine.
	is.True(err == nil || errors.Is(err, io.ErrUnexpectedEOF),
		"read recording before close: %v", err)
	body := string(data)
	is.Contains(body, "first")
	is.Contains(body, "second")
}

// New returns nil when recording is unavailable, sessions rely on the no-op.
func TestNilRecorderIsNoOp(t *testing.T) {
	t.Parallel()

	var rec *Recorder
	rec.RecordOutput([]byte("out"))
	rec.RecordInput([]byte("in"))
	rec.RecordResize(80, 24)
	rec.Close()
	rec.Close()

	// A typed nil: the interface is non-nil, so the methods must be nil-safe.
	var iface interface{ RecordResize(int, int) } = rec
	iface.RecordResize(80, 24)
}

// A session reusing an id never touches the first recording, open or pending.
func TestRecorderRefusesAnIDInUse(t *testing.T) {
	newRecordsDir(t)
	first, err := New(Options{Width: 80, Height: 24, SessionID: testID})
	require.NoError(t, err)
	_, err = New(Options{Width: 80, Height: 24, SessionID: testID})
	require.Error(t, err, "a second recorder opened the first one's file")
	first.RecordOutput([]byte("first session"))
	first.Close()

	_, err = New(Options{Width: 80, Height: 24, SessionID: testID})
	require.Error(t, err, "a second recorder would replace the whole recording at its close")
	data, err := os.ReadFile(first.path)
	require.NoError(t, err)
	text, err := unzipCast(data)
	require.NoError(t, err)
	assert.Contains(t, text, "first session")
}

// Retention tries the lock of every recording. A try by another session must not cost a new recorder its file.
func TestRecorderStartsWhileRetentionLooks(t *testing.T) {
	dir := newRecordsDir(t)
	for range 400 {
		id := uuid.New().String()
		path := filepath.Join(dir, id+partSuffix)
		var started atomic.Bool
		var probes sync.WaitGroup
		for range 4 {
			probes.Go(func() {
				for !started.Load() {
					beingWritten(path)
				}
			})
		}
		rec, err := New(Options{Width: 80, Height: 24, SessionID: id})
		started.Store(true)
		probes.Wait()
		require.NoError(t, err, "a retention check held the new file's lock")
		rec.Close()
		require.NoError(t, os.Remove(rec.path))
	}
}
