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
)

const testID = "0199aaaa-0000-7000-8000-0000000000a1"

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
	rec, err := New(Options{Width: 80, Height: 24, SessionID: testID})
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

// A previous HTML-unescape pass turned a literal < into invalid JSON and broke the whole cast.
func TestRecorderEscapedUnicodeRoundTrips(t *testing.T) {
	recordsDir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	rec, err := New(Options{Width: 80, Height: 24, SessionID: testID})
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

	rec, err := New(Options{Width: 80, Height: 24, Title: "t", SessionID: testID})
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

// A second session under the same id never touches the first one's recording, open or waiting for its upload.
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
