package recording

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

// Keeps the fuzzer from spending the whole run gzipping multi-megabyte inputs.
const fuzzMaxEvent = 64 << 10

// Invalid UTF-8 becomes U+FFFD in the format itself, so byte equality only holds for valid UTF-8.
func FuzzRecordEvents(f *testing.F) {
	f.Add([]byte("hello\n"), "session-1")
	f.Add([]byte{}, "s")
	f.Add([]byte("\x00\x01\x02\xff\n\x1b[31mred\x1b[0m"), "a/b")
	f.Add([]byte("{\"json\": true}"), "")
	f.Add(bytes.Repeat([]byte("x"), 4096), "0123456789abcdef")

	f.Fuzz(func(t *testing.T, data []byte, sessionID string) {
		if len(data) > fuzzMaxEvent {
			data = data[:fuzzMaxEvent]
		}

		dir := t.TempDir()
		t.Setenv("NOKKUD_DATA_DIR", dir)
		recordsDir := paths.RecordsDir()
		if err := os.MkdirAll(recordsDir, 0o700); err != nil {
			t.Fatal(err)
		}
		rec, err := New(Options{
			Width:     80,
			Height:    24,
			Title:     "fuzz-session",
			SessionID: sessionID,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if rec == nil {
			t.Skip("low disk space")
		}

		rec.RecordOutput(data)
		rec.RecordInput(data)
		rec.Close()

		entries, err := os.ReadDir(recordsDir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("expected exactly one recording, got %d (err=%v)", len(entries), err)
		}
		raw, err := os.ReadFile(recordsDir + "/" + entries[0].Name())
		if err != nil {
			t.Fatalf("read recording: %v", err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("recording is not valid gzip: %v", err)
		}
		plain, err := io.ReadAll(zr)
		if err != nil {
			t.Fatalf("gunzip: %v", err)
		}

		lines := bytes.Split(plain, []byte("\n"))
		if len(lines) < 2 || len(lines[len(lines)-1]) != 0 {
			t.Fatalf(
				"recording must end with a newline and hold header + events, got %d lines",
				len(lines),
			)
		}
		lines = lines[:len(lines)-1]

		var header struct {
			Version int `json:"version"`
		}
		if err = json.Unmarshal(lines[0], &header); err != nil || header.Version != 3 {
			t.Fatalf("first line is not an asciicast v3 header: %v", err)
		}

		var sawOutput, sawInput bool
		var output, input strings.Builder
		for _, line := range lines[1:] {
			var parts []json.RawMessage
			if err = json.Unmarshal(line, &parts); err != nil {
				t.Fatalf("event line %q is not valid JSON: %v", line, err)
			}
			if len(parts) != 3 {
				t.Fatalf("event line %q has %d elements, want 3", line, len(parts))
			}
			var elapsed float64
			if err = json.Unmarshal(parts[0], &elapsed); err != nil {
				t.Fatalf("event line %q: elapsed is not a number", line)
			}
			if elapsed < 0 {
				t.Fatalf("event line %q has negative elapsed time", line)
			}
			var typ, payload string
			if err = json.Unmarshal(parts[1], &typ); err != nil {
				t.Fatalf("event line %q: type is not a string", line)
			}
			if err = json.Unmarshal(parts[2], &payload); err != nil {
				t.Fatalf("event line %q: payload is not a string", line)
			}
			switch typ {
			case "o":
				sawOutput = true
				output.WriteString(payload)
			case "i":
				sawInput = true
				input.WriteString(payload)
			case "r":
				// resize events are server-generated, skip
			default:
				t.Fatalf("event line %q has unknown type %q", line, typ)
			}
		}
		if !sawOutput || !sawInput {
			t.Fatalf("recording missing output/input events (o=%v i=%v)", sawOutput, sawInput)
		}
		// A character cut short at the end is recorded at close, so a type's payload can span two events.
		assertPayload(t, output.String(), data)
		assertPayload(t, input.String(), data)
	})
}

// Compares against [json.Marshal]'s own round-trip, invalid UTF-8 becomes U+FFFD so bytes are not compared.
func assertPayload(t *testing.T, payload string, data []byte) {
	t.Helper()
	enc, err := json.Marshal(string(data))
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	var want string
	if err = json.Unmarshal(enc, &want); err != nil {
		t.Fatalf("unmarshal encoder output: %v", err)
	}
	if payload != want {
		t.Fatalf("payload %q does not match encoder round-trip %q", payload, want)
	}
}
