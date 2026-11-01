package recording

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/daemon/internal/paths"
)

// Keeps the fuzzer from spending the whole run gzipping multi-megabyte inputs.
const fuzzMaxEvent = 64 << 10

func FuzzRecordEvents(f *testing.F) {
	f.Add([]byte("hello\n"))
	f.Add([]byte{})
	f.Add([]byte("\x00\x01\x02\xff\n\x1b[31mred\x1b[0m"))
	f.Add([]byte("{\"json\": true}"))
	f.Add(bytes.Repeat([]byte("x"), 4096))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxEvent {
			data = data[:fuzzMaxEvent]
		}

		dir := t.TempDir()
		t.Setenv("NOKKUD_DATA_DIR", dir)
		recordsDir := paths.RecordsDir()
		require.NoError(t, os.MkdirAll(recordsDir, 0o700))
		rec, err := New(Options{
			Width:     80,
			Height:    24,
			Title:     "fuzz-session",
			SessionID: testID,
		})
		require.NoError(t, err)
		if rec == nil {
			t.Skip("low disk space")
		}

		rec.RecordOutput(data)
		rec.RecordInput(data)
		rec.Close()

		entries, err := os.ReadDir(recordsDir)
		require.NoError(t, err)
		require.Len(t, entries, 1, "expected exactly one recording")
		raw, err := os.ReadFile(recordsDir + "/" + entries[0].Name())
		require.NoError(t, err, "read recording")
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		require.NoError(t, err, "recording is not valid gzip")
		plain, err := io.ReadAll(zr)
		require.NoError(t, err, "gunzip")

		lines := bytes.Split(plain, []byte("\n"))
		require.GreaterOrEqual(t, len(lines), 2, "recording must hold a header and events")
		require.Empty(t, lines[len(lines)-1], "recording must end with a newline")
		lines = lines[:len(lines)-1]

		var header struct {
			Version int `json:"version"`
		}
		require.NoError(t, json.Unmarshal(lines[0], &header), "first line is not an asciicast v3 header")
		require.Equal(t, 3, header.Version, "first line is not an asciicast v3 header")

		var sawOutput, sawInput bool
		var output, input strings.Builder
		for _, line := range lines[1:] {
			var parts []json.RawMessage
			require.NoError(t, json.Unmarshal(line, &parts), "event line %q is not valid JSON", line)
			require.Len(t, parts, 3, "event line %q", line)
			var elapsed float64
			require.NoError(t, json.Unmarshal(parts[0], &elapsed), "event line %q: elapsed is not a number", line)
			require.GreaterOrEqual(t, elapsed, 0.0, "event line %q has negative elapsed time", line)
			var typ, payload string
			require.NoError(t, json.Unmarshal(parts[1], &typ), "event line %q: type is not a string", line)
			require.NoError(t, json.Unmarshal(parts[2], &payload), "event line %q: payload is not a string", line)
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
		require.True(t, sawOutput, "recording has no output event")
		require.True(t, sawInput, "recording has no input event")
		// A cut character is recorded at close, so a payload can span events.
		assertPayload(t, output.String(), data)
		assertPayload(t, input.String(), data)
	})
}

// Compares to [json.Marshal]'s round-trip, invalid UTF-8 becomes U+FFFD.
func assertPayload(t *testing.T, payload string, data []byte) {
	t.Helper()
	enc, err := json.Marshal(string(data))
	require.NoError(t, err, "marshal input")
	var want string
	require.NoError(t, json.Unmarshal(enc, &want), "unmarshal encoder output")
	require.Equal(t, want, payload, "payload does not match the encoder round-trip")
}
