package recording

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/storage"
)

const scrubTestCast = `{"version":3,"term":{"cols":80,"rows":24,"type":"xterm-256color"},"timestamp":1700000000}
[0.0, "o", "git push https://ci:AKIAABCDEFGHIJKLMNOP@github.com/x\r\n"]
[0.1, "o", "-----BEGIN RSA PRIVATE KEY-----\r\n"]
[0.2, "o", "MIIB\r\nqwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890\r\n-----END RSA PRIVATE KEY-----\r\n"]
[0.3, "i", "export DB_PASSWORD=VhT9xNq2mLb4Zw\r\n"]
[0.4, "o", "ls -la < /tmp & > out\r\n"]
`

func newScrubTestService(t *testing.T) *Service {
	t.Helper()
	t.Setenv("NOKKU_STORAGE", "local")
	t.Setenv("NOKKU_LOCAL_STORAGE_PATH", t.TempDir())
	st, err := storage.New(t.Context(), "http://localhost:3000")
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	return &Service{store: st}
}

func testRecording() *db.Recording {
	return &db.Recording{ID: "rec1", WorkspaceID: "ws1", Key: NewKey()}
}

// writeFrames stores plaintext as one recording object, in small chunks to
// force many frames.
func writeFrames(t *testing.T, s *Service, rec *db.Recording, plaintext []byte) {
	t.Helper()
	w, err := s.NewWriter(t.Context(), rec)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for chunk := range slices.Chunk(plaintext, 16) {
		if err := w.WriteChunk(chunk); err != nil {
			t.Fatalf("write frame: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("commit object: %v", err)
	}
}

// writeRecordingObject stores a gzipped cast the way UploadRecording does.
func writeRecordingObject(t *testing.T, s *Service, rec *db.Recording, cast []byte) {
	t.Helper()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(cast); err != nil {
		t.Fatalf("gzip cast: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	writeFrames(t, s, rec, gz.Bytes())
}

func readRecordingObject(t *testing.T, s *Service, rec *db.Recording) []byte {
	t.Helper()
	fr, err := s.OpenReader(t.Context(), rec)
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer func() { _ = fr.Close() }()

	gz, err := gzip.NewReader(fr)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer func() { _ = gz.Close() }()

	cast, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	return cast
}

type scrubTestEvent struct {
	code string
	data string
}

func parseCastEvents(t *testing.T, cast []byte) []scrubTestEvent {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(string(cast), "\n"), "\n")
	events := make([]scrubTestEvent, 0, len(lines)-1)
	for _, line := range lines[1:] {
		var raw []json.RawMessage
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			t.Fatalf("event %q is not valid JSON: %v", line, err)
		}
		if len(raw) != 3 {
			t.Fatalf("event %q has %d elements, want 3", line, len(raw))
		}
		ev := scrubTestEvent{}
		if err := json.Unmarshal(raw[1], &ev.code); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw[2], &ev.data); err != nil {
			t.Fatal(err)
		}
		events = append(events, ev)
	}
	return events
}

// TestScrubRemovesSecrets runs the full scrub pipeline over a stored
// recording: AWS keys, private key blocks spanning events, and assignment
// values must be masked, benign content must survive byte for byte, and the
// event structure must stay intact. The fake key body is 64+ chars because
// gitleaks' private-key rule requires that much between the BEGIN/END markers.
func TestScrubRemovesSecrets(t *testing.T) {
	s := newScrubTestService(t)
	rec := testRecording()
	writeRecordingObject(t, s, rec, []byte(scrubTestCast))

	if err := s.scrub(t.Context(), rec); err != nil {
		t.Fatalf("scrub: %v", err)
	}

	events := parseCastEvents(t, readRecordingObject(t, s, rec))
	if len(events) != 5 {
		t.Fatalf("got %d events, want 5", len(events))
	}

	const secret = "<redacted>"
	for _, ev := range events {
		for _, leak := range []string{"AKIA", "MIIB", "VhT9xNq2mLb4Zw", "PRIVATE KEY"} {
			if strings.Contains(ev.data, leak) {
				t.Fatalf("secret fragment %q survived in %q event: %q", leak, ev.code, ev.data)
			}
		}
	}

	// The assignment keeps its key name, the private key block is masked
	// across the two events it was split over.
	if got := events[3].data; !strings.Contains(got, "DB_PASSWORD="+secret) {
		t.Fatalf("assignment event = %q, want key kept with value masked", got)
	}
	if !strings.Contains(events[1].data, secret) || !strings.Contains(events[2].data, secret) {
		t.Fatalf("private key events = %q, %q, want masked", events[1].data, events[2].data)
	}

	// Benign output is untouched, including HTML-significant characters.
	if got := events[4].data; got != "ls -la < /tmp & > out\r\n" {
		t.Fatalf("benign event = %q, want unchanged", got)
	}
}

// TestScrubWithoutSecretsIsNoop verifies a clean recording is not rewritten.
func TestScrubWithoutSecretsIsNoop(t *testing.T) {
	s := newScrubTestService(t)
	rec := testRecording()

	clean := scrubTestCast[:strings.Index(scrubTestCast, "\n")+1] +
		"[0.0, \"o\", \"just a build log\\n\"]\n"
	writeRecordingObject(t, s, rec, []byte(clean))

	if err := s.scrub(t.Context(), rec); err != nil {
		t.Fatalf("scrub: %v", err)
	}

	events := parseCastEvents(t, readRecordingObject(t, s, rec))
	if len(events) != 1 || events[0].data != "just a build log\n" {
		t.Fatalf("clean recording changed: %+v", events)
	}
}

// TestScrubCastSplitsSpansAcrossEvents verifies a secret split across event
// boundaries is redacted in both events it touches.
func TestScrubCastSplitsSpansAcrossEvents(t *testing.T) {
	cast := scrubTestCast[:strings.Index(scrubTestCast, "\n")+1] +
		"[0.0, \"o\", \"ghp_\"]\n" +
		"[0.1, \"o\", \"abcDEF1234567890abcDEF1234567890abcDEF done\\n\"]\n"

	redacted, changed, err := scrubCast([]byte(cast))
	if err != nil {
		t.Fatalf("scrubCast: %v", err)
	}
	if !changed {
		t.Fatal("expected the split secret to be redacted")
	}

	events := parseCastEvents(t, redacted)
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if strings.Contains(string(redacted[1:]), "ghp_") || strings.Contains(string(redacted[1:]), "abcDEF1234567890") {
		t.Fatalf("split secret survived: %s", redacted)
	}
	if !strings.Contains(events[1].data, " done\n") {
		t.Fatalf("trailing benign output lost: %q", events[1].data)
	}
}
