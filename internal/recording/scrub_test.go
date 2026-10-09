package recording

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
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
	return &Service{store: st, uploads: map[string]int{}, scrubs: map[string]*scrubRun{}}
}

// testRecording is a recording whose upload went through whole.
func testRecording() *db.Recording {
	return &db.Recording{ID: "rec1", WorkspaceID: "ws1", Key: NewKey(), Complete: true}
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

// scrubBytes runs every pass over a cast in memory.
func scrubBytes(t *testing.T, cast []byte, window, overlap int) ([]byte, bool) {
	t.Helper()
	rules, err := scrubRules()
	if err != nil {
		t.Fatalf("scrubRules: %v", err)
	}
	spans, err := locateSecrets(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(cast)), nil
	}, rules, window, overlap)
	if err != nil {
		t.Fatalf("locateSecrets: %v", err)
	}
	var out bytes.Buffer
	if err := rewriteCast(bytes.NewReader(cast), &out, spans); err != nil {
		t.Fatalf("rewriteCast: %v", err)
	}
	return out.Bytes(), len(spans) > 0
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

	redacted, changed := scrubBytes(t, []byte(cast), scrubWindow, scrubOverlap)
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

// A cast larger than the window is scrubbed like one that fits in it. The
// secrets are split over two events each and land at every distance from a
// window edge as the window grows.
func TestScrubWindowsFindTheSameSecrets(t *testing.T) {
	secrets := []string{
		"https://ci:AKIAABCDEFGHIJKLMNOP@github.com/x",
		"ghp_abcDEF1234567890abcDEF1234567890abcDEF",
		"export DB_PASSWORD=VhT9xNq2mLb4Zw",
	}
	var cast strings.Builder
	cast.WriteString(scrubTestCast[:strings.Index(scrubTestCast, "\n")+1])
	for i := range 12 {
		secret := secrets[i%len(secrets)]
		half := len(secret) / 2
		for _, data := range []string{
			fmt.Sprintf("step %d of a build log with nothing in it\r\n", i),
			"$ " + secret[:half],
			secret[half:] + "\r\n",
		} {
			line, err := json.Marshal([]any{float64(i), "o", data})
			if err != nil {
				t.Fatal(err)
			}
			cast.Write(line)
			cast.WriteByte('\n')
		}
	}

	whole, changed := scrubBytes(t, []byte(cast.String()), scrubWindow, scrubOverlap)
	if !changed {
		t.Fatal("no secret found in one window")
	}
	for _, leak := range []string{"AKIA", "ghp_", "VhT9xNq2mLb4Zw"} {
		if bytes.Contains(whole, []byte(leak)) {
			t.Fatalf("secret fragment %q survived in one window", leak)
		}
	}
	if got := bytes.Count(whole, []byte("of a build log with nothing in it")); got != 12 {
		t.Fatalf("%d of 12 benign lines left", got)
	}

	// The longest secret here is 44 bytes, well under the overlap.
	const overlap = 96
	for _, window := range []int{200, 331, 487} {
		got, _ := scrubBytes(t, []byte(cast.String()), window, overlap)
		if !bytes.Equal(got, whole) {
			t.Fatalf("a window of %d bytes scrubs differently:\n%s\nwant:\n%s", window, got, whole)
		}
	}
}

// The part of an upload that broke off is scrubbed too. The cut runs through
// its last line, and the stored cast ends after the last whole one.
func TestScrubTakesACutRecording(t *testing.T) {
	s := newScrubTestService(t)
	rec := testRecording()
	rec.Complete = false

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte(scrubTestCast)); err != nil {
		t.Fatal(err)
	}
	// Everything so far can be read back, whatever is lost of the rest.
	if err := zw.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write([]byte("[0.5, \"o\", \"the line the cut runs through 9f3kq7\\r\\n\"]\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	writeFrames(t, s, rec, gz.Bytes()[:gz.Len()-20])

	// A whole upload that reads like this is broken, and is left alone.
	whole := *rec
	whole.Complete = true
	if err := s.scrub(t.Context(), &whole); err == nil {
		t.Fatal("a cut stream passed as a whole recording")
	}

	if err := s.scrub(t.Context(), rec); err != nil {
		t.Fatalf("scrub: %v", err)
	}
	// readRecordingObject fails on a cut stream, the rewrite is a whole one.
	cast := readRecordingObject(t, s, rec)
	if events := parseCastEvents(t, cast); len(events) != 5 {
		t.Fatalf("got %d events, want the 5 whole ones", len(events))
	}
	for _, leak := range []string{"AKIA", "MIIB", "VhT9xNq2mLb4Zw", "the cut runs through"} {
		if bytes.Contains(cast, []byte(leak)) {
			t.Fatalf("%q survived in the cut recording", leak)
		}
	}
}

// A scrub and an upload never write the same object at once. No scrub starts
// while an upload runs, and an upload stops the scrub it finds.
func TestScrubAndUploadTakeTurns(t *testing.T) {
	s := newScrubTestService(t)
	rec := testRecording()
	writeRecordingObject(t, s, rec, []byte(scrubTestCast))
	running := func() *scrubRun {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.scrubs[rec.ID]
	}

	end := s.BeginUpload(rec.ID)
	s.ScrubRecording(t.Context(), rec)
	if running() != nil {
		t.Fatal("a scrub started while an upload was writing")
	}
	end()

	s.ScrubRecording(t.Context(), rec)
	if run := running(); run != nil {
		<-run.done
	}
	if bytes.Contains(readRecordingObject(t, s, rec), []byte("AKIA")) {
		t.Fatal("the scrub after the upload did not run")
	}

	stopped := make(chan struct{})
	s.mu.Lock()
	s.scrubs[rec.ID] = &scrubRun{cancel: func() { close(stopped) }, done: stopped}
	s.mu.Unlock()
	end = s.BeginUpload(rec.ID)
	select {
	case <-stopped:
	default:
		t.Fatal("the upload did not stop the scrub it found")
	}
	end()
}

// scrubEvents scrubs a cast of output events and returns what is left of
// their data, end to end.
func scrubEvents(t *testing.T, events ...string) (string, bool) {
	t.Helper()
	var cast strings.Builder
	cast.WriteString(scrubTestCast[:strings.Index(scrubTestCast, "\n")+1])
	for i, data := range events {
		line, err := json.Marshal([]any{float64(i), "o", data})
		if err != nil {
			t.Fatal(err)
		}
		cast.Write(line)
		cast.WriteByte('\n')
	}
	redacted, changed := scrubBytes(t, []byte(cast.String()), scrubWindow, scrubOverlap)
	var out strings.Builder
	for _, ev := range parseCastEvents(t, redacted) {
		out.WriteString(ev.data)
	}
	return out.String(), changed
}

// A terminal puts sequences in and around what it shows, and shows a secret
// in pieces. None of that may hide one, and the sequences stay in the stream.
func TestScrubSeesThroughTheTerminal(t *testing.T) {
	const (
		token  = "ghp_abcDEF1234567890abcDEF1234567890abcDEF"
		jwt    = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAibm9ra3UtdGVzdCJ9.6h9DMbaBdTLULuL93KyFGXz5XYoR3w18JjZQRgd_q1g"
		line1  = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCRokBog4Y3SG+2"
		line2  = "/s4AOD2yorSphMR67Vgg497D60wDztGYOGTGxpGMukMcMpOkEsAZlYycVdETfOjU"
		line3  = "FpfFXA0mXe3s8R4xaKuCR5Ie0gDpt82nqbKuhAXX0N4xOwe6rRsk38x2gWZvRCt1"
		begin  = "-----BEGIN PRIVATE KEY-----"
		ending = "-----END PRIVATE KEY-----"
	)
	var colored strings.Builder
	for _, c := range token {
		colored.WriteString("\x1b[4m" + string(c))
	}

	tests := []struct {
		name   string
		events []string
		leaks  []string
		keeps  []string
	}{
		{
			name:   "a color reset right after the secret",
			events: []string{"\x1b[37mNPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz0123456789\x1b[0m\r\n"},
			leaks:  []string{"npm_abcdefgh"},
			keeps:  []string{"\x1b[37mNPM_TOKEN=", "\x1b[0m\r\n"},
		},
		{
			name: "a sequence right before the command",
			events: []string{
				"\r\x1b[Kcurl -H \"Authorization: Bearer uSCC5AiBLksydgNKSwZtdfoCUPgdljtm4rKknD7Q\" https://api.internal\r\n",
			},
			leaks: []string{"uSCC5AiBLksy"},
			keeps: []string{"\r\x1b[Kcurl -H", "https://api.internal"},
		},
		{
			name:   "a color for every character",
			events: []string{"$ export GH=" + colored.String() + "\x1b[24m\r\n"},
			leaks:  []string{"\x1b[4mg\x1b[4mh\x1b[4mp", "\x1b[4mD\x1b[4mE\x1b[4mF"},
			keeps:  []string{"$ export GH=", "\x1b[4m\x1b[4m", "\x1b[24m\r\n"},
		},
		{
			name:   "a sequence cut by the end of an event",
			events: []string{"token " + token[:10] + "\x1b[3", "8;5;1m" + token[10:] + "\x1b[0m\r\n"},
			leaks:  []string{token[:10], token[10:]},
			keeps:  []string{"token ", "\x1b[38;5;1m", "\x1b[0m\r\n"},
		},
		{
			name:   "a line the pager wrapped",
			events: []string{"SESSION=" + jwt[:60] + " \b" + jwt[60:] + "\r\n:"},
			leaks:  []string{jwt[:20], jwt[60:80], jwt[len(jwt)-20:]},
			keeps:  []string{"SESSION=", "\r\n:"},
		},
		{
			name:   "a page that ends at the wrap",
			events: []string{"{\"api_key\": \"J1FLd5zohpP9bbBPAxs8 \b:\x1b[K"},
			leaks:  []string{"J1FLd5zohpP9"},
			keeps:  []string{"{\"api_key\": \"", "\b:\x1b[K"},
		},
		{
			name: "seen whole once and cut off at the edge later",
			events: []string{
				"export GITHUB_TOKEN=" + token + "\r\n",
				"\x1b[H\x1bMGITHUB_TOKEN=" + token[:30] + "\x1b[40;1H:",
			},
			leaks: []string{token[:30], token[:12]},
			keeps: []string{"\x1b[H\x1bMGITHUB_TOKEN=", "\x1b[40;1H:"},
		},
		{
			name: "a key block with the prompt of a pager between its lines",
			events: []string{
				begin + "\r\n:", "\r\x1b[K" + line1 + "\r\n:", "\r\x1b[K" + line2 + "\r\n:",
				"\r\x1b[K" + line3 + "\r\n:", "\r\x1b[K" + ending + "\r\n:",
			},
			leaks: []string{"PRIVATE KEY", line1[:12], line2[:12], line3[:12], line3[40:]},
			keeps: []string{"\r\x1b[K", "\r\n:"},
		},
		{
			name:   "the head of a key block",
			events: []string{begin + "\r\n" + line1 + "\r\n" + line2 + "\r\n:", "\r\x1b[K/\r\x1b[K" + line3 + "\r\n:"},
			leaks:  []string{line1[:12], line2[:12], line3[:12]},
		},
		{
			name:   "the tail of a key block",
			events: []string{line2 + "\r\n" + line3 + "\r\n" + ending + "\r\n"},
			leaks:  []string{line2[:12], line3[:12]},
		},
		{
			name:   "a token cut off in its payload",
			events: []string{"  30 │ SESSION=" + jwt[:70] + "\r\n     │ done\r\n"},
			leaks:  []string{jwt[:20], jwt[50:70]},
			keeps:  []string{"  30 │ SESSION=", "     │ done"},
		},
		{
			name:   "a window title",
			events: []string{"\x1b]0;export GITHUB_TOKEN=" + token + "\x07$ "},
			leaks:  []string{token[:12]},
			keeps:  []string{"\x1b]0;export GITHUB_TOKEN=", "\x07$ "},
		},
		{
			name:   "a password in a URL",
			events: []string{"DATABASE_URL=postgres://nokku:gPyKn3HmyTWmVWxrqFaPQDXi@db.internal:5432/nokku\r\n"},
			leaks:  []string{"gPyKn3HmyTWm"},
			keeps:  []string{"DATABASE_URL=postgres://nokku:", "@db.internal:5432/nokku"},
		},
		{
			name:   "a password on the command line of mysql",
			events: []string{"$ mysql -u root -p'U22tXJhb2a5yf4cj' -h 10.0.0.5\r\n"},
			leaks:  []string{"U22tXJhb2a5y"},
			keeps:  []string{"$ mysql -u root -p'", "' -h 10.0.0.5"},
		},
		{
			name: "a Discord webhook",
			events: []string{
				"https://discord.com/api/webhooks/055565118294275913/4I6nL6m3bHCwVjFE8_ueyuG0y4H1mWkIbd5hPQHaPP5d0e-pE7try6y8UVoU2a13AG2r\r\n",
			},
			leaks: []string{"4I6nL6m3bHCw"},
			keeps: []string{"https://discord.com/api/webhooks/"},
		},
		{
			name:   "a key of our own",
			events: []string{"nk login --token nk_sa_abcdefghijklmnopqrstuvwxyzABCDEF012345\r\n"},
			leaks:  []string{"nk_sa_abcdef"},
			keeps:  []string{"nk login --token "},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := scrubEvents(t, tt.events...)
			for _, leak := range tt.leaks {
				if strings.Contains(got, leak) {
					t.Errorf("%q survived in %q", leak, got)
				}
			}
			for _, keep := range tt.keeps {
				if !strings.Contains(got, keep) {
					t.Errorf("%q is gone from %q", keep, got)
				}
			}
			if !strings.Contains(got, redaction) {
				t.Errorf("no redaction in %q", got)
			}
		})
	}
}

// A secret typed one key at a time is one secret, and shows one redaction.
func TestScrubMarksASecretOnce(t *testing.T) {
	typed := strings.Split("export GITHUB_TOKEN=ghp_abcDEF1234567890abcDEF1234567890abcDEF", "")
	got, _ := scrubEvents(t, append(typed, "\r\n")...)
	if want := "export GITHUB_TOKEN=" + redaction + "\r\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Every line of a secret shows the redaction, and keeps its line break. A
// screen that scrolls by lines stays in step.
func TestScrubKeepsTheLinesOfASecret(t *testing.T) {
	got, _ := scrubEvents(
		t,
		"-----BEGIN RSA PRIVATE KEY-----\r\n",
		"MIIBqwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890\r\n-----END RSA PRIVATE KEY-----\r\nnext\r\n",
	)
	if want := strings.Repeat(redaction+"\r\n", 3) + "next\r\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Sequences alone are no reason to rewrite a recording.
func TestScrubLeavesATerminalWithoutSecretsAlone(t *testing.T) {
	events := []string{
		"\x1b[?1049h\x1b[22;0;0t\x1b[1;40r\x1b[H\x1b[2J",
		"\x1b[38;5;246m  12\x1b[0m \x1b[38;5;231mbuild \b step\x1b[0m\r\n",
		"\x1b]0;make test\x07\x1b[32mok\x1b[39m  github.com/nokku-sh/nokku/internal/recording\t0.081s\r\n",
		"\b\b\b\x1b[K\x1b[?1049l",
	}
	got, changed := scrubEvents(t, events...)
	if changed || got != strings.Join(events, "") {
		t.Fatalf("a clean recording changed: %q", got)
	}
}
