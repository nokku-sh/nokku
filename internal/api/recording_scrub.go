package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"

	"github.com/nokku-sh/nokku/internal/db"
	"github.com/nokku-sh/nokku/internal/storage"
)

const (
	// scrubTimeout bounds one scrub job.
	scrubTimeout = 10 * time.Minute
	// maxScrubBytes caps the decompressed cast held in memory while scrubbing.
	maxScrubBytes = 64 << 20
	// scrubChunk is the plaintext gzip slice size written when replacing a
	// scrubbed object.
	scrubChunk = 64 << 10
	// redaction replaces every detected secret value.
	redaction = "<redacted>"
)

// scrubDetector loads the embedded gitleaks ruleset once per process.
var scrubDetector = sync.OnceValues(detect.NewDetectorDefaultConfig)

// keywordRe matches any rule keyword in one pass over the blob, replacing
// gitleaks' per-rule prefilter. A nil regex runs every rule unfiltered.
var keywordRe = sync.OnceValue(func() *regexp.Regexp {
	det, err := scrubDetector()
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	kws := make([]string, 0, 512)
	for _, rule := range det.Config.Rules {
		for _, kw := range rule.Keywords {
			if _, ok := seen[kw]; ok {
				continue
			}
			seen[kw] = struct{}{}
			kws = append(kws, regexp.QuoteMeta(kw))
		}
	}
	return regexp.MustCompile(`(?i)(?:` + strings.Join(kws, "|") + `)`)
})

// customPatterns catch the terminal-typical secrets gitleaks' file-oriented
// rules miss. Group selects the submatch to redact, so assignment and header
// patterns keep their left-hand side readable.
var customPatterns = []struct {
	re    *regexp.Regexp
	group int
}{
	{regexp.MustCompile(`(?s)-----BEGIN [^-]+PRIVATE KEY-----.*?-----END [^-]+PRIVATE KEY-----`), 0},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), 0},
	{regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b`), 0},
	{regexp.MustCompile(`(?i)\bgithub_pat_[A-Za-z0-9_]{20,}\b`), 0},
	{
		regexp.MustCompile(
			`(?i)\b[A-Za-z0-9_]*(?:secret|token|password|passwd|passphrase|apikey|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential|bearer|auth)[A-Za-z0-9_]*\b\s*[=:]\s*["']?([^\s"',;]+)`,
		),
		1,
	},
	{regexp.MustCompile(`(?i)\bauthorization:[ \t]*(?:bearer|basic|token)?[ \t]*([^\s]+)`), 1},
}

// span is a half-open byte range of the stream blob to redact.
type span struct {
	start, end int
}

// ScrubRecording asynchronously scrubs credential patterns from a completed
// recording and replaces the stored object in place. Best effort: a failure
// leaves the recording exactly as uploaded. A failed scrub is not retried,
// and a scrub racing a delete writes a stray object, which the workspace
// wipe sweeps.
func (s *RecordingService) ScrubRecording(rec *db.Recording) {
	ctx, cancel := context.WithTimeout(context.Background(), scrubTimeout)
	go func() {
		defer cancel()
		if err := s.scrub(ctx, rec.WorkspaceID, rec.ID); err != nil {
			slog.Warn("scrub recording failed, recording kept as uploaded",
				"recording_id", rec.ID, "error", err)
		}
	}()
}

// scrub rewrites the recording object with detected secrets masked. The
// object format is unchanged: framed encrypted slices of the gzipped cast.
func (s *RecordingService) scrub(ctx context.Context, workspaceID, recordingID string) error {
	cast, err := s.readRecordingCast(ctx, workspaceID, recordingID)
	if err != nil {
		return err
	}

	redacted, changed, err := scrubCast(cast)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err = zw.Write(redacted); err != nil {
		return fmt.Errorf("gzip scrubbed cast: %w", err)
	}
	if err = zw.Close(); err != nil {
		return fmt.Errorf("finish gzip scrubbed cast: %w", err)
	}

	w, err := s.cfg.Storage.CreateWriter(ctx, storage.RecordingPath(workspaceID, recordingID),
		storage.StoreOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("open scrubbed recording object: %w", err)
	}
	// CreateWriter commits on Close and stages through a temp object, so a
	// failure here never damages the original recording.
	payload := gz.Bytes()
	for len(payload) > 0 {
		n := min(scrubChunk, len(payload))
		framed, encErr := s.frameEncrypted(payload[:n])
		if encErr != nil {
			_ = w.Close()
			return fmt.Errorf("encrypt scrubbed chunk: %w", encErr)
		}
		if _, err = w.Write(framed); err != nil {
			_ = w.Close()
			return fmt.Errorf("write scrubbed recording object: %w", err)
		}
		payload = payload[n:]
	}
	if err = w.Close(); err != nil {
		return fmt.Errorf("commit scrubbed recording object: %w", err)
	}

	slog.Info("recording scrubbed", "recording_id", recordingID)
	return nil
}

// readRecordingCast returns the decompressed asciicast text of a recording.
func (s *RecordingService) readRecordingCast(ctx context.Context, workspaceID, recordingID string) ([]byte, error) {
	fr, err := s.openFrameReader(ctx, storage.RecordingPath(workspaceID, recordingID))
	if err != nil {
		return nil, err
	}
	defer func() { _ = fr.Close() }()

	gz, err := gzip.NewReader(fr)
	if err != nil {
		return nil, fmt.Errorf("open recording gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	cast, err := io.ReadAll(io.LimitReader(gz, maxScrubBytes+1))
	if err != nil {
		return nil, fmt.Errorf("decompress recording cast: %w", err)
	}
	if len(cast) > maxScrubBytes {
		return nil, fmt.Errorf("recording cast exceeds scrub limit of %d bytes", maxScrubBytes)
	}
	return cast, nil
}

// castEvent is one parsed event line whose stream participates in scrubbing.
type castEvent struct {
	line      int
	code      string
	interval  float64
	data      []byte
	redacted  []byte
	dataStart int
	dataEnd   int
}

// scrubCast redacts secrets across the cast and returns the rewritten text.
// Detection runs over each stream (output, input) concatenated back into the
// bytes the terminal produced, so secrets split across event boundaries are
// still caught, then the redactions are mapped back onto the events.
func scrubCast(cast []byte) ([]byte, bool, error) {
	det, err := scrubDetector()
	if err != nil {
		return nil, false, fmt.Errorf("load gitleaks config: %w", err)
	}

	lines := bytes.Split(cast, []byte("\n"))
	events := make([]castEvent, 0, len(lines))
	blobs := make(map[string][]byte)
	for i, line := range lines {
		if i == 0 {
			continue // header
		}
		ev, ok := parseCastEvent(line)
		if !ok {
			continue
		}
		ev.line = i
		ev.dataStart = len(blobs[ev.code])
		blobs[ev.code] = append(blobs[ev.code], ev.data...)
		ev.dataEnd = len(blobs[ev.code])
		events = append(events, ev)
	}

	changed := false
	for code, blob := range blobs {
		spans := secretSpans(blob, det)
		if len(spans) == 0 {
			continue
		}
		changed = true
		redactEvents(events, code, blob, spans)
	}
	if !changed {
		return cast, false, nil
	}

	ei := 0
	for i := 1; i < len(lines) && ei < len(events); i++ {
		ev := &events[ei]
		if ev.line != i {
			continue
		}
		ei++
		if bytes.Equal(ev.redacted, ev.data) {
			continue
		}
		lines[i], err = marshalCastEvent(ev.interval, ev.code, ev.redacted)
		if err != nil {
			return nil, false, fmt.Errorf("re-marshal event line %d: %w", i, err)
		}
	}
	return bytes.Join(lines, []byte("\n")), true, nil
}

// parseCastEvent decodes one asciicast event line. Only output and input
// events carry user-controlled data worth scrubbing.
func parseCastEvent(line []byte) (castEvent, bool) {
	var raw []json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil || len(raw) != 3 {
		return castEvent{}, false
	}
	var ev castEvent
	if json.Unmarshal(raw[0], &ev.interval) != nil {
		return castEvent{}, false
	}
	if json.Unmarshal(raw[1], &ev.code) != nil || (ev.code != "o" && ev.code != "i") {
		return castEvent{}, false
	}
	var data string
	if json.Unmarshal(raw[2], &data) != nil {
		return castEvent{}, false
	}
	ev.data = []byte(data)
	ev.redacted = ev.data
	return ev, true
}

// marshalCastEvent re-encodes one event line without HTML escaping, matching
// the daemon's writer so the cast stays readable.
func marshalCastEvent(interval float64, code string, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode([]any{interval, code, string(data)}); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// secretSpans returns the merged, sorted byte spans of detected secrets.
func secretSpans(blob []byte, det *detect.Detector) []span {
	var spans []span
	kws := keywordRe()
	for _, rule := range det.Config.Rules {
		if rule.Regex == nil {
			continue
		}
		if kws != nil && len(rule.Keywords) > 0 && !kws.Match(blob) {
			continue
		}
		for _, m := range rule.Regex.FindAllSubmatchIndex(blob, -1) {
			start, end := m[0], m[1]
			if rule.SecretGroup > 0 {
				start, end = m[2*rule.SecretGroup], m[2*rule.SecretGroup+1]
				if start < 0 {
					continue
				}
			}
			secret := blob[start:end]
			if rule.Entropy > 0 && shannonEntropy(secret) < rule.Entropy {
				continue
			}
			if allowlisted(rule, det.Config, secret) {
				continue
			}
			spans = append(spans, span{start, end})
		}
	}
	for _, p := range customPatterns {
		for _, m := range p.re.FindAllSubmatchIndex(blob, -1) {
			start, end := m[0], m[1]
			if p.group > 0 {
				start, end = m[2*p.group], m[2*p.group+1]
			}
			spans = append(spans, span{start, end})
		}
	}
	slices.SortFunc(spans, func(a, b span) int { return a.start - b.start })
	return mergeSpans(preferTightest(spans))
}

// preferTightest drops spans fully contained in a strictly larger one, so a
// key=value redaction keeps the key name readable when a wider rule matched
// the whole assignment. Huge span counts fall through to the plain merge.
func preferTightest(spans []span) []span {
	if len(spans) > 1000 {
		return spans
	}
	out := make([]span, 0, len(spans))
	for i, s := range spans {
		container := false
		for j, t := range spans {
			if j == i {
				continue
			}
			if s.start <= t.start && t.end <= s.end && len2(s) > len2(t) {
				container = true
				break
			}
		}
		if !container {
			out = append(out, s)
		}
	}
	return out
}

func len2(s span) int { return s.end - s.start }

// allowlisted reports whether a candidate secret matches a rule or global
// allowlist regex, which gitleaks uses to suppress known false positives.
func allowlisted(rule config.Rule, cfg config.Config, secret []byte) bool {
	for _, al := range rule.Allowlists {
		for _, re := range al.Regexes {
			if re.Match(secret) {
				return true
			}
		}
	}
	for _, al := range cfg.Allowlists {
		for _, re := range al.Regexes {
			if re.Match(secret) {
				return true
			}
		}
	}
	return false
}

// redactEvents maps blob-level spans onto each event of one stream.
func redactEvents(events []castEvent, code string, blob []byte, spans []span) {
	for i := range events {
		ev := &events[i]
		if ev.code != code {
			continue
		}
		ev.redacted = applySpans(blob, ev.dataStart, ev.dataEnd, spans)
	}
}

// applySpans rebuilds blob[start:end] with intersecting spans masked.
func applySpans(blob []byte, start, end int, spans []span) []byte {
	seg := blob[start:end]
	i := sort.Search(len(spans), func(i int) bool { return spans[i].end > start })
	out := make([]byte, 0, len(seg))
	pos := 0
	for ; i < len(spans) && spans[i].start < end; i++ {
		lo := max(spans[i].start-start, 0)
		hi := min(spans[i].end-start, len(seg))
		if hi <= lo {
			continue
		}
		out = append(out, seg[pos:lo]...)
		out = append(out, redaction...)
		pos = hi
	}
	return append(out, seg[pos:]...)
}

func mergeSpans(spans []span) []span {
	out := make([]span, 0, len(spans))
	for _, s := range spans {
		if len(out) > 0 && s.start <= out[len(out)-1].end {
			out[len(out)-1].end = max(out[len(out)-1].end, s.end)
			continue
		}
		out = append(out, s)
	}
	return out
}

func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var e float64
	for _, n := range counts {
		if n == 0 {
			continue
		}
		p := float64(n) / float64(len(b))
		e -= p * math.Log2(p)
	}
	return e
}
