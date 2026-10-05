package recording

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/db"
)

const (
	scrubTimeout  = 10 * time.Minute
	maxScrubBytes = 64 << 20
	scrubChunk    = 64 << 10
	redaction     = "<redacted>"
)

// span is half-open.
type span struct {
	start, end int
}

// ScrubRecording is best effort and never retried. A failure leaves the
// recording as uploaded.
func (s *Service) ScrubRecording(rec *db.Recording) {
	ctx, cancel := context.WithTimeout(context.Background(), scrubTimeout)
	go func() {
		defer cancel()
		if err := s.scrub(ctx, rec); err != nil {
			slog.Error("scrub recording failed, recording kept as uploaded",
				"recording_id", rec.ID, "workspace_id", rec.WorkspaceID, "error", err)
			// Audit it, a failed scrub leaves secrets in the stored object.
			if s.events != nil {
				event := &audit.Event{
					Timestamp:   time.Now().UTC(),
					WorkspaceID: rec.WorkspaceID,
					Action:      "RecordingScrubFailed",
					ActorKind:   "system",
					Target:      rec.ID,
					Details: map[string]any{
						"daemon_id": rec.DaemonID,
						"error":     err.Error(),
					},
				}
				// The scrub ctx may have expired, that is one way to get here.
				appendCtx, appendCancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
				defer appendCancel()
				if appendErr := s.events.Append(appendCtx, event); appendErr != nil {
					slog.Warn("failed to write scrub failure audit log",
						"recording_id", rec.ID, "error", appendErr)
				}
			}
		}
	}()
}

func (s *Service) scrub(ctx context.Context, rec *db.Recording) error {
	cast, err := s.readRecordingCast(ctx, rec)
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

	wctx, abort := context.WithCancel(ctx)
	defer abort()
	w, err := s.NewWriter(wctx, rec)
	if err != nil {
		return err
	}
	for chunk := range slices.Chunk(gz.Bytes(), scrubChunk) {
		if err = w.WriteChunk(chunk); err != nil {
			break
		}
	}
	if err == nil {
		err = w.writeFrame(frameEnd, nil)
	}
	if err != nil {
		// The blob writer commits on Close unless its ctx is canceled, and
		// a partial object would replace the original.
		abort()
		_ = w.w.Close()
		return fmt.Errorf("write scrubbed recording object: %w", err)
	}
	if err = w.w.Close(); err != nil {
		return fmt.Errorf("commit scrubbed recording object: %w", err)
	}

	slog.Info("recording scrubbed", "recording_id", rec.ID)
	return nil
}

func (s *Service) readRecordingCast(ctx context.Context, rec *db.Recording) ([]byte, error) {
	fr, err := s.OpenReader(ctx, rec)
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

type castEvent struct {
	line      int
	code      string
	interval  float64
	data      []byte
	redacted  []byte
	dataStart int
	dataEnd   int
}

// scrubCast detects over each stream concatenated, so secrets split across
// events are still caught, then maps the redactions back onto the events.
func scrubCast(cast []byte) ([]byte, bool, error) {
	rules, err := scrubRules()
	if err != nil {
		return nil, false, err
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
		spans := secretSpans(blob, rules)
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

// parseCastEvent only keeps output and input events.
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

// marshalCastEvent skips HTML escaping to match the daemon's writer.
func marshalCastEvent(interval float64, code string, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode([]any{interval, code, string(data)}); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func secretSpans(blob []byte, rules *scrubRuleSet) []span {
	var spans []span
	hasKeyword := rules.keywords.Match(blob)
	for _, rule := range rules.rules {
		if len(rule.keywords) > 0 && !hasKeyword {
			continue
		}
		for _, m := range rule.regex.FindAllSubmatchIndex(blob, -1) {
			start, end := secretSpan(rule, m)
			if start < 0 || start >= end {
				continue
			}
			secret := blob[start:end]
			if rule.entropy > 0 && shannonEntropy(secret) < rule.entropy {
				continue
			}
			if allowlisted(rule, rules, blob[m[0]:m[1]], secret) {
				continue
			}
			spans = append(spans, span{start, end})
		}
	}

	slices.SortFunc(spans, func(a, b span) int { return a.start - b.start })
	return mergeSpans(preferTightest(spans))
}

// secretSpan narrows the match so assignment keys stay readable.
func secretSpan(rule scrubRule, m []int) (int, int) {
	if g := rule.secretGroup; g > 0 && 2*g+1 < len(m) && m[2*g] >= 0 {
		return m[2*g], m[2*g+1]
	}
	for g := 1; 2*g+1 < len(m); g++ {
		if m[2*g] >= 0 {
			return m[2*g], m[2*g+1]
		}
	}
	return m[0], m[1]
}

// preferTightest drops spans that contain a smaller one, so a key=value
// redaction keeps the key readable. Huge span counts skip this.
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

// allowlisted approximates "line" targets with the match.
func allowlisted(rule scrubRule, rules *scrubRuleSet, match, secret []byte) bool {
	for _, al := range slices.Concat(rule.allowlists, rules.allowlists) {
		for _, re := range al.regexes {
			target := secret
			if al.target == "match" || al.target == "line" {
				target = match
			}
			if re.Match(target) {
				return true
			}
		}
	}
	return false
}

func redactEvents(events []castEvent, code string, blob []byte, spans []span) {
	for i := range events {
		ev := &events[i]
		if ev.code != code {
			continue
		}
		ev.redacted = applySpans(blob, ev.dataStart, ev.dataEnd, spans)
	}
}

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
