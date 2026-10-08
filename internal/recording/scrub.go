package recording

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/nokku-sh/nokku/internal/audit"
	"github.com/nokku-sh/nokku/internal/db"
)

const (
	scrubTimeout = 10 * time.Minute
	// A stream is searched one window at a time, so a cast of any size is
	// scrubbed in the same memory. The end of a window is searched again
	// with the next, a secret shorter than the overlap is always seen whole.
	scrubWindow  = 8 << 20
	scrubOverlap = 64 << 10
	scrubChunk   = 64 << 10
	redaction    = "<redacted>"
)

// span is half-open.
type span struct {
	start, end int
}

// ScrubRecording is best effort and never retried. A failure leaves the
// recording as uploaded. It runs detached, the upload does not wait for it.
// The part of a cut upload is scrubbed like a whole one, it may be all there
// ever is.
func (s *Service) ScrubRecording(ctx context.Context, rec *db.Recording) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), scrubTimeout)
	run := &scrubRun{cancel: cancel, done: make(chan struct{})}
	s.mu.Lock()
	// An upload that writes the object right now scrubs it when it ends.
	if s.uploads[rec.ID] > 0 {
		s.mu.Unlock()
		cancel()
		return
	}
	earlier := s.scrubs[rec.ID]
	s.scrubs[rec.ID] = run
	s.mu.Unlock()

	go func() {
		defer func() {
			cancel()
			s.mu.Lock()
			if s.scrubs[rec.ID] == run {
				delete(s.scrubs, rec.ID)
			}
			s.mu.Unlock()
			close(run.done)
		}()
		if earlier != nil {
			earlier.cancel()
			<-earlier.done
		}
		err := s.scrub(ctx, rec)
		// Stopped for a new upload, which scrubs what it stores.
		if err == nil || errors.Is(ctx.Err(), context.Canceled) {
			return
		}
		slog.Error("scrub recording failed, recording kept as uploaded",
			"recording_id", rec.ID, "workspace_id", rec.WorkspaceID, "error", err)
		// Audit it, a failed scrub leaves secrets in the stored object.
		if s.events == nil {
			return
		}
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
	}()
}

// scrub reads the stored cast twice. The first pass finds the secrets, the
// second writes the cast back with them redacted. Nothing is held whole.
func (s *Service) scrub(ctx context.Context, rec *db.Recording) error {
	rules, err := scrubRules()
	if err != nil {
		return err
	}
	cast, err := s.openCast(ctx, rec)
	if err != nil {
		return err
	}
	spans, err := findSecrets(cast, rules, scrubWindow, scrubOverlap)
	_ = cast.Close()
	if err != nil {
		return fmt.Errorf("search recording cast: %w", err)
	}
	if len(spans) == 0 {
		return nil
	}

	// The store swaps the new object in on commit, so the old one can be
	// read while the new one is written.
	cast, err = s.openCast(ctx, rec)
	if err != nil {
		return err
	}
	defer func() { _ = cast.Close() }()

	wctx, abort := context.WithCancel(ctx)
	defer abort()
	w, err := s.NewWriter(wctx, rec)
	if err != nil {
		return err
	}
	frames := bufio.NewWriterSize(w, scrubChunk)
	zw := gzip.NewWriter(frames)
	err = rewriteCast(cast, zw, spans)
	if err == nil {
		err = zw.Close()
	}
	if err == nil {
		err = frames.Flush()
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
	return nil
}

// openCast opens the stored recording as its plain cast.
func (s *Service) openCast(ctx context.Context, rec *db.Recording) (io.ReadCloser, error) {
	fr, err := s.OpenReader(ctx, rec)
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(fr)
	cut := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
	if err != nil && (rec.Complete || !cut) {
		_ = fr.Close()
		return nil, fmt.Errorf("open recording gzip: %w", err)
	}
	var cast io.Reader = gz
	switch {
	case err != nil:
		// The upload broke off inside the gzip header, there is no cast yet.
		cast = bytes.NewReader(nil)
	case !rec.Complete:
		cast = &cutCast{r: bufio.NewReaderSize(gz, scrubChunk)}
	}
	return struct {
		io.Reader
		io.Closer
	}{cast, fr}, nil
}

// cutCast reads the cast of an upload that broke off. It ends after the last
// whole line. The line the cut ran through goes, it may hold half a secret.
type cutCast struct {
	r    *bufio.Reader
	line []byte
}

func (c *cutCast) Read(p []byte) (int, error) {
	for len(c.line) == 0 {
		line, err := c.r.ReadBytes('\n')
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, io.EOF
		}
		if err != nil {
			return 0, err
		}
		c.line = line
	}
	n := copy(p, c.line)
	c.line = c.line[n:]
	return n, nil
}

// castLines yields the lines of a cast, each with its line break.
func castLines(cast io.Reader) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		r := bufio.NewReaderSize(cast, scrubChunk)
		for {
			line, err := r.ReadBytes('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				yield(nil, fmt.Errorf("decompress recording cast: %w", err))
				return
			}
			if len(line) > 0 && !yield(line, nil) {
				return
			}
			if err != nil {
				return
			}
		}
	}
}

type castEvent struct {
	code     string
	interval float64
	data     []byte
}

// findSecrets is the first pass. It returns the secrets of each stream as
// offsets into that stream's data, all events of one kind put end to end, so
// a secret split across events is still caught.
func findSecrets(cast io.Reader, rules *scrubRuleSet, window, overlap int) (map[string][]span, error) {
	type stream struct {
		// buf is the part of the stream not searched to its end yet, base
		// is where it starts.
		buf   []byte
		base  int
		spans []span
	}
	streams := map[string]*stream{}
	search := func(st *stream) {
		for _, sp := range secretSpans(st.buf, rules) {
			st.spans = append(st.spans, span{st.base + sp.start, st.base + sp.end})
		}
	}
	for line, err := range castLines(cast) {
		if err != nil {
			return nil, err
		}
		ev, ok := parseCastEvent(line)
		if !ok {
			continue
		}
		st := streams[ev.code]
		if st == nil {
			st = &stream{}
			streams[ev.code] = st
		}
		st.buf = append(st.buf, ev.data...)
		if len(st.buf) >= window {
			search(st)
			st.base += len(st.buf) - overlap
			st.buf = append(st.buf[:0], st.buf[len(st.buf)-overlap:]...)
		}
	}

	found := map[string][]span{}
	for code, st := range streams {
		search(st)
		if len(st.spans) == 0 {
			continue
		}
		// The overlap is searched twice, its secrets come up twice.
		slices.SortFunc(st.spans, func(a, b span) int { return a.start - b.start })
		found[code] = mergeSpans(st.spans)
	}
	return found, nil
}

// rewriteCast is the second pass. It copies cast to out with the secrets
// redacted, every other line byte for byte.
func rewriteCast(cast io.Reader, out io.Writer, spans map[string][]span) error {
	offset := map[string]int{}
	for line, err := range castLines(cast) {
		if err != nil {
			return err
		}
		if ev, ok := parseCastEvent(line); ok {
			start := offset[ev.code]
			offset[ev.code] = start + len(ev.data)
			if redacted := applySpans(ev.data, start, spans[ev.code]); !bytes.Equal(redacted, ev.data) {
				marshaled, err := marshalCastEvent(ev.interval, ev.code, redacted)
				if err != nil {
					return fmt.Errorf("re-marshal event: %w", err)
				}
				if bytes.HasSuffix(line, []byte("\n")) {
					marshaled = append(marshaled, '\n')
				}
				line = marshaled
			}
		}
		if _, err := out.Write(line); err != nil {
			return err
		}
	}
	return nil
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

// applySpans redacts the secrets that reach into seg, the data of one event
// that starts at offset start of its stream.
func applySpans(seg []byte, start int, spans []span) []byte {
	end := start + len(seg)
	i := sort.Search(len(spans), func(i int) bool { return spans[i].end > start })
	if i == len(spans) || spans[i].start >= end {
		return seg
	}
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
