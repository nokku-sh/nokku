package recording

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/nokku-sh/nokku/core/internal/audit"
	"github.com/nokku-sh/nokku/core/internal/db"
)

const (
	scrubTimeout = 10 * time.Minute
	// A stream is searched a window at a time. The overlap is searched twice, so a shorter secret is seen whole.
	scrubWindow  = 8 << 20
	scrubOverlap = 64 << 10
	scrubChunk   = 64 << 10
	redaction    = "<redacted>"
	// A screen shows a secret in pieces. A piece this long of a found secret is taken out wherever it stands.
	secretPiece = 12
	// A secret shorter than a piece is only taken out whole, and not at all under this length.
	shortSecret = 8
	// maxSecretPieces bounds what a cast full of secrets can make the scrub hold.
	maxSecretPieces = 1 << 20
)

// span is half-open.
type span struct {
	start, end int
}

// ScrubRecording is best effort, detached and never retried. A failure leaves the recording as uploaded.
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

// scrub reads the stored cast three times: two passes find the secrets, the third writes it back redacted.
func (s *Service) scrub(ctx context.Context, rec *db.Recording) error {
	rules, err := scrubRules()
	if err != nil {
		return err
	}
	spans, err := locateSecrets(func() (io.ReadCloser, error) { return s.openCast(ctx, rec) },
		rules, scrubWindow, scrubOverlap)
	if err != nil {
		return err
	}
	if len(spans) == 0 {
		return nil
	}

	// The store swaps the new object in on commit, so the old one can be read while the new one is written.
	cast, err := s.openCast(ctx, rec)
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
		// The blob writer commits on Close unless its ctx is canceled, and a partial object would replace the original.
		abort()
		_ = w.w.Close()
		return fmt.Errorf("write scrubbed recording object: %w", err)
	}
	if err = w.w.Close(); err != nil {
		return fmt.Errorf("commit scrubbed recording object: %w", err)
	}
	return nil
}

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

// cutCast ends after the last whole line. The line the cut ran through goes, it may hold half a secret.
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

// locateSecrets runs the rules, then looks for what they found where no rule knows it: cut off or without its name.
func locateSecrets(
	open func() (io.ReadCloser, error),
	rules *scrubRuleSet,
	window, overlap int,
) (map[string][]span, error) {
	pass := func(find func(text []byte) []span) (map[string][]span, error) {
		cast, err := open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = cast.Close() }()
		found, err := findSecrets(cast, find, window, overlap)
		if err != nil {
			return nil, fmt.Errorf("search recording cast: %w", err)
		}
		return found, nil
	}

	seen := &seenSecrets{pieces: map[string]struct{}{}, short: map[string]struct{}{}}
	spans, err := pass(func(text []byte) []span {
		found := secretSpans(text, rules)
		for _, sp := range found {
			seen.add(text[sp.start:sp.end])
		}
		return found
	})
	if err != nil || len(spans) == 0 {
		return nil, err
	}
	again, err := pass(seen.spans)
	if err != nil {
		return nil, err
	}
	for code, more := range again {
		spans[code] = append(spans[code], more...)
		slices.SortFunc(spans[code], func(a, b span) int { return a.start - b.start })
		spans[code] = mergeSpans(spans[code])
	}
	return spans, nil
}

// findSecrets runs find a window at a time, so a secret split across events is still caught.
func findSecrets(
	cast io.Reader,
	find func(text []byte) []span,
	window, overlap int,
) (map[string][]span, error) {
	streams := map[string]*streamText{}
	width := 0
	for line, err := range castLines(cast) {
		if err != nil {
			return nil, err
		}
		ev, ok := parseCastEvent(line)
		if !ok {
			if cols, ok := castWidth(line); ok {
				width = cols
				if out := streams["o"]; out != nil {
					out.scan.cols = cols
				}
			}
			continue
		}
		st := streams[ev.code]
		if st == nil {
			st = &streamText{}
			// Only the output has a cursor.
			if ev.code == "o" {
				st.scan.cols = width
			}
			streams[ev.code] = st
		}
		st.write(ev.data)
		if len(st.buf) >= window {
			st.search(find)
			st.keep(overlap)
		}
	}

	found := map[string][]span{}
	for code, st := range streams {
		st.search(find)
		if len(st.spans) == 0 {
			continue
		}
		// The overlap is searched twice, its secrets come up twice.
		slices.SortFunc(st.spans, func(a, b span) int { return a.start - b.start })
		found[code] = mergeSpans(st.spans)
	}
	return found, nil
}

// seenSecrets is what the rules found, cut into the pieces a screen may show of it.
type seenSecrets struct {
	pieces map[string]struct{}
	short  map[string]struct{}
}

func (k *seenSecrets) add(secret []byte) {
	// A secret is one word. A match with blanks has words around it, and those would be taken out everywhere.
	if bytes.ContainsAny(secret, " \t\r\n") || len(secret) < shortSecret ||
		shannonEntropy(secret) < 3 || len(k.pieces) >= maxSecretPieces {
		return
	}
	if len(secret) < secretPiece {
		k.short[string(secret)] = struct{}{}
		return
	}
	for i := range len(secret) - secretPiece + 1 {
		k.pieces[string(secret[i:i+secretPiece])] = struct{}{}
	}
}

func (k *seenSecrets) spans(text []byte) []span {
	var out []span
	take := func(start, end int) {
		if n := len(out); n > 0 && start <= out[n-1].end {
			out[n-1].end = max(out[n-1].end, end)
			return
		}
		out = append(out, span{start, end})
	}
	for i := range text {
		if end := i + secretPiece; end <= len(text) {
			if _, ok := k.pieces[string(text[i:end])]; ok {
				take(i, end)
			}
		}
		for end := i + shortSecret; len(k.short) > 0 && end < i+secretPiece && end <= len(text); end++ {
			if _, ok := k.short[string(text[i:end])]; ok {
				take(i, end)
			}
		}
	}
	return out
}

// rewriteCast is the last pass. Lines without secrets are copied byte for byte.
func rewriteCast(cast io.Reader, out io.Writer, spans map[string][]span) error {
	streams := map[string]*redactor{}
	for line, err := range castLines(cast) {
		if err != nil {
			return err
		}
		if ev, ok := parseCastEvent(line); ok {
			st := streams[ev.code]
			if st == nil {
				st = &redactor{spans: spans[ev.code]}
				streams[ev.code] = st
			}
			if redacted := st.apply(ev.data); !bytes.Equal(redacted, ev.data) {
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

// castWidth reads the terminal width from the header of a cast, or from a resize event.
func castWidth(line []byte) (int, bool) {
	var header struct {
		Term struct {
			Cols int `json:"cols"`
		} `json:"term"`
		Width int `json:"width"`
	}
	if json.Unmarshal(line, &header) == nil {
		cols := cmp.Or(header.Term.Cols, header.Width)
		return cols, cols > 0
	}
	var raw []json.RawMessage
	var code, size string
	if json.Unmarshal(line, &raw) != nil || len(raw) != 3 ||
		json.Unmarshal(raw[1], &code) != nil || code != "r" || json.Unmarshal(raw[2], &size) != nil {
		return 0, false
	}
	width, _, _ := strings.Cut(size, "x")
	cols, err := strconv.Atoi(width)
	return cols, err == nil && cols > 0
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

	spans = append(spans, keyBlockSpans(blob)...)

	// Every match counts, a small one inside a large one is no reason to drop the large one.
	slices.SortFunc(spans, func(a, b span) int { return a.start - b.start })
	return mergeSpans(spans)
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

// keyBlockGap is how much may stand between two lines of a private key: a prompt, a line number, a redrawn line.
const keyBlockGap = 512

var (
	keyBlockMark = regexp.MustCompile(`-----(BEGIN|END)[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----`)
	// A line of a key is 64 characters or more. Anything much shorter is as likely a path.
	keyBlockLine = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	// The last line is as short as it comes out. Further from the END line it has to be long enough not to be a word.
	keyBlockLast = regexp.MustCompile(`([A-Za-z0-9+/=]{4,})[^A-Za-z0-9+/=]{0,12}(?:[0-9]{1,6}[^A-Za-z0-9+/=]{1,12})?$`)
	keyBlockRest = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
)

// keyBlockSpans takes only the lines of the key, not BEGIN to END. An editor draws other lines in between.
func keyBlockSpans(blob []byte) []span {
	marks := keyBlockMark.FindAllSubmatchIndex(blob, -1)
	if len(marks) == 0 {
		return nil
	}
	lines := keyBlockLine.FindAllIndex(blob, -1)
	var spans []span
	for i, mark := range marks {
		spans = append(spans, span{mark[0], mark[1]})
		if blob[mark[2]] == 'B' {
			limit := len(blob)
			if i+1 < len(marks) {
				limit = marks[i+1][0]
			}
			at := mark[1]
			next, _ := slices.BinarySearchFunc(lines, at, func(line []int, at int) int { return line[0] - at })
			for _, line := range lines[next:] {
				if line[1] > limit || line[0]-at > keyBlockGap {
					break
				}
				spans = append(spans, span{line[0], line[1]})
				at = line[1]
			}
			// The last line, when an editor draws it some time after the one before it.
			if at > mark[1] {
				spans = append(spans, keyBlockEnd(blob, at, min(len(blob), at+keyBlockGap))...)
			}
			continue
		}

		limit := 0
		if i > 0 {
			limit = marks[i-1][1]
		}
		at := mark[0]
		from := max(limit, at-keyBlockGap)
		if last := keyBlockLast.FindSubmatchIndex(blob[from:at]); last != nil {
			spans = append(spans, span{from + last[2], from + last[3]})
		}
		// A scrolling editor redraws its top line between the last key line and END, so no other mark bounds this.
		spans = append(spans, keyBlockEnd(blob, max(0, at-keyBlockGap), at)...)
		before, _ := slices.BinarySearchFunc(lines, at, func(line []int, at int) int { return line[0] - at })
		for _, line := range slices.Backward(lines[:before]) {
			if line[0] < limit || at-line[1] > keyBlockGap {
				break
			}
			spans = append(spans, span{line[0], line[1]})
			at = line[0]
		}
	}
	return spans
}

// keyBlockEnd finds the short last line of a key. Only what has digits and both cases counts, a path has not.
func keyBlockEnd(blob []byte, from, to int) []span {
	var spans []span
	for _, rest := range keyBlockRest.FindAllIndex(blob[from:to], -1) {
		word := blob[from+rest[0] : from+rest[1]]
		if bytes.ContainsAny(word, "0123456789") && bytes.ContainsFunc(word, unicode.IsUpper) &&
			bytes.ContainsFunc(word, unicode.IsLower) {
			spans = append(spans, span{from + rest[0], from + rest[1]})
		}
	}
	return spans
}

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
