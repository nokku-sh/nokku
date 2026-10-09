package recording

import (
	"bytes"
	"slices"
)

// A terminal stream is text with control sequences in it. A color change in
// the middle of a secret, or right after it, is nothing a viewer sees, but it
// keeps a rule from matching. So the rules search the text alone, and what
// they find is taken out of the stream around the sequences.

// wrapLookback is how much of a wrapped line is searched once more. A
// secret with its name in front is shorter.
const wrapLookback = 512

type termClass uint8

const (
	// termText shows on screen.
	termText termClass = iota
	// termWhite is a line break or a tab, text to the rules and kept by a
	// redaction.
	termWhite
	// termGlue takes no room: a color change, a bell. Text goes on after it.
	termGlue
	// termBreak moves the cursor. Text after it does not continue the text
	// before it.
	termBreak
	// termBack is a backspace.
	termBack
)

type termState uint8

const (
	termGround termState = iota
	termEscape
	termEscapeMid
	termCSI
	termString
	termStringEscape
)

// termScanner classes the bytes of one stream, in order.
type termScanner struct {
	state termState
}

func (s *termScanner) next(b byte) termClass {
	switch s.state {
	case termGround:
	case termEscape:
		return s.escape(b)
	case termEscapeMid:
		switch {
		case b < 0x20:
			return s.control(b)
		case b >= 0x30:
			s.state = termGround
		}
		return termGlue
	case termCSI:
		switch {
		case b < 0x20:
			return s.control(b)
		case b < 0x40 || b == 0x7f:
			return termGlue
		case b >= 0x80:
			s.state = termGround
			return termText
		}
		s.state = termGround
		// A color change or an erase leaves the cursor where it is, the
		// text goes on. grep puts both in the middle of a line.
		if b == 'm' || b == 'K' || b == 'J' {
			return termGlue
		}
		return termBreak
	case termString:
		// A window title or a link target is text too, it is in the cast.
		switch {
		case b == 0x1b:
			s.state = termStringEscape
			return termGlue
		case b == 0x07, b == 0x18, b == 0x1a:
			s.state = termGround
			return termBreak
		case b < 0x20:
			return termGlue
		}
		return termText
	case termStringEscape:
		if b == '\\' {
			s.state = termGround
			return termBreak
		}
		return s.escape(b)
	}
	return s.control(b)
}

// escape takes the byte after an ESC.
func (s *termScanner) escape(b byte) termClass {
	switch {
	case b == 0x1b:
		s.state = termEscape
		return termGlue
	case b < 0x20:
		return s.control(b)
	case b == '[':
		s.state = termCSI
		return termGlue
	case b == ']', b == 'P', b == '_', b == '^', b == 'X':
		s.state = termString
		return termBreak
	case b < 0x30:
		s.state = termEscapeMid
		return termGlue
	}
	s.state = termGround
	// Keypad modes move nothing, the rest saves, restores or scrolls.
	if b == '=' || b == '>' || b == '\\' || b >= 0x7f {
		return termGlue
	}
	return termBreak
}

// control takes a byte outside a sequence. A terminal runs a control
// character in the middle of a sequence and goes on with the sequence.
func (s *termScanner) control(b byte) termClass {
	switch {
	case b == 0x1b:
		s.state = termEscape
		return termGlue
	case b == '\r', b == '\n', b == '\t':
		return termWhite
	case b == '\b':
		return termBack
	case b == 0x0b, b == 0x0c:
		return termBreak
	case b < 0x20, b == 0x7f:
		return termGlue
	}
	return termText
}

// textRun says where text sits in its stream: the bytes from offset text on,
// up to the next run, are the stream bytes from offset raw on.
type textRun struct {
	text, raw int
}

// streamText is the text of one stream, the part not searched to its end yet.
type streamText struct {
	scan termScanner
	buf  []byte
	// base is the text offset of buf[0], raw the stream offset of the next
	// byte.
	base, raw int
	runs      []textRun
	// gap is set after a cursor move. The next text starts on a line of its
	// own, so the rules do not read two places of the screen as one word.
	gap bool
	// wraps are the text offsets where a pager wrapped a line.
	wraps []int
	spans []span
}

func (t *streamText) write(data []byte) {
	for _, b := range data {
		switch t.scan.next(b) {
		case termText:
			if n := len(t.buf); t.gap && n > 0 && !isBlank(t.buf[n-1]) {
				// The break stands for the sequence right before this byte.
				t.push('\n', t.raw-1)
			}
			t.gap = false
			t.push(b, t.raw)
		case termWhite:
			t.gap = false
			t.push(b, t.raw)
		case termBreak:
			t.gap = true
		case termBack:
			// A pager wraps a long line with a blank and a backspace, and
			// the line goes on over the blank.
			if n := len(t.buf); n > 0 && t.buf[n-1] == ' ' && t.rawOf(t.base+n-1) == t.raw-1 {
				t.pop()
				t.wraps = append(t.wraps, t.base+len(t.buf))
			} else {
				t.gap = true
			}
		case termGlue:
		}
		t.raw++
	}
}

func (t *streamText) push(b byte, raw int) {
	at := t.base + len(t.buf)
	if n := len(t.runs); n == 0 || t.runs[n-1].raw+at-t.runs[n-1].text != raw {
		t.runs = append(t.runs, textRun{at, raw})
	}
	t.buf = append(t.buf, b)
}

func (t *streamText) pop() {
	t.buf = t.buf[:len(t.buf)-1]
	if n := len(t.runs); t.runs[n-1].text == t.base+len(t.buf) {
		t.runs = t.runs[:n-1]
	}
}

// rawOf is the stream offset of the text byte at offset at.
func (t *streamText) rawOf(at int) int {
	i, found := slices.BinarySearchFunc(t.runs, at, func(r textRun, at int) int { return r.text - at })
	if !found {
		i--
	}
	return t.runs[i].raw + at - t.runs[i].text
}

// search runs find over the text and keeps what it finds as stream offsets.
func (t *streamText) search(find func(text []byte) []span) {
	take := func(start, end int) {
		t.spans = append(t.spans, span{t.rawOf(t.base + start), t.rawOf(t.base+end-1) + 1})
	}
	for _, sp := range find(t.buf) {
		take(sp.start, sp.end)
	}
	if len(t.wraps) == 0 {
		return
	}

	// A page can end at a wrap. The rest of the line is not on screen then,
	// the prompt of the pager follows, and a secret that runs into the
	// prompt matches no rule. So each wrapped line is searched once more, as
	// far as the wrap and as a line of its own.
	type head struct {
		// at is where the head starts in lines, text where it starts in buf.
		at, text, size int
	}
	var lines []byte
	heads := make([]head, 0, len(t.wraps))
	for _, wrap := range t.wraps {
		end := wrap - t.base
		start := max(0, end-wrapLookback)
		if i := bytes.LastIndexAny(t.buf[start:end], "\r\n"); i >= 0 {
			start += i + 1
		}
		heads = append(heads, head{len(lines), start, end - start})
		lines = append(lines, t.buf[start:end]...)
		lines = append(lines, '\n')
	}
	for _, sp := range find(lines) {
		i, found := slices.BinarySearchFunc(heads, sp.start, func(h head, at int) int { return h.at - at })
		if !found {
			i--
		}
		h := heads[i]
		// A match that runs on into the next head ends with this one.
		if start, end := sp.start-h.at, min(sp.end-h.at, h.size); start < end {
			take(h.text+start, h.text+end)
		}
	}
}

// keep drops all but the last n bytes of text.
func (t *streamText) keep(n int) {
	cut := len(t.buf) - n
	t.base += cut
	t.buf = append(t.buf[:0], t.buf[cut:]...)
	first, found := slices.BinarySearchFunc(t.runs, t.base, func(r textRun, at int) int { return r.text - at })
	if !found {
		first--
	}
	t.runs = append(t.runs[:0], t.runs[first:]...)
	t.wraps = slices.DeleteFunc(t.wraps, func(wrap int) bool { return wrap <= t.base })
}

func isBlank(b byte) bool {
	return b == ' ' || b == '\n' || b == '\r' || b == '\t'
}

// redactor takes the secrets out of one stream, event by event.
type redactor struct {
	scan  termScanner
	spans []span
	// next is the first span that ends after pos, the stream offset of the
	// next byte.
	next, pos int
	// marked says this line of the secret shows the redaction already.
	marked bool
}

// apply returns data with the text of the secrets in it replaced. Sequences
// and line breaks inside a secret stay, the screen keeps its layout.
func (r *redactor) apply(data []byte) []byte {
	r.skip()
	if end := r.pos + len(data); r.next == len(r.spans) || r.spans[r.next].start >= end {
		for _, b := range data {
			r.scan.next(b)
		}
		r.pos = end
		return data
	}

	out := make([]byte, 0, len(data))
	for _, b := range data {
		class := r.scan.next(b)
		r.skip()
		inside := r.next < len(r.spans) && r.spans[r.next].start <= r.pos
		r.pos++
		switch {
		case !inside:
		case class == termText:
			if !r.marked {
				out = append(out, redaction...)
				r.marked = true
			}
			continue
		case class != termGlue && b != '\t':
			r.marked = false
		}
		out = append(out, b)
	}
	return out
}

// skip leaves the spans that end before pos behind.
func (r *redactor) skip() {
	for r.next < len(r.spans) && r.spans[r.next].end <= r.pos {
		r.next++
		r.marked = false
	}
}
