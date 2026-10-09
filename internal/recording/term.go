package recording

import (
	"bytes"
	"slices"
)

// A color change inside a secret keeps a rule from matching, so the rules search the text without the sequences.

// wrapLookback is how much of a wrapped line is searched once more. A secret with its name in front is shorter.
const wrapLookback = 512

type termClass uint8

const (
	// termText shows on screen.
	termText termClass = iota
	// termWhite is a line break or a tab, text to the rules and kept by a redaction.
	termWhite
	// termGlue takes no room: a color change, a bell. Text goes on after it.
	termGlue
	// termBreak moves the cursor. Text after it does not continue the text before it.
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

// termScanner classes the bytes of one stream and follows the cursor far enough to tell where a line wrapped.
type termScanner struct {
	state termState
	// cols is the width of the terminal, 0 when it is not known. Nothing is a wrap then.
	cols int
	// row and col are where the cursor is. Scrolling is not followed, the row only tells the next row from any other.
	row, col int
	// printed says the byte just read went on screen, at printedRow and printedCol.
	printed                bool
	printedRow, printedCol int
	// The first two parameters of the sequence being read.
	args    [2]int
	arg     int
	private bool
}

// far is a row no cursor is next to. It stands for a position that got lost.
const far = 1 << 20

// atEdge says the last character filled its row to the right edge.
func (s *termScanner) atEdge() bool {
	return s.cols > 0 && s.col >= s.cols
}

func (s *termScanner) next(b byte) termClass {
	s.printed = false
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
		case b >= '0' && b <= '9':
			if s.arg < len(s.args) && s.args[s.arg] < far {
				s.args[s.arg] = s.args[s.arg]*10 + int(b-'0')
			}
			return termGlue
		case b == ';':
			s.arg++
			return termGlue
		case b >= '<' && b <= '?':
			s.private = true
			return termGlue
		case b < 0x40 || b == 0x7f:
			return termGlue
		case b >= 0x80:
			s.state = termGround
			return termText
		}
		s.state = termGround
		// A color change or an erase leaves the cursor where it is. grep puts both in the middle of a line.
		if b == 'm' || b == 'K' || b == 'J' {
			return termGlue
		}
		s.move(b)
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
		s.args, s.arg, s.private = [2]int{}, 0, false
		return termGlue
	case b == ']', b == 'P', b == '_', b == '^', b == 'X':
		s.state = termString
		return termBreak
	case b < 0x30:
		s.state = termEscapeMid
		return termGlue
	}
	s.state = termGround
	switch b {
	case 'D':
		s.row++
	case 'E':
		s.row, s.col = s.row+1, 0
	case 'M':
		s.row--
	case '7':
	case '=', '>', '\\':
		// Keypad modes move nothing.
		return termGlue
	default:
		if b >= 0x7f {
			return termGlue
		}
		s.row = far
	}
	return termBreak
}

// move takes the last byte of a sequence that may move the cursor.
func (s *termScanner) move(b byte) {
	n := max(s.args[0], 1)
	switch b {
	case 'H', 'f':
		s.row, s.col = n-1, max(s.args[1], 1)-1
	case 'G', '`':
		s.col = n - 1
	case 'C', 'a':
		s.col += n
	case 'D':
		s.col = max(s.col-n, 0)
	case 'A':
		s.row -= n
	case 'B', 'e':
		s.row += n
	case 'E':
		s.row, s.col = s.row+n, 0
	case 'F':
		s.row, s.col = s.row-n, 0
	case 'd':
		s.row = n - 1
	case 'h', 'l':
		// The other screen, and the cursor that comes back with it.
		if s.private && (s.args[0] == 47 || s.args[0] >= 1047 && s.args[0] <= 1049) {
			s.row = far
		}
	case 'n', 'c', 'q', 't', 's':
	default:
		// Scrolling, inserting, restoring: where the next row is from here is anyone's guess.
		s.row = far
	}
}

// control takes a byte outside a sequence. A terminal runs one in the middle of a sequence and goes on.
func (s *termScanner) control(b byte) termClass {
	switch {
	case b == 0x1b:
		s.state = termEscape
		return termGlue
	case b == '\r':
		s.col = 0
		return termWhite
	case b == '\n':
		s.row++
		return termWhite
	case b == '\t':
		s.col = (s.col/8 + 1) * 8
		if s.cols > 0 {
			s.col = min(s.col, s.cols-1)
		}
		return termWhite
	case b == '\b':
		s.col = max(s.col-1, 0)
		return termBack
	case b == 0x0b, b == 0x0c:
		s.row++
		return termBreak
	case b < 0x20, b == 0x7f:
		return termGlue
	}
	s.printed = true
	// The bytes of one character after its first go to the same cell.
	if b&0xC0 == 0x80 {
		return termText
	}
	// A full row wraps with the next character, not with the last one.
	if s.atEdge() {
		s.row, s.col = s.row+1, 0
	}
	s.printedRow, s.printedCol = s.row, s.col
	s.col++
	return termText
}

// textRun maps text to its stream: the bytes from offset text on are the stream bytes from offset raw on.
type textRun struct {
	text, raw int
}

// heldByte is a byte that may belong to the wrap of a line.
type heldByte struct {
	class termClass
	b     byte
	raw   int
}

// streamText is the text of one stream, the part not searched to its end yet.
type streamText struct {
	scan termScanner
	buf  []byte
	// base is the text offset of buf[0], raw the stream offset of the next byte.
	base, raw int
	runs      []textRun
	// gap is set after a cursor move, so the rules do not read two places of the screen as one word.
	gap bool
	// wraps are the text offsets where a line was wrapped.
	wraps []int
	spans []span

	// A row was filled to the edge. What follows is held until the next text tells whether the program wrapped a line.
	edge    bool
	edgeRow int
	held    []heldByte
	moved   bool
	// full says the line reached the edge. One broken at a word stops short, and only wraps when the next row is marked.
	full, marked bool
	// digits may be a line number, and the next row a line of its own.
	digits []heldByte
}

const (
	// wrapGutter is how far into the next row a wrapped line may go on.
	wrapGutter = 16
	// wrapShort is how far from the edge a line broken at a word may end.
	wrapShort = 40
)

func (t *streamText) write(data []byte) {
	for _, b := range data {
		class := t.scan.next(b)
		if !t.edge || !t.hold(class, b) {
			t.put(class, b, t.raw)
			if t.scan.printed && t.scan.cols > 0 && t.scan.col >= t.scan.cols-wrapShort {
				// Blanks up to the edge are an editor painting the rest of a row, the line ended before them.
				t.edge, t.edgeRow, t.full = true, t.scan.printedRow, t.scan.atEdge() && b != ' '
				t.moved, t.marked = false, false
			}
		}
		t.raw++
	}
}

// hold takes a byte after a full row. It reports whether the byte is kept back until the wrap is decided.
func (t *streamText) hold(class termClass, b byte) bool {
	below := t.scan.row == t.edgeRow+1
	switch {
	case class == termGlue:
		return true
	case class == termWhite && b != '\t' && t.scan.row <= t.edgeRow+1:
		t.held = append(t.held, heldByte{class, b, t.raw})
		return true
	case class == termBreak && below:
		t.moved = true
		return true
	case class == termBack && len(t.held) > 0 && t.held[len(t.held)-1].b == ' ':
		// A pager wraps with a blank and a backspace, and the line goes on over the blank.
		t.held = t.held[:len(t.held)-1]
		t.moved = true
		return true
	case class == termText && t.scan.printed && t.scan.printedRow == t.edgeRow+1 && t.scan.printedCol <= wrapGutter:
		number := b >= '0' && b <= '9'
		switch {
		case len(t.digits) == 0 && (b == ' ' || b == '|' || b >= 0x80):
			t.marked = t.marked || b != ' '
			t.held = append(t.held, heldByte{class, b, t.raw})
			return true
		case number && len(t.digits) < 6:
			t.digits = append(t.digits, heldByte{class, b, t.raw})
			return true
		case len(t.digits) > 0 && b == ' ':
			// A line number: the next row is the next line, cut off or not.
		case t.full || t.marked:
			// The line goes on. Text that ran over the edge by itself was never apart, anything else leaves a wrap behind.
			for n := len(t.buf); !t.full && n > 0 && t.buf[n-1] == ' '; n-- {
				t.pop()
			}
			if len(t.held) > 0 || t.moved {
				t.wraps = append(t.wraps, t.base+len(t.buf))
			}
			t.edge, t.gap, t.held = false, false, t.held[:0]
			for _, d := range t.digits {
				t.put(d.class, d.b, d.raw)
			}
			t.digits = t.digits[:0]
			return false
		}
	}

	// No wrap, what was held is text like any other.
	t.edge = false
	t.gap = t.gap || t.moved
	for _, h := range slices.Concat(t.held, t.digits) {
		t.put(h.class, h.b, h.raw)
	}
	t.held, t.digits = t.held[:0], t.digits[:0]
	return false
}

func (t *streamText) put(class termClass, b byte, raw int) {
	switch class {
	case termText:
		if n := len(t.buf); t.gap && n > 0 && !isBlank(t.buf[n-1]) {
			// The break stands for the sequence right before this byte.
			t.push('\n', raw-1)
		}
		t.gap = false
		t.push(b, raw)
	case termWhite:
		t.gap = false
		t.push(b, raw)
	case termBreak:
		t.gap = true
	case termBack:
		// The wrap of a pager again, for a terminal of unknown width.
		if n := len(t.buf); n > 0 && t.buf[n-1] == ' ' && t.rawOf(t.base+n-1) == raw-1 {
			t.pop()
			t.wraps = append(t.wraps, t.base+len(t.buf))
		} else {
			t.gap = true
		}
	case termGlue:
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
	// A wrap or a sequence splits text into several pieces of the stream. Only the text is taken.
	take := func(start, end int) {
		at, end := t.base+start, t.base+end
		i, found := slices.BinarySearchFunc(t.runs, at, func(r textRun, at int) int { return r.text - at })
		if !found {
			i--
		}
		for ; at < end; i++ {
			stop := end
			if i+1 < len(t.runs) {
				stop = min(stop, t.runs[i+1].text)
			}
			raw := t.runs[i].raw + at - t.runs[i].text
			t.spans = append(t.spans, span{raw, raw + stop - at})
			at = stop
		}
	}
	for _, sp := range find(t.buf) {
		take(sp.start, sp.end)
	}
	if len(t.wraps) == 0 {
		return
	}

	// A secret that runs into a pager's prompt at a wrap matches no rule, so each wrapped line is searched again alone.
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
	// next is the first span that ends after pos, the stream offset of the next byte.
	next, pos int
	// col is how many characters in a row are replaced.
	col int
}

// apply keeps the width of a secret. An editor counts on every cell it wrote, a shorter line would leave old text.
func (r *redactor) apply(data []byte) []byte {
	r.skip()
	if end := r.pos + len(data); r.next == len(r.spans) || r.spans[r.next].start >= end {
		for _, b := range data {
			if r.scan.next(b) != termGlue {
				r.col = 0
			}
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
		case class == termGlue:
			// A color change in the middle of a secret is no new run.
		case class != termText || !inside:
			// A line break, a cursor move, or text that stays.
			r.col = 0
		case b&0xC0 == 0x80:
			// A character of several bytes takes one cell, at its first byte.
			continue
		default:
			if r.col < len(redaction) {
				b = redaction[r.col]
			} else {
				b = ' '
			}
			r.col++
		}
		out = append(out, b)
	}
	return out
}

// skip leaves the spans that end before pos behind.
func (r *redactor) skip() {
	for r.next < len(r.spans) && r.spans[r.next].end <= r.pos {
		r.next++
	}
}
