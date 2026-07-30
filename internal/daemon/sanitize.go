package daemon

// SanitizeReplay strips terminal query/request sequences (DSR, DA, OSC queries,
// DCS requests, window-title/color queries, sixel queries) from raw PTY output
// so that replaying the buffer into a fresh terminal does not make that
// terminal emit reply bytes back into the PTY. Regular escape sequences
// (colors, cursor moves, erase, etc.) are preserved.
func SanitizeReplay(data []byte) []byte {
	out := make([]byte, 0, len(data))
	i := 0
	for i < len(data) {
		if data[i] != 0x1b {
			out = append(out, data[i])
			i++
			continue
		}
		if skip := skipRequestSequence(data[i:]); skip > 0 {
			i += skip
			continue
		}
		out = append(out, data[i])
		i++
	}
	return out
}

// skipRequestSequence returns the length of a terminal request/query sequence
// starting at p, or 0 if it isn't one we strip.
func skipRequestSequence(p []byte) int {
	if len(p) < 2 {
		return 0
	}
	switch p[1] {
	case '[': // CSI
		return skipCSIRequest(p)
	case ']': // OSC
		return skipOSCQuery(p)
	case 'P': // DCS (DECRQSS, XTGETTCAP, sixel, etc.)
		return skipDCSRequest(p)
	}
	return 0
}

func skipCSIRequest(p []byte) int {
	if len(p) < 3 {
		return 0
	}
	i := 2
	if i < len(p) && (p[i] == '?' || p[i] == '>' || p[i] == '=') {
		i++
	}
	for i < len(p) && ((p[i] >= '0' && p[i] <= '9') || p[i] == ';') {
		i++
	}
	if i >= len(p) {
		return 0
	}
	final := p[i]
	seqLen := i + 1
	switch final {
	case 'n': // DSR: cursor/printer status queries
		return seqLen
	case 'c': // DA: primary/secondary/tertiary device attributes
		return seqLen
	case 't': // window-property queries
		return seqLen
	case 'S':
		if len(p) > 2 && p[2] == '?' { // graphics query
			return seqLen
		}
	}
	return 0
}

func skipOSCQuery(p []byte) int {
	if len(p) < 4 {
		return 0
	}
	i := 2
	for i < len(p) && p[i] >= '0' && p[i] <= '9' {
		i++
	}
	if i >= len(p) || p[i] != ';' {
		return 0
	}
	i++

	hasQuery := false
	start := i
	for i < len(p) {
		if p[i] == '?' {
			hasQuery = true
		}
		if p[i] == 0x07 { // BEL terminator
			if hasQuery {
				return i + 1
			}
			return 0
		}
		if p[i] == 0x1b && i+1 < len(p) && p[i+1] == '\\' { // ST terminator
			if hasQuery {
				return i + 2
			}
			return 0
		}
		i++
	}
	// Unterminated OSC at the buffer tail: strip if it carried a query, so a
	// dangling query doesn't survive into the replay.
	if hasQuery && i-start < 64 {
		return i
	}
	return 0
}

func skipDCSRequest(p []byte) int {
	if len(p) < 3 {
		return 0
	}
	i := 2
	for i < len(p) {
		if p[i] == 0x1b && i+1 < len(p) && p[i+1] == '\\' {
			return i + 2
		}
		i++
	}
	return i // unterminated at tail — strip it
}
