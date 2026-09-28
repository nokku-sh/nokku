package daemon

// sanitizeReplay strips terminal queries (DSR, DA, OSC, DCS, ...) from PTY
// output. A fresh terminal replaying them would answer back into the PTY.
func sanitizeReplay(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); {
		if data[i] == 0x1b {
			if skip := skipRequestSequence(data[i:]); skip > 0 {
				i += skip
				continue
			}
		}
		out = append(out, data[i])
		i++
	}
	return out
}

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
	switch p[i] {
	case 'n', 'c', 't': // DSR, DA, window-property queries
		return i + 1
	case 'S':
		if p[2] == '?' { // graphics query
			return i + 1
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
	// Strip an unterminated query at the buffer tail too.
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
	return i // unterminated at tail, strip it
}
