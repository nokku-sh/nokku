package recording

import (
	"strings"
	"unicode"
)

// maxSnakeCaseLen bounds the result so it always fits a single filename.
const maxSnakeCaseLen = 64

func toSnakeCase(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	lastWasUnderscore := true // Start true so leading separators are dropped

	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
			lastWasUnderscore = false
		} else if !lastWasUnderscore {
			b.WriteByte('_')
			lastWasUnderscore = true
		}
	}

	res := b.String()
	if len(res) > maxSnakeCaseLen {
		res = strings.ToValidUTF8(res[:maxSnakeCaseLen], "")
	}
	if len(res) > 0 && res[len(res)-1] == '_' {
		res = res[:len(res)-1]
	}

	if res == "" {
		return "untitled"
	}

	return res
}
