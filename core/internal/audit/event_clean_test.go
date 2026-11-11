package audit

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDropNUL(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"plain":                   {"web-1", "web-1"},
		"a NUL":                   {"a\x00b", "ab"},
		"only NULs":               {"\x00\x00", ""},
		"text that reads like it": {`a\u0000b`, `a\u0000b`},
		"a backslash before one":  {"a\\\x00b", `a\b`},
		"a quote and a NUL":       {"\"\x00\"", `""`},
		"at the end":              {"tail\x00", "tail"},
	} {
		doc, err := json.Marshal(map[string]any{"v": tc.in, "list": []string{tc.in}})
		require.NoError(t, err)
		var got struct {
			V    string   `json:"v"`
			List []string `json:"list"`
		}
		require.NoError(t, json.Unmarshal(dropNUL(doc), &got), "%s: no JSON left", name)
		assert.Equal(t, tc.want, got.V, name)
		assert.Equal(t, []string{tc.want}, got.List, name)
	}
}

func TestText(t *testing.T) {
	assert.Equal(t, "web", text("w\x00e\xffb"))
}
