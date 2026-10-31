package actor

import (
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestRequestMetaCleansWhatIsStored(t *testing.T) {
	meta := RequestMeta{Header: http.Header{}, RemoteAddr: "203.0.113.7:4242"}
	meta.Header.Set("User-Agent", "curl/8\xff")
	assert.Equal(t, "203.0.113.7", meta.ClientIP())
	assert.Equal(t, "curl/8", meta.UserAgent(), "invalid UTF-8 was kept")

	// A rune cut in half at the limit is dropped whole.
	meta.Header.Set("User-Agent", strings.Repeat("a", maxUserAgent-1)+"é")
	ua := meta.UserAgent()
	assert.Equal(t, strings.Repeat("a", maxUserAgent-1), ua)
	assert.True(t, utf8.ValidString(ua))

	assert.Empty(t, RequestMeta{}.UserAgent(), "a meta without a header")
}
