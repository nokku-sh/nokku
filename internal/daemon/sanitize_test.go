package daemon

import (
	"bytes"
	"testing"
)

func TestSanitizeReplay(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "plain text passes through",
			in:   "hello world\n",
			want: "hello world\n",
		},
		{
			name: "empty input",
			in:   "",
			want: "",
		},
		{
			name: "colors and cursor moves are preserved",
			in:   "\x1b[31mred\x1b[0m \x1b[2K",
			want: "\x1b[31mred\x1b[0m \x1b[2K",
		},
		{
			name: "DSR cursor position query is stripped",
			in:   "before\x1b[6n after",
			want: "before after",
		},
		{
			name: "DA device attributes query is stripped",
			in:   "a\x1b[0c b",
			want: "a b",
		},
		{
			name: "DEC private mode DSR query is stripped",
			in:   "a\x1b[?6n b",
			want: "a b",
		},
		{
			name: "graphics query with private marker is stripped",
			in:   "a\x1b[?12S b",
			want: "a b",
		},
		{
			name: "plain SGR ending in S is preserved",
			in:   "a\x1b[5S b",
			want: "a\x1b[5S b",
		},
		{
			name: "window property query is stripped",
			in:   "a\x1b[11t b",
			want: "a b",
		},
		{
			name: "OSC query terminated by BEL is stripped",
			in:   "a\x1b]11;?\x07 b",
			want: "a b",
		},
		{
			name: "OSC query terminated by ST is stripped",
			in:   "a\x1b]105;?\x1b\\ b",
			want: "a b",
		},
		{
			name: "OSC without query is preserved",
			in:   "a\x1b]0;title\x07 b",
			want: "a\x1b]0;title\x07 b",
		},
		{
			name: "OSC setting with ST without query is preserved",
			in:   "a\x1b]10;#000000\x1b\\ b",
			want: "a\x1b]10;#000000\x1b\\ b",
		},
		{
			name: "unterminated OSC query at tail is stripped",
			in:   "a\x1b]11;?",
			want: "a",
		},
		{
			name: "DCS request (DECRQSS) is stripped",
			in:   "a\x1bP$q q\x1b\\ b",
			want: "a b",
		},
		{
			name: "unterminated DCS at tail is stripped",
			in:   "a\x1bP$q",
			want: "a",
		},
		{
			name: "lone ESC is preserved",
			in:   "a\x1b",
			want: "a\x1b",
		},
		{
			name: "ESC followed by plain char is preserved",
			in:   "a\x1bX b",
			want: "a\x1bX b",
		},
		{
			name: "ESC[ with trailing digits and no final is preserved",
			in:   "a\x1b[123",
			want: "a\x1b[123",
		},
		{
			name: "newline after DSR is preserved",
			in:   "\x1b[6n\n",
			want: "\n",
		},
		{
			name: "multiple queries stripped in one buffer",
			in:   "x\x1b[6n\x1b[0c\x1b]105;?\x07y",
			want: "xy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeReplay([]byte(tt.in))
			if !bytes.Equal(got, []byte(tt.want)) {
				t.Errorf("sanitizeReplay(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeReplay_UnicodePreserved(t *testing.T) {
	in := "héllo\x1b[6n wörld ✓\n"
	want := "héllo wörld ✓\n"
	got := sanitizeReplay([]byte(in))
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("sanitizeReplay() = %q, want %q", got, want)
	}
}

func TestSanitizeReplay_MultibyteAcrossQueries(t *testing.T) {
	// Query sequences must not corrupt surrounding multibyte characters.
	in := "é\x1b[?1;2cè"
	want := "éè"
	got := sanitizeReplay([]byte(in))
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("sanitizeReplay() = %q, want %q", got, want)
	}
}
