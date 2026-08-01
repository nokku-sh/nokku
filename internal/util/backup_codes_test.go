package util

import (
	"strings"
	"testing"
)

func TestNormalizeBackupCode(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "already canonical",
			in:   "ABCD-EFGH-JKLM-NPQR",
			want: "ABCD-EFGH-JKLM-NPQR",
		},
		{
			name: "lowercase input",
			in:   "abcd-efgh-jklm-npqr",
			want: "ABCD-EFGH-JKLM-NPQR",
		},
		{
			name: "no dashes",
			in:   "ABCDEFGHJKLMNPQR",
			want: "ABCD-EFGH-JKLM-NPQR",
		},
		{
			name: "spaces instead of dashes",
			in:   "ABCD EFGH JKLM NPQR",
			want: "ABCD-EFGH-JKLM-NPQR",
		},
		{
			name: "lookalike typos 1/I -> L",
			in:   "1BCD-EFG1-JKLM-NP1R",
			want: "LBCD-EFGL-JKLM-NPLR",
		},
		{
			name: "lookalike typos 0/O -> Q",
			in:   "0BCD-EFG0-JKLM-NP0R",
			want: "QBCD-EFGQ-JKLM-NPQR",
		},
		{
			name: "mixed typos",
			in:   "10IO-0000-LLLL-1111",
			want: "LQLQ-QQQQ-LLLL-LLLL",
		},
		{
			name: "too short stays unformatted",
			in:   "ABCD",
			want: "ABCD",
		},
		{
			name: "empty input",
			in:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeBackupCode(tt.in); got != tt.want {
				t.Errorf("NormalizeBackupCode(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestGenerateBackupCodes(t *testing.T) {
	codes, err := GenerateBackupCodes()
	if err != nil {
		t.Fatalf("GenerateBackupCodes() error: %v", err)
	}

	if len(codes) != 10 {
		t.Fatalf("got %d codes, want 10", len(codes))
	}

	seen := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		if len(code) != 19 { // 16 chars + 3 dashes
			t.Errorf("code %q has length %d, want 19", code, len(code))
		}
		if got := strings.Count(code, "-"); got != 3 {
			t.Errorf("code %q has %d dashes, want 3", code, got)
		}
		for part := range strings.SplitSeq(code, "-") {
			if len(part) != 4 {
				t.Errorf("code %q has a %d-char group, want 4", code, len(part))
			}
			for _, r := range part {
				if !strings.ContainsRune("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", r) {
					t.Errorf("code %q contains invalid character %q", code, r)
				}
			}
		}
		if _, dup := seen[code]; dup {
			t.Errorf("duplicate code %q", code)
		}
		seen[code] = struct{}{}
	}

	// Codes must round-trip through normalization unchanged.
	for _, code := range codes {
		if got := NormalizeBackupCode(code); got != code {
			t.Errorf("NormalizeBackupCode(%q) = %q, want identity", code, got)
		}
	}
}
