package iam

import "testing"

func TestNormalizeBackupCode(t *testing.T) {
	cases := map[string]string{
		"ABCD2345EFGH6789":      "ABCD2345EFGH6789", // bare, as generated
		"abcd2345efgh6789":      "ABCD2345EFGH6789", // lowercase retyping
		"ABCD-2345-EFGH-6789":   "ABCD2345EFGH6789", // dashed, as the UI formats it
		" abcd 2345 efgh 6789 ": "ABCD2345EFGH6789", // spaces and whitespace
	}
	for in, want := range cases {
		if got := normalizeBackupCode(in); got != want {
			t.Errorf("normalizeBackupCode(%q) = %q, want %q", in, got, want)
		}
	}
}
