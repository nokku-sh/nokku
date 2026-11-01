package iam

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleMatchesEveryClaimAsAString(t *testing.T) {
	job := map[string]any{"sub": "job", "run": float64(7), "ok": true, "groups": []any{"job"}}
	tests := []struct {
		name string
		rule map[string]string
		want bool
	}{
		{"one claim", map[string]string{"sub": "job"}, true},
		{"a value that differs", map[string]string{"sub": "Job"}, false},
		{"one of two", map[string]string{"sub": "job", "ref": "main"}, false},
		{"a claim the job lacks", map[string]string{"ref": ""}, false},
		{"a number", map[string]string{"run": "7"}, false},
		{"a bool", map[string]string{"ok": "true"}, false},
		{"a list", map[string]string{"groups": "job"}, false},
		{"no claims", map[string]string{}, false},
		{"a nil rule", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ruleMatches(tt.rule, job))
		})
	}
}

func TestUnverifiedIssuer(t *testing.T) {
	encode := func(payload string) string { return base64.RawURLEncoding.EncodeToString([]byte(payload)) }

	got, err := unverifiedIssuer("head." + encode(`{"iss":"https://ci.test","sub":"job"}`) + ".sig")
	require.NoError(t, err)
	assert.Equal(t, "https://ci.test", got)

	for name, raw := range map[string]string{
		"empty":         "",
		"one part":      "garbage",
		"two parts":     "head." + encode(`{"iss":"x"}`),
		"not base64":    "head.%%%.sig",
		"not JSON":      "head." + encode("nope") + ".sig",
		"no iss":        "head." + encode(`{"sub":"job"}`) + ".sig",
		"iss no string": "head." + encode(`{"iss":7}`) + ".sig",
		"two iss":       "head." + encode(`{"iss":"a","iss":"b"}`) + ".sig",
	} {
		_, err := unverifiedIssuer(raw)
		assert.Error(t, err, name)
	}
}
