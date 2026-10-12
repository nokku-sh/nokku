package db

import (
	"testing"
)

func TestValidateCriticalOptions(t *testing.T) {
	tests := []struct {
		name    string
		in      map[string]string
		wantErr bool
	}{
		{"empty map ok", nil, false},
		{"force-command may carry a value", map[string]string{"force-command": "ls -la"}, false},
		{
			"source-address may carry a value",
			map[string]string{"source-address": "192.0.2.0/24"},
			false,
		},
		{"verify-required may carry a value", map[string]string{"verify-required": ""}, false},
		{"unknown option rejected", map[string]string{"bogus": ""}, true},
		{
			"non-empty value on empty-value option rejected",
			map[string]string{"permit-pty": "x"},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateCriticalOptions(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"ValidateCriticalOptions(%v) error = %v, wantErr %v",
					tt.in,
					err,
					tt.wantErr,
				)
			}
		})
	}
}
