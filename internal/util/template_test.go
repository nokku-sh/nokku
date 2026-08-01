package util

import (
	"testing"
)

func TestParseExtensionsMap(t *testing.T) {
	got, err := ParseExtensionsMap([]byte(`{"permit-pty":""}`))
	if err != nil {
		t.Fatalf("ParseExtensionsMap() error: %v", err)
	}
	if got["permit-pty"] != "" {
		t.Errorf("unexpected map: %v", got)
	}

	// Maps with values must be rejected too.
	if _, err := ParseExtensionsMap([]byte(`{"permit-pty":"x"}`)); err == nil {
		t.Error("ParseExtensionsMap() with non-empty value: want error")
	}

	// Unknown extensions are rejected.
	if _, err := ParseExtensionsMap([]byte(`{"permit-foo":""}`)); err == nil {
		t.Error("ParseExtensionsMap() with unknown extension: want error")
	}
}

func TestValidateExtensions(t *testing.T) {
	tests := []struct {
		name    string
		in      map[string]string
		wantErr bool
	}{
		{"empty map ok", nil, false},
		{"valid extension with empty value", map[string]string{"permit-pty": ""}, false},
		{
			"multiple valid extensions",
			map[string]string{"permit-pty": "", "permit-X11-forwarding": ""},
			false,
		},
		{"unknown extension rejected", map[string]string{"permit-foo": ""}, true},
		{"non-empty value rejected", map[string]string{"permit-pty": "x"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateExtensions(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateExtensions(%v) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
		})
	}
}

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
