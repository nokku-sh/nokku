package util

import (
	"encoding/json"
	"fmt"
)

type (
	Extension      string
	CriticalOption string
)

const (
	ExtX11Forwarding   Extension = "permit-X11-forwarding"
	ExtAgentForwarding Extension = "permit-agent-forwarding"
	ExtPortForwarding  Extension = "permit-port-forwarding"
	ExtPTY             Extension = "permit-pty"
	ExtUserRC          Extension = "permit-user-rc"
	ExtTouchRequired   Extension = "no-touch-required" // For FIDO/U2F keys
)

const (
	COForceCommand   CriticalOption = "force-command"
	COSourceAddress  CriticalOption = "source-address"
	COVerifyRequired CriticalOption = "verify-required" // For FIDO/U2F keys (requires user verification)
)

var allowedExtensions = map[Extension]struct{}{
	ExtX11Forwarding:   {},
	ExtAgentForwarding: {},
	ExtPortForwarding:  {},
	ExtPTY:             {},
	ExtUserRC:          {},
	ExtTouchRequired:   {},
}

var allowedCriticalOptions = map[CriticalOption]struct{}{
	COForceCommand:   {},
	COSourceAddress:  {},
	COVerifyRequired: {},
}

// ValidateExtensionsJSON validates that JSON contains only allowed extensions with empty values.
func ValidateExtensionsJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}

	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("invalid extension JSON: %w", err)
	}

	for k, v := range m {
		if _, ok := allowedExtensions[Extension(k)]; !ok {
			return fmt.Errorf("invalid ssh extension: %q", k)
		}
		if v != "" {
			return fmt.Errorf("extension %q must have empty value", k)
		}
	}
	return nil
}

// ValidateCriticalOptionsJSON validates that JSON contains only allowed critical options.
func ValidateCriticalOptionsJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}

	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("invalid critical option JSON: %w", err)
	}

	for k, v := range m {
		if _, ok := allowedCriticalOptions[CriticalOption(k)]; !ok {
			return fmt.Errorf("invalid ssh critical option: %q", k)
		}
		// Note: force-command and source-address actually DO need values
		// Only validate the key here; value validation should happen at cert creation time
		if v != "" && k != string(COForceCommand) && k != string(COSourceAddress) &&
			k != string(COVerifyRequired) {
			return fmt.Errorf("extension critical option %q must have empty value", k)
		}
	}
	return nil
}

func ValidateExtensions(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}

	for k, v := range m {
		if _, ok := allowedExtensions[Extension(k)]; !ok {
			return nil, fmt.Errorf("invalid ssh extension: %q", k)
		}
		if v != "" {
			return nil, fmt.Errorf("extension %q must have empty value", k)
		}
	}
	return json.Marshal(m)
}

func ValidateCriticalOptions(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}

	for k, v := range m {
		if _, ok := allowedCriticalOptions[CriticalOption(k)]; !ok {
			return nil, fmt.Errorf("invalid ssh critical option: %q", k)
		}
		// Note: force-command and source-address actually DO need values
		// Only validate the key here; value validation should happen at cert creation time
		if v != "" && k != string(COForceCommand) && k != string(COSourceAddress) &&
			k != string(COVerifyRequired) {
			return nil, fmt.Errorf("extension critical option %q must have empty value", k)
		}
	}
	return json.Marshal(m)
}

// BuildExtensions creates JSON from extension list.
func BuildExtensions(exts ...Extension) ([]byte, error) {
	if len(exts) == 0 {
		return []byte("{}"), nil
	}

	m := make(map[string]string, len(exts))
	for _, e := range exts {
		if _, ok := allowedExtensions[e]; !ok {
			return nil, fmt.Errorf("invalid ssh extension: %q", e)
		}
		m[string(e)] = ""
	}

	return json.Marshal(m)
}

// BuildCriticalOptions creates JSON from critical options with optional values.
func BuildCriticalOptions(opts map[CriticalOption]string) ([]byte, error) {
	if len(opts) == 0 {
		return []byte("{}"), nil
	}

	m := make(map[string]string, len(opts))
	for o, v := range opts {
		if _, ok := allowedCriticalOptions[o]; !ok {
			return nil, fmt.Errorf("invalid ssh critical option: %q", o)
		}
		m[string(o)] = v
	}

	return json.Marshal(m)
}

func ParseExtensionsMap(b []byte) (map[string]string, error) {
	if len(b) == 0 || string(b) == "{}" {
		return nil, nil
	}

	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("invalid extension JSON: %w", err)
	}
	if _, err := ValidateExtensions(m); err != nil {
		return nil, err
	}
	return m, nil
}

func ParseCriticalOptionsMap(b []byte) (map[string]string, error) {
	if len(b) == 0 || string(b) == "{}" {
		return nil, nil
	}

	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("invalid critical option JSON: %w", err)
	}
	if _, err := ValidateCriticalOptions(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ParseExtensions extracts extension list from JSON.
func ParseExtensions(b []byte) ([]Extension, error) {
	if len(b) == 0 || string(b) == "{}" {
		return nil, nil
	}

	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("invalid extension JSON: %w", err)
	}

	exts := make([]Extension, 0, len(m))
	for k := range m {
		ext := Extension(k)
		if _, ok := allowedExtensions[ext]; !ok {
			return nil, fmt.Errorf("invalid ssh extension: %q", k)
		}
		exts = append(exts, ext)
	}

	return exts, nil
}

// ParseCriticalOptions extracts critical options map from JSON.
func ParseCriticalOptions(b []byte) (map[CriticalOption]string, error) {
	if len(b) == 0 || string(b) == "{}" {
		return nil, nil
	}

	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("invalid critical option JSON: %w", err)
	}

	opts := make(map[CriticalOption]string, len(m))
	for k, v := range m {
		opt := CriticalOption(k)
		if _, ok := allowedCriticalOptions[opt]; !ok {
			return nil, fmt.Errorf("invalid ssh critical option: %q", k)
		}
		opts[opt] = v
	}

	return opts, nil
}

// HasExtension checks if specific extension is present in JSON.
func HasExtension(b []byte, ext Extension) (bool, error) {
	if len(b) == 0 {
		return false, nil
	}

	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return false, err
	}

	_, ok := m[string(ext)]
	return ok, nil
}
