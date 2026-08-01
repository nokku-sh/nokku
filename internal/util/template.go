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

// ValidateExtensions validates that a map contains only allowed extensions
// with empty values.
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
		// force-command, source-address and verify-required carry values;
		// only keys are validated here, values are checked at cert creation time.
		if v != "" && k != string(COForceCommand) && k != string(COSourceAddress) &&
			k != string(COVerifyRequired) {
			return nil, fmt.Errorf("extension critical option %q must have empty value", k)
		}
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
