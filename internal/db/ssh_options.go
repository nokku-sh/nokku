package db

// The two JSONB columns on ssh_cas hold SSH certificate
// extensions and critical options. Only known names are accepted.

import (
	"encoding/json"
	"fmt"
)

type (
	extension      string
	criticalOption string
)

const (
	extX11Forwarding   extension = "permit-X11-forwarding"
	extAgentForwarding extension = "permit-agent-forwarding"
	extPortForwarding  extension = "permit-port-forwarding"
	extPTY             extension = "permit-pty"
	extUserRC          extension = "permit-user-rc"
	extTouchRequired   extension = "no-touch-required" // For FIDO/U2F keys
)

const (
	coForceCommand   criticalOption = "force-command"
	coSourceAddress  criticalOption = "source-address"
	coVerifyRequired criticalOption = "verify-required" // For FIDO/U2F keys (requires user verification)
)

var allowedExtensions = map[extension]struct{}{
	extX11Forwarding:   {},
	extAgentForwarding: {},
	extPortForwarding:  {},
	extPTY:             {},
	extUserRC:          {},
	extTouchRequired:   {},
}

var allowedCriticalOptions = map[criticalOption]struct{}{
	coForceCommand:   {},
	coSourceAddress:  {},
	coVerifyRequired: {},
}

func ValidateExtensions(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}

	for k, v := range m {
		if _, ok := allowedExtensions[extension(k)]; !ok {
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

	// Values are checked at cert creation time.
	for k := range m {
		if _, ok := allowedCriticalOptions[criticalOption(k)]; !ok {
			return nil, fmt.Errorf("invalid ssh critical option: %q", k)
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
