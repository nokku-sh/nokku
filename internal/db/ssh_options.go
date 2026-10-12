package db

// Only known critical option names are accepted in ssh_cas.user_critical_options.

import (
	"encoding/json"
	"fmt"
)

type criticalOption string

const (
	coForceCommand   criticalOption = "force-command"
	coSourceAddress  criticalOption = "source-address"
	coVerifyRequired criticalOption = "verify-required" // For FIDO/U2F keys (requires user verification)
)

var allowedCriticalOptions = map[criticalOption]struct{}{
	coForceCommand:   {},
	coSourceAddress:  {},
	coVerifyRequired: {},
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
