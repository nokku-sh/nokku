package state

import (
	"fmt"
	"regexp"
)

// The shadow-utils relaxed rules, so LDAP and SSSD names like john.doe pass. Keep in sync with protos.
var posixUserRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]*\$?$`)

func validatePrincipal(principal string) error {
	if len(principal) > 32 || !posixUserRE.MatchString(principal) {
		return fmt.Errorf("invalid username %q", principal)
	}
	return nil
}
