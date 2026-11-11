// Package login is what the core, nokkud and nk must agree on for SSH logins.
package login

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"
)

// WebSessionKeyIDPrefix plus the session id is a web terminal cert's key id.
const WebSessionKeyIDPrefix = "nokku:web:session:"

// MaxCertTTL is the longest a person's certificate lasts. The core takes no setting above it, and a daemon that has
// not synced for this long takes no new logins: what it saved is older than any certificate it could vouch for.
const MaxCertTTL = 7 * 24 * time.Hour

// MaxRelayTime ends a relayed connection on both sides, so a revoke the daemon never heard of holds no longer.
const MaxRelayTime = 8 * time.Hour

// maxAccounts keeps a huge passwd file from flooding the core.
const maxAccounts = 200

// The shadow-utils relaxed rule, for LDAP names like john.doe, plus a trailing
// $ for Samba machine accounts. The protos and EnrollSheet.svelte carry the
// same pattern.
var usernameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]*\$?$`)

type Parts struct {
	SubjectID string
	TargetID  string
	Username  string
}

// ValidUsername passes names safe in a path, ssh_config and sshd_config.
func ValidUsername(name string) bool {
	return len(name) <= 32 && usernameRE.MatchString(name)
}

// Principal is one subject as one account on one daemon server, compared whole.
func Principal(subjectID, targetID, username string) string {
	return subjectID + "@" + targetID + ":" + username
}

// ParsePrincipal wants UUIDs, so "@" or ":" in a username can't shift it.
func ParsePrincipal(s string) (Parts, bool) {
	subject, rest, ok := strings.Cut(s, "@")
	if !ok {
		return Parts{}, false
	}
	target, username, ok := strings.Cut(rest, ":")
	if !ok || username == "" {
		return Parts{}, false
	}
	if _, err := uuid.Parse(subject); err != nil {
		return Parts{}, false
	}
	if _, err := uuid.Parse(target); err != nil {
		return Parts{}, false
	}
	return Parts{SubjectID: subject, TargetID: target, Username: username}, true
}

// ServerPrincipal is signed only for granted accounts, so servers list no one.
func ServerPrincipal(targetID, account string) string {
	return targetID + ":" + account
}

// ValidID wants a canonical UUID, the only form safe in paths and ssh configs.
func ValidID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id.String() == s
}

// PrincipalsCommand writes targetID raw, so the caller checks it with
// [ValidID]. The id in front keeps echo from reading an option.
func PrincipalsCommand(targetID string) string {
	return "AuthorizedPrincipalsCommand /bin/echo " + ServerPrincipal(targetID, "%u") + "\n" +
		"AuthorizedPrincipalsCommandUser nobody\n"
}

// Accounts sorts before it caps, so only the tail can change between reports.
func Accounts(passwd string) []string {
	var accounts []string
	for line := range strings.SplitSeq(passwd, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || !ValidUsername(fields[0]) {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil || (uid != 0 && uid < 1000) || noLoginShell(fields[6]) {
			continue
		}
		accounts = append(accounts, fields[0])
	}
	slices.Sort(accounts)
	accounts = slices.Compact(accounts)
	return accounts[:min(len(accounts), maxAccounts)]
}

func noLoginShell(shell string) bool {
	return strings.HasSuffix(shell, "nologin") ||
		strings.HasSuffix(shell, "false") ||
		strings.HasSuffix(shell, "sync")
}

// HomeKeyFiles picks the AuthorizedKeysFile entries out of sshd -T output that
// live in home directories, where a granted user can add a key of their own.
func HomeKeyFiles(sshdConfig string) []string {
	var files []string
	for line := range strings.Lines(sshdConfig) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), " ")
		if key != "authorizedkeysfile" {
			continue
		}
		// sshd reads a relative path from the user's home.
		for f := range strings.FieldsSeq(value) {
			if f != "none" && (!strings.HasPrefix(f, "/") || strings.Contains(f, "%h")) {
				files = append(files, f)
			}
		}
	}
	return files
}
