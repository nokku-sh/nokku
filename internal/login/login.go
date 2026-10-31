// Package login holds what the core, nokkud and nk must agree on about an SSH
// login: the principals a certificate carries, the key id of a web terminal,
// and which local accounts a server offers.
package login

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"uuid"
)

// WebSessionKeyIDPrefix starts the key id of a certificate the core mints for
// a web terminal. The core's session id follows it.
const WebSessionKeyIDPrefix = "nokku:web:session:"

// maxAccounts keeps a huge passwd file from flooding the core.
const maxAccounts = 200

// The shadow-utils relaxed rule, so LDAP and SSSD names like john.doe pass,
// plus a trailing $ for Samba machine accounts. The protos and
// TokenSheet.svelte carry the same pattern.
var usernameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]*\$?$`)

// ValidUsername reports whether name is an account name Nokku handles. Such a
// name is safe as a path component, in ssh_config and in sshd_config.
func ValidUsername(name string) bool {
	return len(name) <= 32 && usernameRE.MatchString(name)
}

// Principal lets one subject log in as one account on one server that runs
// the daemon. The daemon compares it as a whole string.
func Principal(subjectID, targetID, username string) string {
	return subjectID + "@" + targetID + ":" + username
}

// Parts is a [Principal] taken apart.
type Parts struct {
	SubjectID string
	TargetID  string
	Username  string
}

// ParsePrincipal is for the core. The ids are UUIDs, so "@" or ":" in a
// username cannot shift the split.
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

// ServerPrincipal lets whoever holds it log in as account on a server set up
// with nk sync. The core signs it only for the accounts a subject is granted
// there, so the server needs no list of people.
func ServerPrincipal(targetID, account string) string {
	return targetID + ":" + account
}

// ValidID reports whether s is a UUID in its canonical form, lowercase and
// hyphenated. Only that form is safe as a path segment, an ssh token and a
// line of sshd_config.
func ValidID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id.String() == s
}

// PrincipalsCommand is the sshd_config that makes such a server take
// [ServerPrincipal] for the account a login asks for. sshd runs echo as
// nobody, and the id in front keeps echo from reading an option. targetID
// goes into sshd_config as it is, so the caller checks it with [ValidID].
func PrincipalsCommand(targetID string) string {
	return "AuthorizedPrincipalsCommand /bin/echo " + ServerPrincipal(targetID, "%u") + "\n" +
		"AuthorizedPrincipalsCommandUser nobody\n"
}

// Accounts reads getent passwd output and keeps the accounts a person may log
// in as: uid 0 or at least 1000, a real login shell and a valid name. The list
// is sorted before it is capped, so only its tail can change between reports.
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
