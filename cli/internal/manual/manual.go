// Package manual renders the probe and the script of a manual sync. It does no I/O, which keeps both testable.
package manual

import (
	"errors"
	"slices"
	"strconv"
	"strings"
)

// The web UI names these paths too, see TargetSheet.svelte.
const (
	caPath        = "/etc/ssh/nokku_ca.pub"
	principalsDir = "/etc/ssh/nokku_principals"
	dropInDir     = "/etc/ssh/sshd_config.d"
	dropInPath    = dropInDir + "/60-nokku.conf"

	// A huge passwd file cannot flood the core. Matches nokkud sysutil.maxReportedUsers.
	maxLocalAccounts = 200
)

const (
	sectionPasswd     = "#nk passwd"
	sectionHostKey    = "#nk hostkey"
	sectionPrincipals = "#nk principals"
)

// Writing /etc/ssh needs root, so the script stops early with a clear message.
const requireRoot = `[ "$(id -u)" = 0 ] || { echo "nk must connect as root" >&2; exit 1; }` + "\n"

// ProbeCommand gathers the accounts, the host key (ed25519 first) and the principals files in one ssh round trip.
const ProbeCommand = requireRoot +
	`echo '` + sectionPasswd + `'
getent passwd 2>/dev/null || cat /etc/passwd
echo '` + sectionHostKey + `'
for t in ed25519 ecdsa rsa; do
  f=/etc/ssh/ssh_host_${t}_key.pub
  if [ -r "$f" ]; then cat "$f"; break; fi
done
echo '` + sectionPrincipals + `'
for f in ` + principalsDir + `/*; do
  if [ -f "$f" ]; then basename "$f"; fi
done
`

type Host struct {
	// Accounts are capped at maxLocalAccounts.
	Accounts []string
	HostKey  string
	// Principals leave out the files of accounts past the cap, they are not stale.
	Principals []string
}

func ParseProbe(out string) (Host, error) {
	sections := map[string][]string{}
	var current string
	for line := range strings.SplitSeq(out, "\n") {
		switch line {
		case sectionPasswd, sectionHostKey, sectionPrincipals:
			current = line
		default:
			if current != "" && strings.TrimSpace(line) != "" {
				sections[current] = append(sections[current], line)
			}
		}
	}

	accounts := localAccounts(sections[sectionPasswd])
	capped := accounts[min(len(accounts), maxLocalAccounts):]
	h := Host{
		Accounts: accounts[:min(len(accounts), maxLocalAccounts)],
		Principals: slices.DeleteFunc(sections[sectionPrincipals], func(name string) bool {
			return slices.Contains(capped, name)
		}),
	}
	if keys := sections[sectionHostKey]; len(keys) > 0 {
		h.HostKey = strings.TrimSpace(keys[0])
	}
	if h.HostKey == "" {
		return h, errors.New("found no ssh host key in /etc/ssh")
	}
	return h, nil
}

// Accounts a human may log in as: uid 0 or at least 1000, a real login shell, a name safe as a file name.
func localAccounts(passwd []string) []string {
	var accounts []string
	for _, line := range passwd {
		fields := strings.Split(line, ":")
		if len(fields) < 7 || !safeName(fields[0]) {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil || (uid != 0 && uid < 1000) || noLoginShell(fields[6]) {
			continue
		}
		accounts = append(accounts, fields[0])
	}
	slices.Sort(accounts)
	return slices.Compact(accounts)
}

func noLoginShell(shell string) bool {
	return strings.HasSuffix(shell, "nologin") ||
		strings.HasSuffix(shell, "false") ||
		strings.HasSuffix(shell, "sync")
}

func safeName(name string) bool {
	if name == "" || name[0] == '.' || name[0] == '-' {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.'
	})
}

// An empty file denies certificate login for the account.
func renderPrincipals(ids []string) string {
	ids = slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return id == "" })
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if len(ids) == 0 {
		return ""
	}
	return strings.Join(ids, "\n") + "\n"
}
