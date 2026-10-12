// Package manual renders what a manual sync runs on a daemonless host: one
// probe that gathers the host's state and one script that writes the trusted
// CA key, the sshd drop-in, and a principals file per local account. It does
// no I/O, which keeps both testable.
package manual

import (
	"errors"
	"slices"
	"strconv"
	"strings"
)

// Host layout shared with the daemon and the web UI.
const (
	caPath        = "/etc/ssh/nokku_ca.pub"
	principalsDir = "/etc/ssh/nokku_principals"
	dropInDir     = "/etc/ssh/sshd_config.d"
	dropInPath    = dropInDir + "/60-nokku.conf"

	// maxLocalAccounts caps what one sync reports, so a pathological passwd
	// file cannot flood the backend. Matches nokkud sysutil.maxReportedUsers.
	maxLocalAccounts = 200
)

const (
	sectionPasswd     = "#nk passwd"
	sectionHostKey    = "#nk hostkey"
	sectionPrincipals = "#nk principals"
)

// requireRoot stops a script early with a clear message. Writing /etc/ssh
// needs root, and a manual target is managed by its root operator.
const requireRoot = `[ "$(id -u)" = 0 ] || { echo "nk must connect as root" >&2; exit 1; }` + "\n"

// ProbeCommand gathers the local accounts, the host key (ed25519 first), and
// the existing principals files in one ssh round trip.
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

// Host is what the probe found on a host.
type Host struct {
	Accounts   []string
	HostKey    string
	Principals []string
}

// ParseProbe reads the output of ProbeCommand.
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

	h := Host{
		Accounts:   localAccounts(sections[sectionPasswd]),
		Principals: sections[sectionPrincipals],
	}
	if keys := sections[sectionHostKey]; len(keys) > 0 {
		h.HostKey = strings.TrimSpace(keys[0])
	}
	if h.HostKey == "" {
		return h, errors.New("found no ssh host key in /etc/ssh")
	}
	return h, nil
}

// localAccounts keeps the accounts a human may log in as: uid 0 or at least
// 1000, a real login shell, and a name that is safe as a file name.
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
	accounts = slices.Compact(accounts)
	return accounts[:min(len(accounts), maxLocalAccounts)]
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

// renderPrincipals renders the certificate principals allowed to log in as one
// account. An empty file denies certificate login for it.
func renderPrincipals(ids []string) string {
	ids = slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return id == "" })
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if len(ids) == 0 {
		return ""
	}
	return strings.Join(ids, "\n") + "\n"
}
