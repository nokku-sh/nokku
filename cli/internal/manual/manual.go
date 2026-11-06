// Package manual renders the probe and script of a manual sync, with no I/O.
package manual

import (
	"errors"
	"strings"

	"github.com/nokku-sh/nokku/internal/login"
)

const (
	caPath     = "/etc/ssh/nokku_ca.pub"
	dropInDir  = "/etc/ssh/sshd_config.d"
	dropInPath = dropInDir + "/60-nokku.conf"
	// Held a file per account before the drop-in named a command.
	oldPrincipalsDir = "/etc/ssh/nokku_principals"
)

const (
	sectionPasswd  = "#nk passwd"
	sectionHostKey = "#nk hostkey"
)

// ProbeCommand gathers accounts and the host key in one ssh round trip.
var ProbeCommand = render("probe.sh.tmpl", shared)

type Host struct {
	Accounts []string
	HostKey  string
}

func ParseProbe(out string) (Host, error) {
	sections := map[string][]string{}
	var current string
	for line := range strings.SplitSeq(out, "\n") {
		switch line {
		case sectionPasswd, sectionHostKey:
			current = line
		default:
			if current != "" && strings.TrimSpace(line) != "" {
				sections[current] = append(sections[current], line)
			}
		}
	}

	h := Host{Accounts: login.Accounts(strings.Join(sections[sectionPasswd], "\n"))}
	if keys := sections[sectionHostKey]; len(keys) > 0 {
		h.HostKey = strings.TrimSpace(keys[0])
	}
	if h.HostKey == "" {
		return h, errors.New("found no ssh host key in /etc/ssh")
	}
	return h, nil
}
