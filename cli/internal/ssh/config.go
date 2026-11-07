package ssh

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"text/template"

	"github.com/mizuchilabs/kata/fsutil"

	"github.com/nokku-sh/nokku/internal/login"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

const header = "# Managed by Nokku. nk regenerates this file, do not edit it.\n\n"

// What the core allows. Anything wider could claim github.com or reach a shell.
var targetName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

//go:embed ssh_config.tmpl
var sshConfigText string

var sshConfig = template.Must(template.New("ssh_config").Parse(sshConfigText))

// Every value is ready for ssh_config, quoted where it needs to be.
type hostBlock struct {
	Host, User, ID                                        string
	Prepare, NK, Certificate, Identity, Agent, KnownHosts string
}

func WriteConfigs(s *state.State) error {
	config := renderSSHConfig(s, HostAliases(s), nkCommand())
	if err := fsutil.WriteIfChanged(paths.SSHConfigFile(), config, 0o600); err != nil {
		return err
	}
	if err := fsutil.WriteIfChanged(paths.KnownHostsFile(), renderKnownHosts(s), 0o600); err != nil {
		return err
	}
	return ensureInclude()
}

// HostAliases has no entry for a target that cannot go into ssh_config.
func HostAliases(s *state.State) map[string]string {
	return hostAliases(s, readOwnHosts())
}

// nk's Include comes first, so a bare name could take over a user's own host.
func hostAliases(s *state.State, own ownHosts) map[string]string {
	// Case folded, ssh's Match can't tell Web from web. Neither can people.
	names := make(map[string]int)
	for _, t := range s.Targets {
		if usable(t) {
			names[strings.ToLower(t.Name)]++
		}
	}

	aliases := make(map[string]string, len(s.Targets))
	for _, t := range s.Targets {
		if !usable(t) {
			continue
		}
		switch {
		case names[strings.ToLower(t.Name)] > 1:
			aliases[t.ID] = "nokku/" + t.ID
		case own.claims(t.Name):
			aliases[t.ID] = "nokku/" + t.Name
		default:
			aliases[t.ID] = t.Name
		}
	}
	return aliases
}

func renderSSHConfig(s *state.State, aliases map[string]string, nk string) []byte {
	identity, agent := configValue(paths.PubKeyFile()), configValue(paths.AgentSocket())
	if s.SecurityKey {
		// ssh talks to the key itself and asks for the touch, the handle is no secret.
		identity, agent = configValue(paths.SecurityKeyFile()), "none"
	}
	var hosts []hostBlock
	for _, t := range s.Targets {
		host, ok := aliases[t.ID]
		if !ok {
			continue
		}
		hosts = append(hosts, hostBlock{
			Host: host,
			User: t.Usernames[0],
			ID:   t.ID,
			// ssh loads CertificateFile before ProxyCommand, so Match exec renews
			// first. It lowercases %h, hence the id.
			Prepare:     configValue(nk + " prepare " + t.ID),
			NK:          nk,
			Certificate: configValue(paths.SSHCertificate(t.ID)),
			Identity:    identity,
			Agent:       agent,
			KnownHosts:  configValue(paths.KnownHostsFile()),
		})
	}

	var b bytes.Buffer
	b.WriteString(header)
	// The template is fixed and the tests run it, so only a bug can fail here.
	if err := sshConfig.Execute(&b, hosts); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// Trust is scoped to the target id, the HostKeyAlias, never a global "*".
func renderKnownHosts(s *state.State) []byte {
	var b bytes.Buffer
	b.WriteString(header)
	for _, t := range s.Targets {
		if t.Manual() {
			// A manual host presents its own key, not a CA-signed one.
			if key := strings.TrimSpace(t.HostPublicKey); safeLine(key) {
				fmt.Fprintf(&b, "%s %s\n", t.ID, key)
			}
			continue
		}
		if s.CA == nil {
			continue
		}
		if key := strings.TrimSpace(s.CA.HostPublicKey); safeLine(key) {
			fmt.Fprintf(&b, "@cert-authority %s %s\n", t.ID, key)
		}
	}
	return b.Bytes()
}

// An absolute path, for ssh started without nk on its PATH (IDEs, cron).
func nkCommand() string {
	self, err := os.Executable()
	if err != nil {
		return "nk"
	}
	bin := self
	if found, lookErr := exec.LookPath("nk"); lookErr == nil && filepath.IsAbs(found) && sameFile(found, self) {
		bin = found
	}
	// ssh expands % and runs a shell, so unsafe paths fall back to PATH.
	unsafe := "\"$`%\\\n"
	if runtime.GOOS == "windows" {
		// Windows paths have backslashes, and no shell reads the line there.
		unsafe = "\"$`%\n"
	}
	if strings.ContainsAny(bin, unsafe) {
		return "nk"
	}
	if strings.ContainsAny(bin, " \t") {
		return `"` + bin + `"`
	}
	return bin
}

func sameFile(a, b string) bool {
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
}

func usable(t state.Target) bool {
	return len(t.Usernames) > 0 && targetName.MatchString(t.Name) && login.ValidUsername(t.Usernames[0])
}

// Control characters are the only thing that can break out of a key line.
func safeLine(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// ssh unescapes \\ and \", which Windows paths and quoted commands need.
func configValue(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// On top, because an Include after a Host line would be scoped to it.
func ensureInclude() error {
	path := userConfig()
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read ssh config: %w", err)
	}
	if HasInclude(data) {
		return nil
	}
	out := append([]byte(includeLine()+"\n\n"), data...)
	if err = fsutil.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("cannot update %s (%w), add this line at its top yourself:\n  %s", path, err, includeLine())
	}
	return nil
}

func includeLine() string {
	return "Include " + configValue(paths.SSHConfigFile())
}

func RemoveInclude() error {
	path := userConfig()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read ssh config: %w", err)
	}
	if !HasInclude(data) {
		return nil
	}
	var kept []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if !isInclude(line) {
			kept = append(kept, line)
		}
	}
	out := strings.TrimLeft(strings.Join(kept, "\n"), "\n")
	return fsutil.WriteFile(path, []byte(out), 0o600)
}

func HasInclude(data []byte) bool {
	for line := range strings.SplitSeq(string(data), "\n") {
		if isInclude(line) {
			return true
		}
	}
	return false
}

func isInclude(line string) bool {
	return strings.ReplaceAll(strings.TrimSpace(line), `"`, "") ==
		strings.ReplaceAll(includeLine(), `"`, "")
}

// Resolves symlinks, so dotfile managers keep their link.
func userConfig() string {
	path := paths.SSHUserConfig()
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}
