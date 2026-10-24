package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/mizuchilabs/kata/fsutil"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

const header = "# Managed by Nokku. nk regenerates this file, do not edit it.\n\n"

// Held to what the core itself allows. Anything wider could claim a real host like github.com or reach the shell.
var (
	targetName  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)
	accountName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]*$`)
)

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

// nk's Include sits on top of the user's config, so a bare name there would take over a host of their own.
func hostAliases(s *state.State, own ownHosts) map[string]string {
	// Case is folded. ssh's Match does not tell Web from web, and neither does a person.
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
	var b bytes.Buffer
	b.WriteString(header)
	for _, t := range s.Targets {
		host, ok := aliases[t.ID]
		if !ok {
			continue
		}

		// ssh loads CertificateFile before ProxyCommand, so Match exec renews first. It lowercases %h, hence the id.
		fmt.Fprintf(&b, `Match originalhost %s exec %s

Host %s
    User %s
    ProxyCommand %s proxy %s %%p
    HostKeyAlias %s
    CertificateFile %s
    IdentityFile %s
    IdentityAgent %s
    UserKnownHostsFile %s
    IdentitiesOnly yes
    PasswordAuthentication no
    StrictHostKeyChecking yes
    ForwardAgent no
    ForwardX11 no
    ServerAliveInterval 60
    LogLevel ERROR

`, host, configValue(nk+" prepare "+t.ID), host, t.Usernames[0], nk, t.ID, t.ID,
			configValue(paths.SSHCertificate(t.ID)), configValue(paths.PubKeyFile()),
			configValue(paths.AgentSocket()), configValue(paths.KnownHostsFile()))
	}
	return b.Bytes()
}

// Trust is scoped to the target id, the HostKeyAlias in ssh_config, never a global "*".
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
		ca := s.CAByID(t.CAID)
		if ca == nil {
			continue
		}
		// A daemon that missed a rollover still shows a host certificate from the replaced key.
		for _, key := range ca.TrustedHostKeys() {
			if safeLine(key) {
				fmt.Fprintf(&b, "@cert-authority %s %s\n", t.ID, key)
			}
		}
	}
	return b.Bytes()
}

// An absolute path, so ssh started without nk on its PATH (IDEs, cron, git GUIs) still finds this nk.
func nkCommand() string {
	self, err := os.Executable()
	if err != nil {
		return "nk"
	}
	bin := self
	if found, lookErr := exec.LookPath("nk"); lookErr == nil && filepath.IsAbs(found) && sameFile(found, self) {
		bin = found
	}
	// ssh expands % tokens and hands the line to a shell, so what a quoted path cannot carry falls back to PATH.
	unsafe := "\"$`%\\\n"
	if runtime.GOOS == "windows" {
		// Every Windows path has a backslash, and no shell reads the line there.
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
	return len(t.Usernames) > 0 && targetName.MatchString(t.Name) && accountName.MatchString(t.Usernames[0])
}

// Control characters are the only thing that can break out of a key line.
func safeLine(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// Quotes cover spaces, and ssh unescapes \\ and \", which Windows paths and quoted commands need.
func configValue(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

func includeLine() string {
	return "Include " + configValue(paths.SSHConfigFile())
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

// Resolved through symlinks, so dotfile managers keep their link and nk edits the real file.
func userConfig() string {
	path := paths.SSHUserConfig()
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}
