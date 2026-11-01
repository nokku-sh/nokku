package manual

import (
	"fmt"
	"strings"

	"github.com/nokku-sh/nokku/internal/login"
)

const (
	reloadMarker = "#nk reloaded"
	verifyMarker = "#nk verified"
)

// Signals run the EXIT trap. A dropped connection hits PIPE at the next echo.
const (
	exitOnSignal = "trap 'exit 1' HUP INT TERM PIPE"
	clearTraps   = "trap - EXIT HUP INT TERM PIPE"
)

// sshd on RHEL, ssh on Debian, and the pid file for hosts without systemd.
const reloadSSHD = `nk_reloaded=''
if systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null ||
  { [ -f /run/sshd.pid ] && kill -HUP "$(cat /run/sshd.pid)"; } ||
  { [ -f /var/run/sshd.pid ] && kill -HUP "$(cat /var/run/sshd.pid)"; }; then
  nk_reloaded=1
  echo '` + reloadMarker + `'
fi
`

// RemoveScript restores the drop-in if sshd -t fails or the run dies first.
const RemoveScript = "set -e\n" + requireRoot +
	`if [ -f ` + dropInPath + ` ]; then
  rm -f ` + dropInPath + `.nokku-bak
  trap 'if [ -f ` + dropInPath + `.nokku-bak ]; then mv -f ` + dropInPath + `.nokku-bak ` + dropInPath + `; fi' EXIT
  ` + exitOnSignal + `
  mv -f ` + dropInPath + ` ` + dropInPath + `.nokku-bak
  if ! sshd -t; then
    echo 'sshd rejects its config without the Nokku drop-in, nothing was removed' >&2
    exit 1
  fi
  ` + clearTraps + `
  rm -f ` + dropInPath + `.nokku-bak
  echo "removed   ` + dropInPath + `"
fi
if [ -f ` + caPath + ` ]; then
  rm -f ` + caPath + `
  echo "removed   ` + caPath + `"
fi
if [ -d ` + oldPrincipalsDir + ` ]; then
  rm -rf ` + oldPrincipalsDir + `
  echo "removed   ` + oldPrincipalsDir + `"
fi
` + reloadSSHD

// File is always 0644, which is what sshd wants for all of them.
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type Plan struct {
	Files []File
	// targetID is a placeholder before the target exists.
	targetID string
}

type Result struct {
	Reloaded bool
	Verified bool
}

// NewPlan takes an empty targetID for a new server, which only a dry run shows.
func NewPlan(caKey, targetID string) (Plan, error) {
	shown := "<target-id>"
	if targetID != "" {
		// The id lands in sshd_config, a line break would add a directive.
		if !login.ValidID(targetID) {
			return Plan{}, fmt.Errorf("the core sent an unusable target id %q, nothing was written", targetID)
		}
		shown = targetID
	}
	return Plan{targetID: shown, Files: []File{
		{Path: caPath, Content: strings.TrimSpace(caKey) + "\n"},
		{Path: dropInPath, Content: "TrustedUserCAKeys " + caPath + "\n" + login.PrincipalsCommand(shown)},
	}}, nil
}

func (p Plan) Script() string {
	var b strings.Builder
	b.WriteString("set -e\n" + requireRoot)
	b.WriteString("sshd -t || { echo 'the sshd config on this host is already invalid, fix it first' >&2; exit 1; }\n")
	fmt.Fprintf(&b, "mkdir -p %s\n", q(dropInDir))

	paths := make([]string, len(p.Files))
	for i, f := range p.Files {
		paths[i] = q(f.Path)
	}
	// A backup from a run that died early would restore a stale file.
	fmt.Fprintf(&b, "for f in %s; do rm -f \"$f.nokku-bak\"; done\n", strings.Join(paths, " "))
	b.WriteString("nk_new=''\nnk_restore() {\n  set +e\n")
	fmt.Fprintf(&b, "  for f in %s; do\n", strings.Join(paths, " "))
	b.WriteString("    if [ -f \"$f.nokku-bak\" ]; then mv -f \"$f.nokku-bak\" \"$f\"; fi\n  done\n")
	b.WriteString("  for f in $nk_new; do rm -f \"$f\"; done\n}\n")
	// Any exit before sshd accepts the result rolls back, Ctrl-C included.
	b.WriteString("trap nk_restore EXIT\n" + exitOnSignal + "\n")

	for _, f := range p.Files {
		path, content, tmp := q(f.Path), q(f.Content), q(f.Path+".nokku-tmp")
		fmt.Fprintf(&b, "if [ -f %s ] && printf '%%s' %s | cmp -s - %s; then\n", path, content, path)
		fmt.Fprintf(&b, "  echo \"unchanged %s\"\nelse\n", f.Path)
		fmt.Fprintf(
			&b,
			"  if [ -f %s ]; then cp -p %s %s; else nk_new=\"$nk_new \"%s; fi\n",
			path,
			path,
			q(f.Path+".nokku-bak"),
			path,
		)
		// Stage then rename, so sshd never reads a torn file.
		fmt.Fprintf(&b, "  printf '%%s' %s > %s\n  chmod 0644 %s\n  mv -f %s %s\n", content, tmp, tmp, tmp, path)
		fmt.Fprintf(&b, "  echo \"written   %s\"\nfi\n", f.Path)
	}

	b.WriteString("if ! sshd -t; then\n")
	b.WriteString("  echo 'sshd rejected the new config, every file was rolled back' >&2\n  exit 1\nfi\n")
	b.WriteString(clearTraps + "\n")
	fmt.Fprintf(&b, "for f in %s; do rm -f \"$f.nokku-bak\"; done\n", strings.Join(paths, " "))

	b.WriteString(reloadSSHD)
	// A running sshd may still read the old files until it reloads.
	fmt.Fprintf(
		&b,
		"if [ -n \"$nk_reloaded\" ] && [ -d %[1]s ]; then\n  rm -rf %[1]s\n  echo \"removed   %[2]s\"\nfi\n",
		q(oldPrincipalsDir),
		oldPrincipalsDir,
	)

	// A config without the Include line reloads fine and ignores the drop-in.
	// sshd -T prints lowercase keywords.
	command, _, _ := strings.Cut(login.PrincipalsCommand(p.targetID), "\n")
	keyword, value, _ := strings.Cut(command, " ")
	fmt.Fprintf(&b, "nk_cfg=$(sshd -T 2>/dev/null || true)\n")
	fmt.Fprintf(&b, "if echo \"$nk_cfg\" | grep -qi %s && echo \"$nk_cfg\" | grep -qi %s; then\n",
		q("^trustedusercakeys "+caPath), q("^"+strings.ToLower(keyword)+" "+value))
	fmt.Fprintf(&b, "  echo '%s'\nfi\n", verifyMarker)
	return b.String()
}

func ParseResult(out string) Result {
	return Result{
		Reloaded: strings.Contains(out, reloadMarker),
		Verified: strings.Contains(out, verifyMarker),
	}
}

func Output(out string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(out, "\n") {
		if line != "" && !strings.HasPrefix(line, "#nk ") {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

func q(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
