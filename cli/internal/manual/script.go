package manual

import (
	"fmt"
	"slices"
	"strings"
)

const (
	reloadMarker = "#nk reloaded"
	verifyMarker = "#nk verified"
)

// A signal ends the script through its EXIT trap. PIPE matters: a dropped connection kills the shell at its next echo.
const (
	exitOnSignal = "trap 'exit 1' HUP INT TERM PIPE"
	clearTraps   = "trap - EXIT HUP INT TERM PIPE"
)

// systemd calls the unit sshd on RHEL and ssh on Debian, the pid file covers hosts without systemd.
const reloadSSHD = `if systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null ||
  { [ -f /run/sshd.pid ] && kill -HUP "$(cat /run/sshd.pid)"; } ||
  { [ -f /var/run/sshd.pid ] && kill -HUP "$(cat /var/run/sshd.pid)"; }; then
  echo '` + reloadMarker + `'
fi
`

// RemoveScript puts the drop-in back when sshd rejects the config without it, or the run dies before sshd -t.
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
if [ -d ` + principalsDir + ` ]; then
  rm -rf ` + principalsDir + `
  echo "removed   ` + principalsDir + `"
fi
` + reloadSSHD

// File is always 0644, which is what sshd wants for all of them.
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type Plan struct {
	Files []File
	// Stale are principals files whose account no longer exists.
	Stale []string
}

// NewPlan gives an account without grants an empty file, so a revoked grant denies by default.
func NewPlan(caKey string, grants map[string][]string, h Host) Plan {
	p := Plan{Files: []File{
		{Path: caPath, Content: strings.TrimSpace(caKey) + "\n"},
		{
			Path:    dropInPath,
			Content: "TrustedUserCAKeys " + caPath + "\nAuthorizedPrincipalsFile " + principalsDir + "/%u\n",
		},
	}}
	for _, name := range h.Accounts {
		p.Files = append(p.Files, File{Path: principalsDir + "/" + name, Content: renderPrincipals(grants[name])})
	}
	for _, name := range h.Principals {
		if safeName(name) && !slices.Contains(h.Accounts, name) {
			p.Stale = append(p.Stale, principalsDir+"/"+name)
		}
	}
	return p
}

// Script refuses a host with a broken sshd config, rolls back on any exit before sshd accepts the result, then reloads.
func (p Plan) Script() string {
	var b strings.Builder
	b.WriteString("set -e\n" + requireRoot)
	b.WriteString("sshd -t || { echo 'the sshd config on this host is already invalid, fix it first' >&2; exit 1; }\n")
	fmt.Fprintf(&b, "mkdir -p %s %s\nchmod 0755 %s\n", q(principalsDir), q(dropInDir), q(principalsDir))

	paths := make([]string, len(p.Files))
	for i, f := range p.Files {
		paths[i] = q(f.Path)
	}
	// A backup left by a run that died before its trap existed would restore a stale file.
	fmt.Fprintf(&b, "for f in %s; do rm -f \"$f.nokku-bak\"; done\n", strings.Join(paths, " "))
	b.WriteString("nk_new=''\nnk_restore() {\n  set +e\n")
	fmt.Fprintf(&b, "  for f in %s; do\n", strings.Join(paths, " "))
	b.WriteString("    if [ -f \"$f.nokku-bak\" ]; then mv -f \"$f.nokku-bak\" \"$f\"; fi\n  done\n")
	b.WriteString("  for f in $nk_new; do rm -f \"$f\"; done\n}\n")
	// Any exit before sshd accepts the result rolls back, a failed write and Ctrl-C included.
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
	for _, path := range p.Stale {
		fmt.Fprintf(&b, "rm -f %s\necho \"removed   %s\"\n", q(path), path)
	}

	b.WriteString(reloadSSHD)

	// A reload does not prove sshd read the drop-in. A config without the Include line ignores it.
	fmt.Fprintf(&b, "nk_cfg=$(sshd -T 2>/dev/null || true)\n")
	fmt.Fprintf(&b, "if echo \"$nk_cfg\" | grep -qi %s && echo \"$nk_cfg\" | grep -qi %s; then\n",
		q("^trustedusercakeys "+caPath), q("^authorizedprincipalsfile "+principalsDir+"/%u"))
	fmt.Fprintf(&b, "  echo '%s'\nfi\n", verifyMarker)
	return b.String()
}

type Result struct {
	Reloaded bool
	Verified bool
}

func ParseResult(out string) Result {
	return Result{
		Reloaded: strings.Contains(out, reloadMarker),
		Verified: strings.Contains(out, verifyMarker),
	}
}

// Output drops the markers, leaving what the operator should see.
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
