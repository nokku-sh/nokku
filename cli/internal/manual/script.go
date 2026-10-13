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

// reloadSSHD prints reloadMarker when sshd took the reload. systemd calls the
// unit sshd on RHEL and ssh on Debian, the pid file covers hosts without
// systemd.
const reloadSSHD = `if systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null ||
  { [ -f /run/sshd.pid ] && kill -HUP "$(cat /run/sshd.pid)"; } ||
  { [ -f /var/run/sshd.pid ] && kill -HUP "$(cat /var/run/sshd.pid)"; }; then
  echo '` + reloadMarker + `'
fi
`

// RemoveScript undoes a manual sync. The drop-in goes first and comes back
// when sshd rejects the config without it, so a failed run changes nothing.
const RemoveScript = "set -e\n" + requireRoot +
	`if [ -f ` + dropInPath + ` ]; then
  mv -f ` + dropInPath + ` ` + dropInPath + `.nokku-bak
  if ! sshd -t; then
    mv -f ` + dropInPath + `.nokku-bak ` + dropInPath + `
    echo 'sshd rejects its config without the Nokku drop-in, nothing was removed' >&2
    exit 1
  fi
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

// File is one file a manual sync writes. Every file is 0644, which is what
// sshd wants for all of them.
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Plan is everything one sync changes on a host.
type Plan struct {
	Files []File
	// Stale are principals files whose account no longer exists.
	Stale []string
}

// NewPlan renders the CA key, the drop-in, and one principals file per local
// account. An account without grants still gets an empty file, so a revoked
// grant denies by default.
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

// Script writes the plan idempotently. It refuses a host whose sshd config is
// already broken, rolls every file back when sshd rejects the result, and
// only then removes stale files and reloads sshd.
func (p Plan) Script() string {
	var b strings.Builder
	b.WriteString("set -e\n" + requireRoot)
	b.WriteString("sshd -t || { echo 'the sshd config on this host is already invalid, fix it first' >&2; exit 1; }\n")
	fmt.Fprintf(&b, "mkdir -p %s %s\nchmod 0755 %s\n", q(principalsDir), q(dropInDir), q(principalsDir))

	paths := make([]string, len(p.Files))
	for i, f := range p.Files {
		paths[i] = q(f.Path)
	}
	b.WriteString("nk_new=''\nnk_restore() {\n")
	fmt.Fprintf(&b, "  for f in %s; do\n", strings.Join(paths, " "))
	b.WriteString("    if [ -f \"$f.nokku-bak\" ]; then mv -f \"$f.nokku-bak\" \"$f\"; fi\n  done\n")
	b.WriteString("  for f in $nk_new; do rm -f \"$f\"; done\n}\n")

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

	b.WriteString("if ! sshd -t; then\n  nk_restore\n")
	b.WriteString("  echo 'sshd rejected the new config, every file was rolled back' >&2\n  exit 1\nfi\n")
	fmt.Fprintf(&b, "for f in %s; do rm -f \"$f.nokku-bak\"; done\n", strings.Join(paths, " "))
	for _, path := range p.Stale {
		fmt.Fprintf(&b, "rm -f %s\necho \"removed   %s\"\n", q(path), path)
	}

	b.WriteString(reloadSSHD)

	// A reload does not prove sshd read the drop-in. A config without the
	// Include line, or one that sets these options first, ignores it.
	fmt.Fprintf(&b, "nk_cfg=$(sshd -T 2>/dev/null || true)\n")
	fmt.Fprintf(&b, "if echo \"$nk_cfg\" | grep -qi %s && echo \"$nk_cfg\" | grep -qi %s; then\n",
		q("^trustedusercakeys "+caPath), q("^authorizedprincipalsfile "+principalsDir+"/%u"))
	fmt.Fprintf(&b, "  echo '%s'\nfi\n", verifyMarker)
	return b.String()
}

// Result is what the write script reported.
type Result struct {
	Reloaded bool
	Verified bool
}

// ParseResult reads the markers the script prints.
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
