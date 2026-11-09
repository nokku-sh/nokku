package manual

import (
	"embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/nokku-sh/nokku/internal/login"
)

const (
	reloadMarker = "#nk reloaded"
	verifyMarker = "#nk verified"
	keysMarker   = "#nk keys"
)

//go:embed scripts/*.tmpl
var scriptFS embed.FS

// A broken template fails the tests and the start, never a sync.
var scripts = template.Must(template.New("").Funcs(template.FuncMap{"q": q}).ParseFS(scriptFS, "scripts/*.tmpl"))

// The parsers and NewPlan use the same values, so the scripts get them from here.
var shared = scriptData{
	CA:             caPath,
	DropInDir:      dropInDir,
	DropIn:         dropInPath,
	OldPrincipals:  oldPrincipalsDir,
	PasswdSection:  sectionPasswd,
	HostKeySection: sectionHostKey,
	ReloadMarker:   reloadMarker,
	VerifyMarker:   verifyMarker,
	KeysMarker:     keysMarker,
}

// RemoveScript restores the drop-in if sshd -t fails or the run dies first.
var RemoveScript = render("remove.sh.tmpl", shared)

type scriptData struct {
	CA, DropInDir, DropIn, OldPrincipals string
	PasswdSection, HostKeySection        string
	ReloadMarker, VerifyMarker           string
	KeysMarker                           string

	// Only the sync script reads these.
	Files          []File
	Paths          string
	CommandPattern string
}

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
	// HomeKeys are the authorized keys files sshd reads from home directories.
	HomeKeys []string
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
	paths := make([]string, len(p.Files))
	for i, f := range p.Files {
		paths[i] = q(f.Path)
	}
	// sshd -T prints lowercase keywords.
	command, _, _ := strings.Cut(login.PrincipalsCommand(p.targetID), "\n")
	keyword, value, _ := strings.Cut(command, " ")

	d := shared
	d.Files = p.Files
	d.Paths = strings.Join(paths, " ")
	d.CommandPattern = "^" + strings.ToLower(keyword) + " " + value
	return render("sync.sh.tmpl", d)
}

func ParseResult(out string) Result {
	var keys strings.Builder
	for line := range strings.Lines(out) {
		if rest, ok := strings.CutPrefix(line, keysMarker+" "); ok {
			keys.WriteString(rest)
		}
	}
	return Result{
		Reloaded: strings.Contains(out, reloadMarker),
		Verified: strings.Contains(out, verifyMarker),
		HomeKeys: login.HomeKeyFiles(keys.String()),
	}
}

func Output(out string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(out, "\n") {
		if line != "" && !strings.HasPrefix(line, "#nk ") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// render panics because the templates are fixed and the tests run all of them.
func render(name string, data any) string {
	var b strings.Builder
	if err := scripts.ExecuteTemplate(&b, name, data); err != nil {
		panic(err)
	}
	return b.String()
}

func q(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
