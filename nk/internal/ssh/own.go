package ssh

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/nokku-sh/nokku/nk/internal/paths"
)

// ssh stops following Include at this depth too.
const maxIncludeDepth = 16

// maxOwnFiles and maxOwnFileSize bound what a wide Include glob can pull in.
const (
	maxOwnFiles    = 256
	maxOwnFileSize = 1 << 20
)

// ownBlock is one Host or Match block of the user's own ssh config.
type ownBlock struct {
	// patterns are lowercased, see hostAliases. A leading ! negates.
	patterns []string
	// dest is set when the block says where to connect. A block without it
	// only adds options, to a Nokku server too.
	dest bool
}

type ownHosts []*ownBlock

// claims reports whether the user's config sends name somewhere itself.
func (o ownHosts) claims(name string) bool {
	name = strings.ToLower(name)
	for _, b := range o {
		if b.dest && b.matches(name) {
			return true
		}
	}
	return false
}

// matches follows ssh: one pattern has to match and no negated one may. A
// pattern of wildcards only, like the usual Host *, holds defaults and names
// nothing.
func (b *ownBlock) matches(name string) bool {
	named := false
	for _, raw := range b.patterns {
		p, negated := strings.CutPrefix(raw, "!")
		// ssh patterns know * and ? only, and a name has no / in it.
		if ok, _ := path.Match(p, name); !ok {
			continue
		}
		if negated {
			return false
		}
		named = named || strings.Trim(p, "*?") != ""
	}
	return named
}

type ownReader struct {
	blocks ownHosts
	// cur outlives an Include, the way ssh keeps its active block.
	cur   *ownBlock
	files int
}

// readOwnHosts reads ~/.ssh/config and what it includes, without the file nk
// writes there. What it cannot read or parse it skips.
func readOwnHosts() ownHosts {
	var r ownReader
	r.read(userConfig(), 0)
	return r.blocks
}

func (r *ownReader) read(file string, depth int) {
	if depth > maxIncludeDepth || r.files >= maxOwnFiles || sameFile(file, paths.SSHConfigFile()) {
		return
	}
	// A glob can match a socket or a pipe, and opening a pipe blocks.
	fi, err := os.Stat(file)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxOwnFileSize {
		return
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}
	r.files++
	for line := range strings.SplitSeq(string(data), "\n") {
		key, args := configLine(line)
		switch key {
		case "host":
			for i := range args {
				args[i] = strings.ToLower(args[i])
			}
			r.cur = &ownBlock{patterns: args}
			r.blocks = append(r.blocks, r.cur)
		case "match":
			r.cur = &ownBlock{patterns: matchHosts(args)}
			r.blocks = append(r.blocks, r.cur)
		case "hostname", "proxyjump", "proxycommand":
			if r.cur != nil {
				r.cur.dest = true
			}
		case "include":
			for _, arg := range args {
				for _, f := range includedFiles(arg) {
					r.read(f, depth+1)
				}
			}
		}
	}
}

// configLine splits an ssh_config line into its lowercased keyword and its
// arguments. ssh takes whitespace or one = after the keyword, double quotes
// around an argument, and a # that ends the line.
func configLine(line string) (string, []string) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return "", nil
	}
	key, rest := line, ""
	if i := strings.IndexAny(line, " \t="); i >= 0 {
		key, rest = line[:i], strings.TrimLeft(line[i:], " \t")
		rest = strings.TrimPrefix(rest, "=")
	}

	var args []string
	var arg strings.Builder
	quoted, open := false, false
	for _, c := range rest + " " {
		switch {
		case c == '"':
			quoted, open = !quoted, true
		case quoted || !strings.ContainsRune(" \t#", c):
			arg.WriteRune(c)
			open = true
		default:
			if open {
				args = append(args, arg.String())
				arg.Reset()
				open = false
			}
			if c == '#' {
				return strings.ToLower(key), args
			}
		}
	}
	return strings.ToLower(key), args
}

// matchHosts picks the host patterns out of a Match line. Its other criteria
// only narrow the block, so leaving them out errs toward the user's side.
func matchHosts(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "all", "final", "canonical":
		case "host", "originalhost":
			if i+1 < len(args) {
				out = append(out, strings.Split(strings.ToLower(args[i+1]), ",")...)
			}
			i++
		default:
			// Every other criterion takes one argument.
			i++
		}
	}
	return out
}

// includedFiles resolves one Include argument the way ssh does for a user
// config: ~ is the home directory and a relative path starts in ~/.ssh.
func includedFiles(arg string) []string {
	if rest, ok := strings.CutPrefix(arg, "~"); ok && (rest == "" || strings.ContainsRune(`/\`, rune(rest[0]))) {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		arg = filepath.Join(home, rest)
	}
	if !filepath.IsAbs(arg) {
		arg = filepath.Join(filepath.Dir(paths.SSHUserConfig()), arg)
	}
	files, _ := filepath.Glob(arg)
	return files
}
