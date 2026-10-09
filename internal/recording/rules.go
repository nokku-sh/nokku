package recording

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/pelletier/go-toml/v2"
)

// The secret detection rules are the gitleaks default config, embedded as
// the file it ships. Only the parts that apply to a terminal stream are
// read: regex, keywords, entropy, secret group and regex allowlists. Path,
// commit and stopword allowlists have nothing to match here.
//
//go:embed gitleaks.toml
var gitleaksRules []byte

// What gitleaks has no rule for, and a terminal shows all the time.
//
//go:embed nokku.toml
var nokkuRules []byte

type scrubAllowlist struct {
	// target is what the regexes are matched against: the secret, or the
	// whole match for "match" and "line".
	target  string
	regexes []*regexp.Regexp
}

type scrubRule struct {
	regex       *regexp.Regexp
	keywords    []string
	entropy     float64
	secretGroup int
	allowlists  []scrubAllowlist
}

type scrubRuleSet struct {
	rules []scrubRule
	// allowlists apply to every rule.
	allowlists []scrubAllowlist
	// keywords is one prefilter for all rules. A blob without any keyword
	// skips every rule that has keywords.
	keywords *regexp.Regexp
}

var scrubRules = sync.OnceValues(func() (*scrubRuleSet, error) {
	type allowlist struct {
		RegexTarget string   `toml:"regexTarget"`
		Regexes     []string `toml:"regexes"`
	}
	type rules struct {
		Allowlist  *allowlist  `toml:"allowlist"`
		Allowlists []allowlist `toml:"allowlists"`
		Rules      []struct {
			ID          string      `toml:"id"`
			Regex       string      `toml:"regex"`
			SecretGroup int         `toml:"secretGroup"`
			Entropy     float64     `toml:"entropy"`
			Keywords    []string    `toml:"keywords"`
			Allowlists  []allowlist `toml:"allowlists"`
		} `toml:"rules"`
	}
	var file, more rules
	if err := toml.Unmarshal(gitleaksRules, &file); err != nil {
		return nil, fmt.Errorf("parse gitleaks rules: %w", err)
	}
	if err := toml.Unmarshal(nokkuRules, &more); err != nil {
		return nil, fmt.Errorf("parse nokku rules: %w", err)
	}
	file.Rules = append(file.Rules, more.Rules...)

	compile := func(lists []allowlist) ([]scrubAllowlist, error) {
		var out []scrubAllowlist
		for _, l := range lists {
			al := scrubAllowlist{target: l.RegexTarget}
			for _, expr := range l.Regexes {
				re, err := regexp.Compile(expr)
				if err != nil {
					return nil, err
				}
				al.regexes = append(al.regexes, re)
			}
			out = append(out, al)
		}
		return out, nil
	}

	set := &scrubRuleSet{}
	global := file.Allowlists
	if file.Allowlist != nil {
		global = append(global, *file.Allowlist)
	}
	var err error
	if set.allowlists, err = compile(global); err != nil {
		return nil, fmt.Errorf("global allowlist: %w", err)
	}

	seen := map[string]struct{}{}
	var keywords []string
	for _, r := range file.Rules {
		// Rules without a regex only match file paths. A private key has a
		// matcher of its own, keyBlockSpans says why.
		if r.Regex == "" || r.ID == "private-key" {
			continue
		}
		rule := scrubRule{entropy: r.Entropy, secretGroup: r.SecretGroup}
		if rule.regex, err = regexp.Compile(r.Regex); err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		if rule.allowlists, err = compile(r.Allowlists); err != nil {
			return nil, fmt.Errorf("rule %s allowlist: %w", r.ID, err)
		}
		for _, kw := range r.Keywords {
			kw = strings.ToLower(kw)
			rule.keywords = append(rule.keywords, kw)
			if _, ok := seen[kw]; !ok {
				seen[kw] = struct{}{}
				keywords = append(keywords, regexp.QuoteMeta(kw))
			}
		}
		set.rules = append(set.rules, rule)
	}
	if set.keywords, err = regexp.Compile(`(?i)(?:` + strings.Join(keywords, "|") + `)`); err != nil {
		return nil, fmt.Errorf("keyword prefilter: %w", err)
	}
	return set, nil
})
