// Package namegen produces display names like "sunny-otter". Callers enforce uniqueness.
package namegen

import (
	"crypto/rand"
	"math/big"
	"regexp"
	"strings"
	"unicode"
)

var adjectives = []string{
	"amber", "ancient", "autumn", "azure", "bold", "brave", "bright", "calm",
	"cheerful", "clever", "cobalt", "cosmic", "crimson", "crisp", "curious",
	"daring", "dreamy", "eager", "fair", "fearless", "festive", "foggy",
	"frozen", "gentle", "golden", "graceful", "grand", "green", "happy",
	"hardy", "hopeful", "humble", "ivory", "jolly", "jovial", "keen", "kind",
	"lavender", "lively", "loyal", "lucky", "lunar", "merry", "mighty",
	"misty", "mossy", "nimble", "noble", "onyx", "patient", "peaceful",
	"perky", "playful", "plucky", "polished", "polite", "proud", "quick",
	"quiet", "radiant", "rapid", "ready", "rosy", "ruby", "russet", "scarlet",
	"serene", "sharp", "shiny", "silent", "silver", "sleek", "sleepy",
	"smooth", "snowy", "solar", "sparkling", "spry", "steady", "stormy",
	"sturdy", "sunny", "swift", "teal", "tender", "tidal", "tiny", "tranquil",
	"upbeat", "velvet", "vibrant", "vivid", "warm", "wild", "wise", "witty",
	"zealous",
}

var nouns = []string{
	"badger", "basil", "bay", "beacon", "beaver", "birch", "blossom",
	"boulder", "breeze", "brook", "cactus", "canyon", "cedar", "cherry",
	"clover", "comet", "coral", "crane", "creek", "daisy", "dolphin", "dove",
	"drift", "eagle", "echo", "elk", "ember", "falcon", "fern", "finch",
	"fjord", "flamingo", "forest", "fox", "frost", "galaxy", "garden",
	"gecko", "glacier", "grove", "gull", "harbor", "hare", "hawk", "heron",
	"hill", "horizon", "hummingbird", "island", "islet", "ivy", "jay",
	"juniper", "kelp", "lagoon", "lake", "lantern", "lark", "laurel", "leaf",
	"lily", "lotus", "lynx", "maple", "meadow", "mesa", "meteor", "mist",
	"moss", "moth", "mountain", "newt", "oak", "oasis", "ocean", "osprey",
	"otter", "owl", "panda", "parrot", "pebble", "penguin", "petal", "pine",
	"plum", "pond", "puffin", "quail", "rabbit", "raven", "reef", "ridge",
	"river", "robin", "rose", "salmon", "sand", "sea", "seagull", "sequoia",
	"shell", "shore", "sky", "sparrow", "spruce", "squirrel", "star",
	"stream", "summit", "sun", "swan", "tide", "trout", "tulip", "valley",
	"violet", "warbler", "willow", "wolf", "wren", "yarrow", "zephyr",
}

func Generate() string {
	return word(adjectives) + "-" + word(nouns)
}

func word(list []string) string {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(list))))
	if err != nil {
		return list[0] // degrade to the first entry
	}
	return list[n.Int64()]
}

// maxHostnameLen is the DNS label limit, so a longer name was not typed by a person.
const maxHostnameLen = 63

var (
	hostnameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	// defaultHostRE matches what cloud images and container runtimes hand out when nobody picked a name.
	defaultHostRE = regexp.MustCompile(`^(` +
		`ip-\d+-\d+-\d+-\d+` + // AWS
		`|[0-9a-f]{12}` + // Docker
		`|instance-\d+` + // GCP
		`|(vps|srv|server|host|vm|node|box|machine|instance|default|localhost` +
		`|ubuntu|debian|fedora|centos|rocky|alma|alpine|arch|linux|rhel|amazon|ec2|test)-?\d*` +
		`)$`)
)

// FromHostname turns a hostname into a target name when a person chose it. Image and cloud defaults, and names
// that are mostly digits, are left to Generate. Kubernetes pod names pass, they are what kubectl shows.
func FromHostname(host string) (string, bool) {
	name, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(host)), ".")
	name = strings.Trim(strings.ReplaceAll(name, "_", "-"), "-")
	if name == "" || len(name) > maxHostnameLen || !hostnameRE.MatchString(name) || defaultHostRE.MatchString(name) {
		return "", false
	}
	var letters, digits int
	for _, r := range name {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsDigit(r):
			digits++
		}
	}
	if digits > letters {
		return "", false
	}
	return name, true
}
