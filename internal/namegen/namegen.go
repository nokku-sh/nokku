// Package namegen produces display names like "sunny-otter". Callers enforce
// uniqueness.
package namegen

import (
	"crypto/rand"
	"math/big"
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
