// Package web embeds the built UI and email templates. Both directories hold
// a committed .gitkeep so the Go build works without node.
package web

import (
	"embed"
)

//go:embed all:ui/build
var UIFS embed.FS

//go:embed all:email/out
var EmailFS embed.FS
