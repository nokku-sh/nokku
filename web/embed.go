// Package web embeds the built UI and email templates.
package web

import (
	"embed"
)

//go:embed ui/build/*
var UIFS embed.FS

//go:embed email/out/*.html
var EmailFS embed.FS
