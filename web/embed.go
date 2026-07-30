// Package web embeds various files for the backend
package web

import (
	"embed"
)

//go:embed ui/build/*
var UIFS embed.FS

//go:embed email/out/*.html
var EmailFS embed.FS
