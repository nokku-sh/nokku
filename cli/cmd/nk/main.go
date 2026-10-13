package main

import (
	"fmt"
	"os"

	"github.com/mizuchilabs/kata/sigx"

	"github.com/nokku-sh/nokku/cli/internal/cmd"
	"github.com/nokku-sh/nokku/cli/internal/ui"
)

func main() {
	root := cmd.Root()
	if err := root.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", root.Name, ui.Plain(err.Error()))
		os.Exit(1)
	}
}
