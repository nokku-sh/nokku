package doctor

import (
	"fmt"
	"io"

	"github.com/nokku-sh/nokku/cli/internal/ui"
)

var glyph = map[Status]string{
	StatusOK:   "✔",
	StatusWarn: "⚠",
	StatusFail: "✖",
	StatusInfo: "ℹ",
}

func color(status Status) func(string) string {
	switch status {
	case StatusOK:
		return ui.Green
	case StatusWarn:
		return ui.Yellow
	case StatusFail:
		return ui.Red
	case StatusInfo:
		return ui.Dim
	default:
		return ui.Dim
	}
}

// Print writes the report to w as text.
func Print(w io.Writer, r Report) {
	for _, f := range r.Fixes {
		fmt.Fprintf(w, "  %s %s\n", ui.Green("✔"), f)
	}
	if len(r.Fixes) > 0 {
		fmt.Fprintln(w)
	}

	width := 0
	for _, c := range r.Checks {
		width = max(width, len(c.Name))
	}
	var lastSection string
	for _, c := range r.Checks {
		if c.Section != lastSection {
			if lastSection != "" {
				fmt.Fprintln(w)
			}
			fmt.Fprintln(w, ui.Bold(c.Section))
			lastSection = c.Section
		}
		paint := color(c.Status)
		glyph := paint(glyph[c.Status])
		name := ui.Bold(fmt.Sprintf("%-*s", width, c.Name))
		if c.Detail != "" {
			fmt.Fprintf(w, "  %s %s  %s\n", glyph, name, ui.Dim(c.Detail))
		} else {
			fmt.Fprintf(w, "  %s %s\n", glyph, name)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, summarize(r))
}

func summarize(r Report) string {
	var ok, warn, fail int
	for _, c := range r.Checks {
		switch c.Status {
		case StatusOK:
			ok++
		case StatusWarn:
			warn++
		case StatusFail:
			fail++
		case StatusInfo:
		}
	}

	line := fmt.Sprintf("Result: %d ok, %d warn, %d fail", ok, warn, fail)
	switch {
	case fail > 0:
		return ui.Red(line + " (run `nk doctor --fix` or `nk login`)")
	case warn > 0:
		return ui.Yellow(line + " (see warnings above)")
	default:
		return ui.Green(line + " (all good)")
	}
}
