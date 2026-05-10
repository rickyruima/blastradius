package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/rickyruima/blastradius/pkg/rules"
	"github.com/rickyruima/blastradius/pkg/scorer"
)

// Markdown writes the result as GitHub-flavored markdown to w.
func Markdown(w io.Writer, result scorer.Result) {
	fmt.Fprintf(w, "# Blast Radius: %s (%.1f/10)\n\n", result.Level, result.Overall)

	p := result.Plan
	total := p.TotalCreate + p.TotalUpdate + p.TotalDelete + p.TotalReplace
	fmt.Fprintf(w, "**%d resources affected** — ", total)
	parts := []string{}
	if p.TotalCreate > 0 {
		parts = append(parts, fmt.Sprintf("%d create", p.TotalCreate))
	}
	if p.TotalUpdate > 0 {
		parts = append(parts, fmt.Sprintf("%d update", p.TotalUpdate))
	}
	if p.TotalDelete > 0 {
		parts = append(parts, fmt.Sprintf("%d destroy", p.TotalDelete))
	}
	if p.TotalReplace > 0 {
		parts = append(parts, fmt.Sprintf("%d replace", p.TotalReplace))
	}
	fmt.Fprintf(w, "%s\n\n", strings.Join(parts, ", "))

	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "> No risks detected. All changes appear safe.\n")
		return
	}

	fmt.Fprintf(w, "## Risks\n\n")
	fmt.Fprintf(w, "| Severity | Resource | Description |\n")
	fmt.Fprintf(w, "|----------|----------|-------------|\n")
	for _, f := range result.Findings {
		sev := severityEmoji(f.Rule.Severity) + " " + strings.ToUpper(string(f.Rule.Severity))
		fmt.Fprintf(w, "| %s | `%s` | %s |\n", sev, f.Resource.Address, f.Rule.Description)
	}
	fmt.Fprintln(w)
}

func severityEmoji(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return "🔴"
	case rules.SeverityHigh:
		return "🟠"
	case rules.SeverityMedium:
		return "🟡"
	default:
		return "⚪"
	}
}
