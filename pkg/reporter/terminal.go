package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/rickyruima/blastradius/pkg/rules"
	"github.com/rickyruima/blastradius/pkg/scorer"
)

// Terminal writes a colored terminal report to w.
func Terminal(w io.Writer, result scorer.Result, useColor bool) {
	if !useColor {
		color.NoColor = true
		defer func() { color.NoColor = false }()
	}

	levelColor := levelColorFn(result.Level)
	fmt.Fprintf(w, "\n  Blast Radius: %s (%s/10)\n\n",
		levelColor(result.Level),
		levelColor(fmt.Sprintf("%.1f", result.Overall)),
	)

	p := result.Plan
	total := p.TotalCreate + p.TotalUpdate + p.TotalDelete + p.TotalReplace
	fmt.Fprintf(w, "  Summary\n")
	fmt.Fprintf(w, "    %d resources affected", total)
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
	if len(parts) > 0 {
		fmt.Fprintf(w, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintf(w, "\n\n")

	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "  No risks detected. All changes appear safe.\n\n")
		return
	}

	critical := filterBySeverity(result.Findings, rules.SeverityCritical)
	high := filterBySeverity(result.Findings, rules.SeverityHigh)
	medium := filterBySeverity(result.Findings, rules.SeverityMedium)
	low := filterBySeverity(result.Findings, rules.SeverityLow)

	fmt.Fprintf(w, "  Risks\n")
	printFindings(w, critical, color.New(color.FgRed, color.Bold).SprintFunc())
	printFindings(w, high, color.New(color.FgRed).SprintFunc())
	printFindings(w, medium, color.New(color.FgYellow).SprintFunc())
	printFindings(w, low, color.New(color.FgWhite).SprintFunc())
	fmt.Fprintln(w)
}

func printFindings(w io.Writer, findings []rules.Finding, colorFn func(a ...interface{}) string) {
	for _, f := range findings {
		severity := strings.ToUpper(string(f.Rule.Severity))
		fmt.Fprintf(w, "    [%s] %s\n", colorFn(severity), f.Resource.Address)
		fmt.Fprintf(w, "             %s\n", f.Rule.Description)
	}
}

func filterBySeverity(findings []rules.Finding, severity rules.Severity) []rules.Finding {
	var out []rules.Finding
	for _, f := range findings {
		if f.Rule.Severity == severity {
			out = append(out, f)
		}
	}
	return out
}

func levelColorFn(level string) func(a ...interface{}) string {
	switch level {
	case "CRITICAL":
		return color.New(color.FgRed, color.Bold).SprintFunc()
	case "HIGH":
		return color.New(color.FgRed).SprintFunc()
	case "MEDIUM":
		return color.New(color.FgYellow).SprintFunc()
	default:
		return color.New(color.FgGreen).SprintFunc()
	}
}
