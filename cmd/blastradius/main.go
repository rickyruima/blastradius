package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rickyruima/blastradius/pkg/config"
	"github.com/rickyruima/blastradius/pkg/graph"
	"github.com/rickyruima/blastradius/pkg/parser"
	"github.com/rickyruima/blastradius/pkg/reporter"
	"github.com/rickyruima/blastradius/pkg/rules"
	"github.com/rickyruima/blastradius/pkg/scorer"
)

var version = "0.1.0"

func main() {
	root := &cobra.Command{
		Use:     "blastradius",
		Short:   "Terraform plan blast radius analyzer",
		Version: version,
	}

	var (
		configPath string
		format     string
		threshold  string
	)

	scan := &cobra.Command{
		Use:   "scan <plan.json>",
		Short: "Analyze a terraform plan JSON for risk",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(args[0], configPath, format, threshold)
		},
	}

	scan.Flags().StringVarP(&configPath, "config", "c", ".blastradius.yaml", "path to config file")
	scan.Flags().StringVarP(&format, "format", "f", "terminal", "output format: terminal, json, markdown")
	scan.Flags().StringVarP(&threshold, "threshold", "t", "high", "minimum risk level to fail: low, medium, high, critical")

	root.AddCommand(scan)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func shouldFail(level, threshold string) bool {
	levels := map[string]int{"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
	return levels[strings.ToUpper(level)] >= levels[strings.ToUpper(threshold)]
}

func runScan(planPath, configPath, format, threshold string) error {
	data, err := os.ReadFile(planPath)
	if err != nil {
		return fmt.Errorf("read plan file: %w", err)
	}

	plan, err := parser.Parse(data)
	if err != nil {
		return fmt.Errorf("parse plan: %w", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	allRules, err := rules.LoadEmbedded()
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}

	var activeRules []rules.Rule
	for _, r := range allRules {
		if !cfg.ShouldIgnoreRule(r.ID) {
			activeRules = append(activeRules, r)
		}
	}

	engine := rules.NewEngine(activeRules)
	findings := engine.Evaluate(plan.Resources)

	depGraph := graph.Build(plan.Resources)
	_, maxImpact := depGraph.MaxImpact()

	result := scorer.Score(findings, plan, maxImpact)

	switch format {
	case "json":
		if err := reporter.JSON(os.Stdout, result); err != nil {
			return err
		}
	case "markdown":
		reporter.Markdown(os.Stdout, result)
	default:
		reporter.Terminal(os.Stdout, result, true)
	}

	if shouldFail(result.Level, threshold) {
		os.Exit(2)
	}
	return nil
}
