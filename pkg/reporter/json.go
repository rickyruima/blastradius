package reporter

import (
	"encoding/json"
	"io"

	"github.com/rickyruima/blastradius/pkg/scorer"
)

type jsonReport struct {
	Overall    float64            `json:"overall"`
	Level      string             `json:"level"`
	Dimensions map[string]float64 `json:"dimensions"`
	Findings   []jsonFinding      `json:"findings"`
	Summary    jsonSummary        `json:"summary"`
}

type jsonFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Resource    string `json:"resource"`
	Description string `json:"description"`
}

type jsonSummary struct {
	TotalCreate  int `json:"create"`
	TotalUpdate  int `json:"update"`
	TotalDelete  int `json:"delete"`
	TotalReplace int `json:"replace"`
}

// JSON writes the result as JSON to w.
func JSON(w io.Writer, result scorer.Result) error {
	dims := make(map[string]float64)
	for k, v := range result.Dimensions {
		dims[string(k)] = v
	}

	findings := make([]jsonFinding, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, jsonFinding{
			RuleID:      f.Rule.ID,
			Severity:    string(f.Rule.Severity),
			Resource:    f.Resource.Address,
			Description: f.Rule.Description,
		})
	}

	report := jsonReport{
		Overall:    result.Overall,
		Level:      result.Level,
		Dimensions: dims,
		Findings:   findings,
		Summary: jsonSummary{
			TotalCreate:  result.Plan.TotalCreate,
			TotalUpdate:  result.Plan.TotalUpdate,
			TotalDelete:  result.Plan.TotalDelete,
			TotalReplace: result.Plan.TotalReplace,
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
