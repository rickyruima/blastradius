package reporter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rickyruima/blastradius/pkg/model"
	"github.com/rickyruima/blastradius/pkg/rules"
	"github.com/rickyruima/blastradius/pkg/scorer"
)

func TestTerminalReport_ContainsScore(t *testing.T) {
	result := scorer.Result{
		Overall: 8.4,
		Level:   "CRITICAL",
		Dimensions: map[scorer.Dimension]float64{
			scorer.DimDestruction: 10,
			scorer.DimSecurity:    7,
		},
		Findings: []rules.Finding{
			{
				Rule: rules.Rule{
					ID:          "rds_replacement",
					Severity:    rules.SeverityCritical,
					Category:    rules.CatDestruction,
					Description: "Database replacement causes downtime",
				},
				Resource: model.ResourceChange{
					Address: "aws_db_instance.main",
					Type:    "aws_db_instance",
				},
			},
		},
		Plan: &model.Plan{
			TotalCreate:  2,
			TotalUpdate:  5,
			TotalDelete:  1,
			TotalReplace: 1,
		},
	}

	var buf bytes.Buffer
	Terminal(&buf, result, false)

	output := buf.String()

	if !strings.Contains(output, "CRITICAL") {
		t.Error("output should contain CRITICAL")
	}
	if !strings.Contains(output, "8.4") {
		t.Error("output should contain score 8.4")
	}
	if !strings.Contains(output, "aws_db_instance.main") {
		t.Error("output should contain resource address")
	}
	if !strings.Contains(output, "Database replacement") {
		t.Error("output should contain rule description")
	}
}

func TestTerminalReport_NoFindings(t *testing.T) {
	result := scorer.Result{
		Overall:    0,
		Level:      "LOW",
		Dimensions: map[scorer.Dimension]float64{},
		Findings:   nil,
		Plan: &model.Plan{
			TotalCreate: 3,
		},
	}

	var buf bytes.Buffer
	Terminal(&buf, result, false)

	output := buf.String()
	if !strings.Contains(output, "LOW") {
		t.Error("output should contain LOW")
	}
	if !strings.Contains(output, "No risks detected") {
		t.Error("output should say no risks detected")
	}
}
