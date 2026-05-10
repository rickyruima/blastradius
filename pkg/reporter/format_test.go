package reporter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rickyruima/blastradius/pkg/model"
	"github.com/rickyruima/blastradius/pkg/rules"
	"github.com/rickyruima/blastradius/pkg/scorer"
)

func TestJSONReport_ValidJSON(t *testing.T) {
	result := scorer.Result{
		Overall: 5.0,
		Level:   "MEDIUM",
		Dimensions: map[scorer.Dimension]float64{
			scorer.DimDestruction: 5,
		},
		Findings: []rules.Finding{
			{
				Rule: rules.Rule{
					ID:          "s3_bucket_deletion",
					Severity:    rules.SeverityHigh,
					Category:    rules.CatDestruction,
					Description: "S3 bucket will be deleted",
				},
				Resource: model.ResourceChange{
					Address: "aws_s3_bucket.logs",
				},
			},
		},
		Plan: &model.Plan{TotalDelete: 1},
	}

	var buf bytes.Buffer
	if err := JSON(&buf, result); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"level": "MEDIUM"`) {
		t.Error("JSON should contain level")
	}
	if !strings.Contains(output, `"overall": 5`) {
		t.Error("JSON should contain overall score")
	}
	if !strings.Contains(output, `"s3_bucket_deletion"`) {
		t.Error("JSON should contain rule ID")
	}
}

func TestMarkdownReport_ContainsHeaders(t *testing.T) {
	result := scorer.Result{
		Overall: 8.0,
		Level:   "CRITICAL",
		Dimensions: map[scorer.Dimension]float64{
			scorer.DimDestruction: 10,
		},
		Findings: []rules.Finding{
			{
				Rule: rules.Rule{
					ID:          "rds_replacement",
					Severity:    rules.SeverityCritical,
					Description: "Database replacement",
				},
				Resource: model.ResourceChange{
					Address: "aws_db_instance.main",
				},
			},
		},
		Plan: &model.Plan{TotalReplace: 1},
	}

	var buf bytes.Buffer
	Markdown(&buf, result)

	output := buf.String()
	if !strings.Contains(output, "# Blast Radius") {
		t.Error("markdown should contain header")
	}
	if !strings.Contains(output, "CRITICAL") {
		t.Error("markdown should contain level")
	}
	if !strings.Contains(output, "aws_db_instance.main") {
		t.Error("markdown should contain resource")
	}
}
