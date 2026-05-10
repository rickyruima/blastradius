package scorer

import (
	"testing"

	"github.com/rickyruima/blastradius/pkg/model"
	"github.com/rickyruima/blastradius/pkg/rules"
)

func TestScore_CriticalFinding(t *testing.T) {
	findings := []rules.Finding{
		{
			Rule: rules.Rule{
				ID:       "rds_replacement",
				Severity: rules.SeverityCritical,
				Category: rules.CatDestruction,
			},
			Resource: model.ResourceChange{
				Address: "aws_db_instance.main",
			},
		},
	}

	plan := &model.Plan{
		Resources:    []model.ResourceChange{{Address: "aws_db_instance.main"}},
		TotalReplace: 1,
	}

	result := Score(findings, plan, 0)
	if result.Level != "CRITICAL" {
		t.Errorf("expected CRITICAL level, got %s", result.Level)
	}
	if result.Overall < 8.0 {
		t.Errorf("expected overall >= 8.0, got %.1f", result.Overall)
	}
	if result.Dimensions[DimDestruction] == 0 {
		t.Error("expected destruction dimension > 0")
	}
}

func TestScore_LowRiskOnly(t *testing.T) {
	findings := []rules.Finding{
		{
			Rule: rules.Rule{
				ID:       "lambda_deletion",
				Severity: rules.SeverityMedium,
				Category: rules.CatDestruction,
			},
			Resource: model.ResourceChange{
				Address: "aws_lambda_function.cron",
			},
		},
	}

	plan := &model.Plan{
		Resources:   []model.ResourceChange{{Address: "aws_lambda_function.cron"}},
		TotalDelete: 1,
	}

	result := Score(findings, plan, 0)
	if result.Level == "CRITICAL" {
		t.Error("single medium finding should not be CRITICAL")
	}
	if result.Overall > 5.0 {
		t.Errorf("expected overall <= 5.0, got %.1f", result.Overall)
	}
}

func TestScore_NoFindings(t *testing.T) {
	plan := &model.Plan{
		Resources:   []model.ResourceChange{{Address: "aws_instance.web"}},
		TotalCreate: 1,
	}

	result := Score(nil, plan, 0)
	if result.Level != "LOW" {
		t.Errorf("expected LOW level, got %s", result.Level)
	}
	if result.Overall != 0 {
		t.Errorf("expected overall 0, got %.1f", result.Overall)
	}
}

func TestScore_BlastRadiusBoost(t *testing.T) {
	findings := []rules.Finding{
		{
			Rule: rules.Rule{
				ID:       "vpc_deletion",
				Severity: rules.SeverityCritical,
				Category: rules.CatNetwork,
			},
			Resource: model.ResourceChange{
				Address: "aws_vpc.main",
			},
		},
	}

	plan := &model.Plan{
		Resources:   []model.ResourceChange{{Address: "aws_vpc.main"}},
		TotalDelete: 1,
	}

	result := Score(findings, plan, 10)
	if result.Dimensions[DimBlastRadius] == 0 {
		t.Error("expected blast_radius dimension > 0 when maxImpact > 0")
	}
}
