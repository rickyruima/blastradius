package rules

import (
	"testing"

	"github.com/rickyruima/blastradius/pkg/model"
)

func TestEngine_MatchesDestructiveRule(t *testing.T) {
	rules := []Rule{
		{
			ID:            "rds_replacement",
			Severity:      SeverityCritical,
			Category:      CatDestruction,
			Description:   "Database replacement causes downtime",
			ResourceTypes: []string{"aws_db_instance"},
			Actions:       []string{"delete", "replace"},
		},
	}

	engine := NewEngine(rules)

	changes := []model.ResourceChange{
		{
			Address: "aws_db_instance.main",
			Type:    "aws_db_instance",
			Actions: []model.Action{model.ActionDelete, model.ActionCreate},
		},
		{
			Address: "aws_instance.web",
			Type:    "aws_instance",
			Actions: []model.Action{model.ActionCreate},
		},
	}

	findings := engine.Evaluate(changes)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Rule.ID != "rds_replacement" {
		t.Errorf("expected rule rds_replacement, got %s", findings[0].Rule.ID)
	}
	if findings[0].Resource.Address != "aws_db_instance.main" {
		t.Errorf("expected resource aws_db_instance.main, got %s", findings[0].Resource.Address)
	}
}

func TestEngine_NoMatchForSafeChange(t *testing.T) {
	rules := []Rule{
		{
			ID:            "rds_replacement",
			Severity:      SeverityCritical,
			Category:      CatDestruction,
			ResourceTypes: []string{"aws_db_instance"},
			Actions:       []string{"delete", "replace"},
		},
	}

	engine := NewEngine(rules)
	changes := []model.ResourceChange{
		{
			Address: "aws_db_instance.main",
			Type:    "aws_db_instance",
			Actions: []model.Action{model.ActionUpdate},
		},
	}

	findings := engine.Evaluate(changes)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestEngine_ConditionMatch(t *testing.T) {
	rules := []Rule{
		{
			ID:            "sg_public_ingress",
			Severity:      SeverityHigh,
			Category:      CatSecurity,
			ResourceTypes: []string{"aws_security_group_rule"},
			Actions:       []string{"create", "update"},
			Condition:     "cidr_blocks contains 0.0.0.0/0",
		},
	}

	engine := NewEngine(rules)
	changes := []model.ResourceChange{
		{
			Address: "aws_security_group_rule.public",
			Type:    "aws_security_group_rule",
			Actions: []model.Action{model.ActionCreate},
			After: map[string]any{
				"cidr_blocks": []any{"0.0.0.0/0"},
			},
		},
	}

	findings := engine.Evaluate(changes)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestEngine_DeduplicatesSameResourceCategory(t *testing.T) {
	ruleSet := []Rule{
		{
			ID:            "rds_replacement",
			Severity:      SeverityCritical,
			Category:      CatDestruction,
			Description:   "Database replacement causes downtime",
			ResourceTypes: []string{"aws_db_instance"},
			Actions:       []string{"delete", "replace"},
		},
		{
			ID:            "rds_deletion",
			Severity:      SeverityCritical,
			Category:      CatDestruction,
			Description:   "Database will be deleted",
			ResourceTypes: []string{"aws_db_instance"},
			Actions:       []string{"delete"},
		},
	}

	engine := NewEngine(ruleSet)
	changes := []model.ResourceChange{
		{
			Address: "aws_db_instance.main",
			Type:    "aws_db_instance",
			Actions: []model.Action{model.ActionDelete, model.ActionCreate},
		},
	}

	findings := engine.Evaluate(changes)
	if len(findings) != 1 {
		t.Errorf("expected 1 deduplicated finding, got %d", len(findings))
	}
}

func TestEngine_ConditionNoMatch(t *testing.T) {
	rules := []Rule{
		{
			ID:            "sg_public_ingress",
			Severity:      SeverityHigh,
			Category:      CatSecurity,
			ResourceTypes: []string{"aws_security_group_rule"},
			Actions:       []string{"create", "update"},
			Condition:     "cidr_blocks contains 0.0.0.0/0",
		},
	}

	engine := NewEngine(rules)
	changes := []model.ResourceChange{
		{
			Address: "aws_security_group_rule.private",
			Type:    "aws_security_group_rule",
			Actions: []model.Action{model.ActionCreate},
			After: map[string]any{
				"cidr_blocks": []any{"10.0.0.0/8"},
			},
		},
	}

	findings := engine.Evaluate(changes)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}
