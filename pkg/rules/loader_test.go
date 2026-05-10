package rules

import (
	"testing"
)

func TestLoadEmbeddedRules(t *testing.T) {
	rules, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if len(rules) < 20 {
		t.Errorf("expected at least 20 rules, got %d", len(rules))
	}

	// Verify a known rule exists
	found := false
	for _, r := range rules {
		if r.ID == "rds_replacement" {
			found = true
			if r.Severity != SeverityCritical {
				t.Errorf("rds_replacement should be critical, got %s", r.Severity)
			}
			if r.Category != CatDestruction {
				t.Errorf("rds_replacement should be destruction category, got %s", r.Category)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find rds_replacement rule")
	}
}

func TestLoadEmbeddedRules_AllHaveRequiredFields(t *testing.T) {
	rules, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}

	for _, r := range rules {
		if r.ID == "" {
			t.Error("rule has empty ID")
		}
		if r.Severity == "" {
			t.Errorf("rule %s has empty severity", r.ID)
		}
		if r.Category == "" {
			t.Errorf("rule %s has empty category", r.ID)
		}
		if r.Description == "" {
			t.Errorf("rule %s has empty description", r.ID)
		}
		if len(r.ResourceTypes) == 0 && len(r.Actions) == 0 {
			t.Errorf("rule %s has no resource_types and no actions", r.ID)
		}
	}
}
