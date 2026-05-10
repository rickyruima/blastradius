package parser

import (
	"os"
	"testing"

)

func TestParsePlan(t *testing.T) {
	data, err := os.ReadFile("../../testdata/simple_plan.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	plan, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(plan.Resources) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(plan.Resources))
	}

	// Check the RDS replacement
	db := plan.Resources[1]
	if db.Address != "aws_db_instance.main" {
		t.Errorf("expected aws_db_instance.main, got %s", db.Address)
	}
	if db.Type != "aws_db_instance" {
		t.Errorf("expected type aws_db_instance, got %s", db.Type)
	}
	if !db.IsDestructive() {
		t.Error("expected db change to be destructive (replace)")
	}
	if len(db.Actions) != 2 {
		t.Errorf("expected 2 actions (delete+create), got %d", len(db.Actions))
	}

	// Check counters
	if plan.TotalCreate != 1 {
		t.Errorf("expected TotalCreate=1, got %d", plan.TotalCreate)
	}
	if plan.TotalReplace != 1 {
		t.Errorf("expected TotalReplace=1, got %d", plan.TotalReplace)
	}
	if plan.TotalUpdate != 1 {
		t.Errorf("expected TotalUpdate=1, got %d", plan.TotalUpdate)
	}
}

func TestParsePlan_References(t *testing.T) {
	data, err := os.ReadFile("../../testdata/simple_plan.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	plan, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// aws_instance.web references aws_subnet.main
	web := plan.Resources[0]
	found := false
	for _, ref := range web.References {
		if ref == "aws_subnet.main" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected aws_instance.web to reference aws_subnet.main, got refs: %v", web.References)
	}
}

func TestParsePlan_InvalidJSON(t *testing.T) {
	_, err := Parse([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

