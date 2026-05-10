package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_DefaultsWhenNoFile(t *testing.T) {
	cfg, err := Load("/nonexistent/path/.blastradius.yaml")
	if err != nil {
		t.Fatalf("Load should not error for missing file: %v", err)
	}
	if cfg == nil {
		t.Fatal("config should not be nil")
	}
	if len(cfg.ProductionTags) == 0 {
		t.Error("expected default production tags")
	}
}

func TestLoad_ParsesYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".blastradius.yaml")
	content := `
production_tags:
  - "env:prod"
  - "tier:0"
critical_resources:
  - "aws_db_instance.main"
ignore_rules:
  - "iam_role_change"
weights:
  destruction: 1.5
  security: 2.0
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.ProductionTags) != 2 {
		t.Errorf("expected 2 production tags, got %d", len(cfg.ProductionTags))
	}
	if cfg.ProductionTags[0] != "env:prod" {
		t.Errorf("expected env:prod, got %s", cfg.ProductionTags[0])
	}
	if len(cfg.CriticalResources) != 1 {
		t.Errorf("expected 1 critical resource, got %d", len(cfg.CriticalResources))
	}
	if len(cfg.IgnoreRules) != 1 {
		t.Errorf("expected 1 ignore rule, got %d", len(cfg.IgnoreRules))
	}
	if cfg.Weights["destruction"] != 1.5 {
		t.Errorf("expected destruction weight 1.5, got %f", cfg.Weights["destruction"])
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".blastradius.yaml")
	if err := os.WriteFile(path, []byte(":::invalid"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestShouldIgnoreRule(t *testing.T) {
	cfg := &Config{IgnoreRules: []string{"iam_role_change", "subnet_change"}}
	if !cfg.ShouldIgnoreRule("iam_role_change") {
		t.Error("should ignore iam_role_change")
	}
	if cfg.ShouldIgnoreRule("rds_replacement") {
		t.Error("should not ignore rds_replacement")
	}
}
