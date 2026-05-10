# BlastRadius v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working Go CLI that reads `terraform show -json` output and produces a scored risk report with colored terminal output.

**Architecture:** Parse plan JSON into internal model → match resource changes against YAML-defined risk rules → build dependency graph to compute blast radius → aggregate findings into dimensional scores (0-10) → output formatted report (terminal/JSON/markdown).

**Tech Stack:** Go 1.22, github.com/hashicorp/terraform-json, github.com/dominikbraun/graph, github.com/spf13/cobra, github.com/fatih/color, gopkg.in/yaml.v3

---

## File Structure

```
blastradius/
├── cmd/blastradius/main.go              # CLI entry, cobra root command
├── pkg/
│   ├── model/model.go                   # Internal types (ResourceChange, Plan, Action)
│   ├── parser/parser.go                 # terraform-json → internal model
│   ├── parser/parser_test.go
│   ├── rules/
│   │   ├── rule.go                      # Rule/Finding/Severity types
│   │   ├── engine.go                    # Match engine (evaluates rules against changes)
│   │   ├── engine_test.go
│   │   ├── loader.go                    # YAML rule loader (embed)
│   │   └── loader_test.go
│   ├── graph/
│   │   ├── graph.go                     # Dependency graph builder + impact count
│   │   └── graph_test.go
│   ├── scorer/
│   │   ├── scorer.go                    # Dimensional scoring + aggregation
│   │   └── scorer_test.go
│   ├── reporter/
│   │   ├── terminal.go                  # Colored terminal output
│   │   ├── json.go                      # JSON output
│   │   ├── markdown.go                  # Markdown output
│   │   └── reporter_test.go
│   └── config/
│       ├── config.go                    # .blastradius.yaml loader
│       └── config_test.go
├── rules/                               # Embedded YAML rule files
│   ├── destruction.yaml
│   ├── security.yaml
│   ├── network.yaml
│   └── stateful.yaml
├── testdata/
│   ├── simple_plan.json                 # Minimal plan for unit tests
│   ├── dangerous_plan.json              # Plan with high-risk changes
│   └── safe_plan.json                   # Plan with only low-risk changes
├── go.mod
├── go.sum
└── .blastradius.yaml.example            # Example config
```

---

### Task 1: Internal Model + Project Dependencies

**Files:**
- Create: `pkg/model/model.go`
- Modify: `go.mod`

- [ ] **Step 1: Define internal model types**

```go
// pkg/model/model.go
package model

// Action represents a terraform resource change action.
type Action string

const (
	ActionCreate      Action = "create"
	ActionRead        Action = "read"
	ActionUpdate      Action = "update"
	ActionDelete      Action = "delete"
	ActionReplace     Action = "replace"
	ActionNoOp        Action = "no-op"
)

// ResourceChange represents a single resource being modified in a plan.
type ResourceChange struct {
	Address    string
	Type       string
	Name       string
	Provider   string
	Actions    []Action
	Before     map[string]any
	After      map[string]any
	References []string // other resource addresses this depends on
}

// IsDestructive returns true if the change involves delete or replace.
func (rc ResourceChange) IsDestructive() bool {
	for _, a := range rc.Actions {
		if a == ActionDelete || a == ActionReplace {
			return true
		}
	}
	return false
}

// Plan represents a parsed terraform plan.
type Plan struct {
	Resources    []ResourceChange
	TotalCreate  int
	TotalUpdate  int
	TotalDelete  int
	TotalReplace int
}
```

- [ ] **Step 2: Add all dependencies to go.mod**

Run:
```bash
cd /Users/ruima/Desktop/app_dev/blastradius && cat > go.mod << 'EOF'
module github.com/rickyruima/blastradius

go 1.22

require (
	github.com/dominikbraun/graph v0.23.0
	github.com/fatih/color v1.16.0
	github.com/hashicorp/terraform-json v0.22.1
	github.com/spf13/cobra v1.8.0
	gopkg.in/yaml.v3 v3.0.1
)
EOF
go mod tidy
```

- [ ] **Step 3: Verify the module compiles**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go build ./...`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add pkg/model/model.go go.mod go.sum
git commit -m "feat: define internal model types and project dependencies"
```

---

### Task 2: Parser (Plan JSON → Internal Model)

**Files:**
- Create: `pkg/parser/parser.go`
- Create: `pkg/parser/parser_test.go`
- Create: `testdata/simple_plan.json`

- [ ] **Step 1: Create test fixture — minimal terraform plan JSON**

```json
// testdata/simple_plan.json
{
  "format_version": "1.2",
  "terraform_version": "1.7.0",
  "resource_changes": [
    {
      "address": "aws_instance.web",
      "type": "aws_instance",
      "name": "web",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "ami": "ami-12345",
          "instance_type": "t3.micro",
          "tags": {"Name": "web", "env": "prod"}
        },
        "after_unknown": {}
      }
    },
    {
      "address": "aws_db_instance.main",
      "type": "aws_db_instance",
      "name": "main",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["delete", "create"],
        "before": {
          "identifier": "main-db",
          "engine": "postgres",
          "instance_class": "db.t3.medium"
        },
        "after": {
          "identifier": "main-db",
          "engine": "postgres",
          "instance_class": "db.r5.large"
        },
        "after_unknown": {}
      }
    },
    {
      "address": "aws_s3_bucket.logs",
      "type": "aws_s3_bucket",
      "name": "logs",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["update"],
        "before": {
          "bucket": "my-logs",
          "acl": "private"
        },
        "after": {
          "bucket": "my-logs",
          "acl": "public-read"
        },
        "after_unknown": {}
      }
    }
  ],
  "configuration": {
    "root_module": {
      "resources": [
        {
          "address": "aws_instance.web",
          "type": "aws_instance",
          "name": "web",
          "expressions": {
            "subnet_id": {
              "references": ["aws_subnet.main.id", "aws_subnet.main"]
            }
          }
        },
        {
          "address": "aws_db_instance.main",
          "type": "aws_db_instance",
          "name": "main",
          "expressions": {
            "vpc_security_group_ids": {
              "references": ["aws_security_group.db.id", "aws_security_group.db"]
            }
          }
        }
      ]
    }
  }
}
```

- [ ] **Step 2: Write the failing test**

```go
// pkg/parser/parser_test.go
package parser

import (
	"os"
	"testing"

	"github.com/rickyruima/blastradius/pkg/model"
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/parser/ -v`
Expected: FAIL (package does not exist yet)

- [ ] **Step 4: Implement parser**

```go
// pkg/parser/parser.go
package parser

import (
	"encoding/json"
	"fmt"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/rickyruima/blastradius/pkg/model"
)

// Parse reads terraform show -json output and returns an internal Plan.
func Parse(data []byte) (*model.Plan, error) {
	var raw tfjson.Plan
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse plan JSON: %w", err)
	}

	refs := extractReferences(&raw)

	plan := &model.Plan{}
	for _, rc := range raw.ResourceChanges {
		actions := convertActions(rc.Change.Actions)
		change := model.ResourceChange{
			Address:    rc.Address,
			Type:       rc.Type,
			Name:       rc.Name,
			Provider:   rc.ProviderName,
			Actions:    actions,
			Before:     rawToMap(rc.Change.Before),
			After:      rawToMap(rc.Change.After),
			References: refs[rc.Address],
		}
		plan.Resources = append(plan.Resources, change)
		countActions(plan, actions)
	}
	return plan, nil
}

func convertActions(actions tfjson.Actions) []model.Action {
	out := make([]model.Action, 0, len(actions))
	for _, a := range actions {
		switch a {
		case tfjson.ActionCreate:
			out = append(out, model.ActionCreate)
		case tfjson.ActionRead:
			out = append(out, model.ActionRead)
		case tfjson.ActionUpdate:
			out = append(out, model.ActionUpdate)
		case tfjson.ActionDelete:
			out = append(out, model.ActionDelete)
		case tfjson.ActionNoop:
			out = append(out, model.ActionNoOp)
		}
	}
	return out
}

func countActions(plan *model.Plan, actions []model.Action) {
	// delete+create = replace
	hasDelete := false
	hasCreate := false
	for _, a := range actions {
		if a == model.ActionDelete {
			hasDelete = true
		}
		if a == model.ActionCreate {
			hasCreate = true
		}
	}
	if hasDelete && hasCreate {
		plan.TotalReplace++
		return
	}
	for _, a := range actions {
		switch a {
		case model.ActionCreate:
			plan.TotalCreate++
		case model.ActionUpdate:
			plan.TotalUpdate++
		case model.ActionDelete:
			plan.TotalDelete++
		}
	}
}

func rawToMap(v interface{}) map[string]any {
	if v == nil {
		return nil
	}
	// terraform-json unmarshals change values as map[string]interface{}
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

// extractReferences builds address→[]referenced_address from plan configuration.
func extractReferences(plan *tfjson.Plan) map[string][]string {
	refs := make(map[string][]string)
	if plan.Configuration == nil || plan.Configuration.RootModule == nil {
		return refs
	}
	for _, res := range plan.Configuration.RootModule.Resources {
		addr := res.Type + "." + res.Name
		seen := make(map[string]bool)
		for _, expr := range res.Expressions {
			for _, ref := range expr.References {
				// Filter to resource references (type.name format), deduplicate
				if isResourceAddress(ref) && !seen[ref] {
					seen[ref] = true
					refs[addr] = append(refs[addr], ref)
				}
			}
		}
	}
	return refs
}

// isResourceAddress checks if a reference looks like "type.name" (not "type.name.attr").
func isResourceAddress(ref string) bool {
	dots := 0
	for _, c := range ref {
		if c == '.' {
			dots++
		}
	}
	return dots == 1
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/parser/ -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add pkg/parser/ testdata/simple_plan.json
git commit -m "feat: implement plan JSON parser with reference extraction"
```

---

### Task 3: Rule Types + Match Engine

**Files:**
- Create: `pkg/rules/rule.go`
- Create: `pkg/rules/engine.go`
- Create: `pkg/rules/engine_test.go`

- [ ] **Step 1: Define rule types**

```go
// pkg/rules/rule.go
package rules

import "github.com/rickyruima/blastradius/pkg/model"

// Severity levels for risk findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Category groups rules into scoring dimensions.
type Category string

const (
	CatDestruction Category = "destruction"
	CatSecurity    Category = "security"
	CatNetwork     Category = "network"
	CatStateful    Category = "stateful"
)

// Rule defines a risk detection rule.
type Rule struct {
	ID            string   `yaml:"id"`
	Severity      Severity `yaml:"severity"`
	Category      Category `yaml:"category"`
	Description   string   `yaml:"description"`
	ResourceTypes []string `yaml:"resource_types"`
	Actions       []string `yaml:"actions"`
	Condition     string   `yaml:"condition,omitempty"` // attribute condition (simple key=value for v0.1)
}

// Finding represents a matched rule against a specific resource.
type Finding struct {
	Rule     Rule
	Resource model.ResourceChange
	Message  string
}

// SeverityWeight returns a numeric weight for scoring.
func SeverityWeight(s Severity) float64 {
	switch s {
	case SeverityCritical:
		return 10.0
	case SeverityHigh:
		return 7.0
	case SeverityMedium:
		return 4.0
	case SeverityLow:
		return 2.0
	default:
		return 1.0
	}
}
```

- [ ] **Step 2: Write the failing engine test**

```go
// pkg/rules/engine_test.go
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/rules/ -v`
Expected: FAIL (NewEngine not defined)

- [ ] **Step 4: Implement the engine**

```go
// pkg/rules/engine.go
package rules

import (
	"fmt"
	"strings"

	"github.com/rickyruima/blastradius/pkg/model"
)

// Engine evaluates rules against resource changes.
type Engine struct {
	rules []Rule
}

// NewEngine creates a rule engine with the given rules.
func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// Evaluate runs all rules against all resource changes, returning findings.
func (e *Engine) Evaluate(changes []model.ResourceChange) []Finding {
	var findings []Finding
	for _, rc := range changes {
		for _, rule := range e.rules {
			if e.matches(rule, rc) {
				findings = append(findings, Finding{
					Rule:     rule,
					Resource: rc,
					Message:  fmt.Sprintf("[%s] %s: %s", strings.ToUpper(string(rule.Severity)), rc.Address, rule.Description),
				})
			}
		}
	}
	return findings
}

func (e *Engine) matches(rule Rule, rc model.ResourceChange) bool {
	if !e.matchType(rule, rc) {
		return false
	}
	if !e.matchAction(rule, rc) {
		return false
	}
	if rule.Condition != "" && !e.matchCondition(rule.Condition, rc) {
		return false
	}
	return true
}

func (e *Engine) matchType(rule Rule, rc model.ResourceChange) bool {
	if len(rule.ResourceTypes) == 0 {
		return true
	}
	for _, rt := range rule.ResourceTypes {
		if rt == rc.Type {
			return true
		}
	}
	return false
}

func (e *Engine) matchAction(rule Rule, rc model.ResourceChange) bool {
	if len(rule.Actions) == 0 {
		return true
	}
	for _, ruleAction := range rule.Actions {
		for _, rcAction := range rc.Actions {
			if ruleAction == string(rcAction) {
				return true
			}
			// "replace" matches delete+create combo
			if ruleAction == "replace" && rcAction == model.ActionDelete {
				for _, a := range rc.Actions {
					if a == model.ActionCreate {
						return true
					}
				}
			}
		}
	}
	return false
}

// matchCondition evaluates simple conditions like "key contains value".
func (e *Engine) matchCondition(condition string, rc model.ResourceChange) bool {
	parts := strings.SplitN(condition, " contains ", 2)
	if len(parts) != 2 {
		return false
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	attrs := rc.After
	if attrs == nil {
		return false
	}

	attrVal, ok := attrs[key]
	if !ok {
		return false
	}

	return containsValue(attrVal, value)
}

func containsValue(attr any, target string) bool {
	switch v := attr.(type) {
	case string:
		return v == target
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == target {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/rules/ -v`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add pkg/rules/rule.go pkg/rules/engine.go pkg/rules/engine_test.go
git commit -m "feat: implement rule engine with type, action, and condition matching"
```

---

### Task 4: YAML Rule Loader + Built-in Rules

**Files:**
- Create: `pkg/rules/loader.go`
- Create: `pkg/rules/loader_test.go`
- Create: `rules/destruction.yaml`
- Create: `rules/security.yaml`
- Create: `rules/network.yaml`
- Create: `rules/stateful.yaml`

- [ ] **Step 1: Write the failing loader test**

```go
// pkg/rules/loader_test.go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/rules/ -v -run TestLoad`
Expected: FAIL (LoadEmbedded not defined)

- [ ] **Step 3: Create YAML rule files**

```yaml
# rules/destruction.yaml
- id: rds_replacement
  severity: critical
  category: destruction
  description: "Database instance will be REPLACED — causes downtime and potential data loss"
  resource_types: ["aws_db_instance", "aws_rds_cluster"]
  actions: ["delete", "replace"]

- id: rds_deletion
  severity: critical
  category: destruction
  description: "Database instance will be DELETED"
  resource_types: ["aws_db_instance", "aws_rds_cluster"]
  actions: ["delete"]

- id: s3_bucket_deletion
  severity: high
  category: destruction
  description: "S3 bucket will be deleted — all objects lost"
  resource_types: ["aws_s3_bucket"]
  actions: ["delete"]

- id: eks_cluster_deletion
  severity: critical
  category: destruction
  description: "EKS cluster will be deleted — all workloads lost"
  resource_types: ["aws_eks_cluster"]
  actions: ["delete", "replace"]

- id: ecs_service_deletion
  severity: high
  category: destruction
  description: "ECS service will be deleted — service interruption"
  resource_types: ["aws_ecs_service"]
  actions: ["delete"]

- id: elasticache_deletion
  severity: high
  category: destruction
  description: "ElastiCache cluster will be deleted — cache data lost"
  resource_types: ["aws_elasticache_cluster", "aws_elasticache_replication_group"]
  actions: ["delete", "replace"]

- id: lambda_deletion
  severity: medium
  category: destruction
  description: "Lambda function will be deleted"
  resource_types: ["aws_lambda_function"]
  actions: ["delete"]
```

```yaml
# rules/security.yaml
- id: iam_policy_change
  severity: high
  category: security
  description: "IAM policy modified — review permission scope"
  resource_types: ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]
  actions: ["create", "update"]

- id: iam_role_change
  severity: medium
  category: security
  description: "IAM role modified"
  resource_types: ["aws_iam_role"]
  actions: ["create", "update"]

- id: sg_public_ingress
  severity: high
  category: security
  description: "Security group rule opens access to 0.0.0.0/0"
  resource_types: ["aws_security_group_rule", "aws_vpc_security_group_ingress_rule"]
  actions: ["create", "update"]
  condition: "cidr_blocks contains 0.0.0.0/0"

- id: sg_deletion
  severity: medium
  category: security
  description: "Security group will be deleted — dependent resources may lose access"
  resource_types: ["aws_security_group"]
  actions: ["delete"]

- id: kms_key_deletion
  severity: critical
  category: security
  description: "KMS key will be deleted — encrypted data becomes unrecoverable"
  resource_types: ["aws_kms_key"]
  actions: ["delete"]

- id: secrets_manager_deletion
  severity: high
  category: security
  description: "Secret will be deleted"
  resource_types: ["aws_secretsmanager_secret"]
  actions: ["delete"]
```

```yaml
# rules/network.yaml
- id: vpc_deletion
  severity: critical
  category: network
  description: "VPC will be deleted — all contained resources affected"
  resource_types: ["aws_vpc"]
  actions: ["delete"]

- id: subnet_change
  severity: medium
  category: network
  description: "Subnet modified — may affect resource placement"
  resource_types: ["aws_subnet"]
  actions: ["delete", "replace", "update"]

- id: route_table_change
  severity: high
  category: network
  description: "Route table modified — may break network connectivity"
  resource_types: ["aws_route_table", "aws_route"]
  actions: ["delete", "update", "replace"]

- id: nat_gateway_change
  severity: high
  category: network
  description: "NAT gateway modified — private subnet internet access affected"
  resource_types: ["aws_nat_gateway"]
  actions: ["delete", "replace"]

- id: lb_deletion
  severity: high
  category: network
  description: "Load balancer will be deleted — service interruption"
  resource_types: ["aws_lb", "aws_alb", "aws_elb"]
  actions: ["delete"]

- id: vpc_peering_change
  severity: high
  category: network
  description: "VPC peering connection modified — cross-VPC communication affected"
  resource_types: ["aws_vpc_peering_connection"]
  actions: ["delete", "replace"]
```

```yaml
# rules/stateful.yaml
- id: dynamodb_table_deletion
  severity: critical
  category: stateful
  description: "DynamoDB table will be deleted — all data lost"
  resource_types: ["aws_dynamodb_table"]
  actions: ["delete"]

- id: ebs_volume_deletion
  severity: high
  category: stateful
  description: "EBS volume will be deleted — data loss"
  resource_types: ["aws_ebs_volume"]
  actions: ["delete"]

- id: efs_deletion
  severity: high
  category: stateful
  description: "EFS file system will be deleted — shared data lost"
  resource_types: ["aws_efs_file_system"]
  actions: ["delete"]

- id: sqs_queue_deletion
  severity: medium
  category: stateful
  description: "SQS queue will be deleted — queued messages lost"
  resource_types: ["aws_sqs_queue"]
  actions: ["delete"]

- id: sns_topic_deletion
  severity: medium
  category: stateful
  description: "SNS topic will be deleted — subscribers disconnected"
  resource_types: ["aws_sns_topic"]
  actions: ["delete"]
```

- [ ] **Step 4: Implement the loader with embed**

```go
// pkg/rules/loader.go
package rules

import (
	"embed"
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed ../../rules/*.yaml
var embeddedRules embed.FS

// LoadEmbedded loads all built-in YAML rule files.
func LoadEmbedded() ([]Rule, error) {
	entries, err := embeddedRules.ReadDir("../../rules")
	if err != nil {
		return nil, fmt.Errorf("read embedded rules dir: %w", err)
	}

	var allRules []Rule
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		data, err := embeddedRules.ReadFile("../../rules/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		var rules []Rule
		if err := yaml.Unmarshal(data, &rules); err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		allRules = append(allRules, rules...)
	}
	return allRules, nil
}
```

**Note:** Go embed paths are relative to the source file. Since `loader.go` is in `pkg/rules/`, the embed pattern `../../rules/*.yaml` won't work. We need to restructure. Instead, embed from a top-level `embed.go`:

Actually, the cleaner approach is to put the rules dir adjacent to loader or use a top-level embed package. Let's put the YAML files inside `pkg/rules/definitions/`:

Move the YAML files to `pkg/rules/definitions/` instead:

```go
// pkg/rules/loader.go
package rules

import (
	"embed"
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed definitions/*.yaml
var embeddedRules embed.FS

// LoadEmbedded loads all built-in YAML rule files.
func LoadEmbedded() ([]Rule, error) {
	entries, err := embeddedRules.ReadDir("definitions")
	if err != nil {
		return nil, fmt.Errorf("read embedded rules dir: %w", err)
	}

	var allRules []Rule
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		data, err := embeddedRules.ReadFile("definitions/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		var rules []Rule
		if err := yaml.Unmarshal(data, &rules); err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		allRules = append(allRules, rules...)
	}
	return allRules, nil
}
```

Place YAML files in `pkg/rules/definitions/destruction.yaml`, etc. (same content as above). Also keep copies in top-level `rules/` for user reference, but the embedded ones live under `pkg/rules/definitions/`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/rules/ -v -run TestLoad`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add pkg/rules/loader.go pkg/rules/loader_test.go pkg/rules/definitions/
git commit -m "feat: add YAML rule loader with 24 embedded risk rules"
```

---

### Task 5: Dependency Graph

**Files:**
- Create: `pkg/graph/graph.go`
- Create: `pkg/graph/graph_test.go`

- [ ] **Step 1: Write the failing test**

```go
// pkg/graph/graph_test.go
package graph

import (
	"testing"

	"github.com/rickyruima/blastradius/pkg/model"
)

func TestBuildGraph_ImpactCount(t *testing.T) {
	resources := []model.ResourceChange{
		{
			Address:    "aws_vpc.main",
			Type:       "aws_vpc",
			References: nil, // root
		},
		{
			Address:    "aws_subnet.a",
			Type:       "aws_subnet",
			References: []string{"aws_vpc.main"},
		},
		{
			Address:    "aws_subnet.b",
			Type:       "aws_subnet",
			References: []string{"aws_vpc.main"},
		},
		{
			Address:    "aws_instance.web",
			Type:       "aws_instance",
			References: []string{"aws_subnet.a"},
		},
		{
			Address:    "aws_db_instance.main",
			Type:       "aws_db_instance",
			References: []string{"aws_subnet.b"},
		},
	}

	g := Build(resources)

	// VPC impacts everything downstream (4 resources)
	impact := g.ImpactCount("aws_vpc.main")
	if impact != 4 {
		t.Errorf("aws_vpc.main impact: expected 4, got %d", impact)
	}

	// subnet.a impacts only instance.web
	impact = g.ImpactCount("aws_subnet.a")
	if impact != 1 {
		t.Errorf("aws_subnet.a impact: expected 1, got %d", impact)
	}

	// instance.web is a leaf, impacts nothing
	impact = g.ImpactCount("aws_instance.web")
	if impact != 0 {
		t.Errorf("aws_instance.web impact: expected 0, got %d", impact)
	}
}

func TestBuildGraph_MaxImpact(t *testing.T) {
	resources := []model.ResourceChange{
		{Address: "aws_vpc.main", References: nil},
		{Address: "aws_subnet.a", References: []string{"aws_vpc.main"}},
		{Address: "aws_instance.web", References: []string{"aws_subnet.a"}},
	}

	g := Build(resources)
	maxAddr, maxCount := g.MaxImpact()
	if maxAddr != "aws_vpc.main" {
		t.Errorf("expected max impact from aws_vpc.main, got %s", maxAddr)
	}
	if maxCount != 2 {
		t.Errorf("expected max impact count 2, got %d", maxCount)
	}
}

func TestBuildGraph_Empty(t *testing.T) {
	g := Build(nil)
	impact := g.ImpactCount("nonexistent")
	if impact != 0 {
		t.Errorf("expected 0 for nonexistent, got %d", impact)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/graph/ -v`
Expected: FAIL (package does not exist)

- [ ] **Step 3: Implement the graph**

```go
// pkg/graph/graph.go
package graph

import "github.com/rickyruima/blastradius/pkg/model"

// DependencyGraph represents resource dependencies for impact analysis.
type DependencyGraph struct {
	// dependents maps address → list of addresses that depend on it
	dependents map[string][]string
	addresses  map[string]bool
}

// Build constructs a dependency graph from resource changes.
// References mean "this resource depends on those", so we invert
// to get "if X changes, these are affected".
func Build(resources []model.ResourceChange) *DependencyGraph {
	g := &DependencyGraph{
		dependents: make(map[string][]string),
		addresses:  make(map[string]bool),
	}

	for _, r := range resources {
		g.addresses[r.Address] = true
		for _, ref := range r.References {
			g.dependents[ref] = append(g.dependents[ref], r.Address)
			g.addresses[ref] = true
		}
	}
	return g
}

// ImpactCount returns how many resources are transitively affected
// if the given resource changes (downstream dependents).
func (g *DependencyGraph) ImpactCount(address string) int {
	visited := make(map[string]bool)
	g.walkDependents(address, visited)
	// Don't count the resource itself
	delete(visited, address)
	return len(visited)
}

func (g *DependencyGraph) walkDependents(address string, visited map[string]bool) {
	if visited[address] {
		return
	}
	visited[address] = true
	for _, dep := range g.dependents[address] {
		g.walkDependents(dep, visited)
	}
}

// MaxImpact returns the resource with the highest downstream impact count.
func (g *DependencyGraph) MaxImpact() (address string, count int) {
	for addr := range g.addresses {
		c := g.ImpactCount(addr)
		if c > count {
			count = c
			address = addr
		}
	}
	return
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/graph/ -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add pkg/graph/
git commit -m "feat: implement dependency graph with transitive impact counting"
```

---

### Task 6: Scorer

**Files:**
- Create: `pkg/scorer/scorer.go`
- Create: `pkg/scorer/scorer_test.go`

- [ ] **Step 1: Write the failing test**

```go
// pkg/scorer/scorer_test.go
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
				Type:    "aws_db_instance",
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

	// maxImpact = 10 means lots of downstream resources
	result := Score(findings, plan, 10)
	if result.Dimensions[DimBlastRadius] == 0 {
		t.Error("expected blast_radius dimension > 0 when maxImpact > 0")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/scorer/ -v`
Expected: FAIL

- [ ] **Step 3: Implement the scorer**

```go
// pkg/scorer/scorer.go
package scorer

import (
	"math"

	"github.com/rickyruima/blastradius/pkg/model"
	"github.com/rickyruima/blastradius/pkg/rules"
)

// Dimension represents a scoring category.
type Dimension string

const (
	DimDestruction Dimension = "destruction"
	DimSecurity    Dimension = "security"
	DimNetwork     Dimension = "network"
	DimStateful    Dimension = "stateful"
	DimBlastRadius Dimension = "blast_radius"
)

// Result contains the final scored output.
type Result struct {
	Overall    float64
	Level      string // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Dimensions map[Dimension]float64
	Findings   []rules.Finding
	Plan       *model.Plan
}

// Score computes the overall blast radius score from findings.
// maxImpact is the maximum downstream dependency count from the graph.
func Score(findings []rules.Finding, plan *model.Plan, maxImpact int) Result {
	dims := map[Dimension]float64{
		DimDestruction: 0,
		DimSecurity:    0,
		DimNetwork:     0,
		DimStateful:    0,
		DimBlastRadius: 0,
	}

	// Accumulate per-dimension scores from findings
	for _, f := range findings {
		dim := categoryToDimension(f.Rule.Category)
		weight := rules.SeverityWeight(f.Rule.Severity)
		dims[dim] = math.Min(10, dims[dim]+weight)
	}

	// Blast radius dimension based on dependency graph impact
	if maxImpact > 0 {
		dims[DimBlastRadius] = math.Min(10, float64(maxImpact)*1.5)
	}

	// Overall = max dimension score (worst case drives the rating)
	overall := 0.0
	for _, v := range dims {
		if v > overall {
			overall = v
		}
	}

	// Cap at 10
	overall = math.Min(10, overall)

	return Result{
		Overall:    overall,
		Level:      overallToLevel(overall),
		Dimensions: dims,
		Findings:   findings,
		Plan:       plan,
	}
}

func categoryToDimension(cat rules.Category) Dimension {
	switch cat {
	case rules.CatDestruction:
		return DimDestruction
	case rules.CatSecurity:
		return DimSecurity
	case rules.CatNetwork:
		return DimNetwork
	case rules.CatStateful:
		return DimStateful
	default:
		return DimDestruction
	}
}

func overallToLevel(score float64) string {
	switch {
	case score >= 8:
		return "CRITICAL"
	case score >= 6:
		return "HIGH"
	case score >= 3:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/scorer/ -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add pkg/scorer/
git commit -m "feat: implement dimensional risk scorer with level classification"
```

---

### Task 7: Terminal Reporter

**Files:**
- Create: `pkg/reporter/terminal.go`
- Create: `pkg/reporter/reporter_test.go`

- [ ] **Step 1: Write the failing test**

```go
// pkg/reporter/reporter_test.go
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
	Terminal(&buf, result, false) // false = no color (for testing)

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/reporter/ -v`
Expected: FAIL

- [ ] **Step 3: Implement terminal reporter**

```go
// pkg/reporter/terminal.go
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
// If useColor is false, output is plain text (for testing/piping).
func Terminal(w io.Writer, result scorer.Result, useColor bool) {
	if !useColor {
		color.NoColor = true
		defer func() { color.NoColor = false }()
	}

	// Header
	levelColor := levelColorFn(result.Level)
	fmt.Fprintf(w, "\n  Blast Radius: %s (%s/10)\n\n",
		levelColor(result.Level),
		levelColor(fmt.Sprintf("%.1f", result.Overall)),
	)

	// Summary
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

	// Findings
	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "  No risks detected. All changes appear safe.\n\n")
		return
	}

	// Group by severity
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/reporter/ -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add pkg/reporter/terminal.go pkg/reporter/reporter_test.go
git commit -m "feat: implement colored terminal risk reporter"
```

---

### Task 8: JSON + Markdown Reporters

**Files:**
- Create: `pkg/reporter/json.go`
- Create: `pkg/reporter/markdown.go`
- Modify: `pkg/reporter/reporter_test.go`

- [ ] **Step 1: Add tests for JSON and Markdown output**

Append to `pkg/reporter/reporter_test.go`:

```go
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
	if !strings.Contains(output, `"level":"MEDIUM"`) {
		t.Error("JSON should contain level")
	}
	if !strings.Contains(output, `"overall":5`) {
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/reporter/ -v -run "JSON|Markdown"`
Expected: FAIL

- [ ] **Step 3: Implement JSON reporter**

```go
// pkg/reporter/json.go
package reporter

import (
	"encoding/json"
	"io"

	"github.com/rickyruima/blastradius/pkg/scorer"
)

type jsonReport struct {
	Overall    float64        `json:"overall"`
	Level      string         `json:"level"`
	Dimensions map[string]float64 `json:"dimensions"`
	Findings   []jsonFinding  `json:"findings"`
	Summary    jsonSummary    `json:"summary"`
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
```

- [ ] **Step 4: Implement Markdown reporter**

```go
// pkg/reporter/markdown.go
package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/rickyruima/blastradius/pkg/rules"
	"github.com/rickyruima/blastradius/pkg/scorer"
)

// Markdown writes the result as GitHub-flavored markdown to w.
func Markdown(w io.Writer, result scorer.Result) {
	fmt.Fprintf(w, "# Blast Radius: %s (%.1f/10)\n\n", result.Level, result.Overall)

	// Summary
	p := result.Plan
	total := p.TotalCreate + p.TotalUpdate + p.TotalDelete + p.TotalReplace
	fmt.Fprintf(w, "**%d resources affected** — ", total)
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
	fmt.Fprintf(w, "%s\n\n", strings.Join(parts, ", "))

	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "> No risks detected. All changes appear safe.\n")
		return
	}

	// Findings table
	fmt.Fprintf(w, "## Risks\n\n")
	fmt.Fprintf(w, "| Severity | Resource | Description |\n")
	fmt.Fprintf(w, "|----------|----------|-------------|\n")
	for _, f := range result.Findings {
		sev := severityEmoji(f.Rule.Severity) + " " + strings.ToUpper(string(f.Rule.Severity))
		fmt.Fprintf(w, "| %s | `%s` | %s |\n", sev, f.Resource.Address, f.Rule.Description)
	}
	fmt.Fprintln(w)
}

func severityEmoji(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return "🔴"
	case rules.SeverityHigh:
		return "🟠"
	case rules.SeverityMedium:
		return "🟡"
	default:
		return "⚪"
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/reporter/ -v`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add pkg/reporter/json.go pkg/reporter/markdown.go pkg/reporter/reporter_test.go
git commit -m "feat: add JSON and Markdown report formatters"
```

---

### Task 9: Config Loader

**Files:**
- Create: `pkg/config/config.go`
- Create: `pkg/config/config_test.go`

- [ ] **Step 1: Write the failing test**

```go
// pkg/config/config_test.go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/config/ -v`
Expected: FAIL

- [ ] **Step 3: Implement config loader**

```go
// pkg/config/config.go
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents .blastradius.yaml user configuration.
type Config struct {
	ProductionTags    []string           `yaml:"production_tags"`
	CriticalResources []string           `yaml:"critical_resources"`
	IgnoreRules       []string           `yaml:"ignore_rules"`
	Weights           map[string]float64 `yaml:"weights"`
}

// Load reads config from path. Returns defaults if file doesn't exist.
func Load(path string) (*Config, error) {
	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

func defaults() *Config {
	return &Config{
		ProductionTags: []string{
			"env:prod",
			"env:production",
			"environment:prod",
			"environment:production",
		},
		Weights: map[string]float64{
			"destruction": 1.0,
			"security":    1.0,
			"network":     1.0,
			"stateful":    1.0,
		},
	}
}

// ShouldIgnoreRule checks if a rule ID is in the ignore list.
func (c *Config) ShouldIgnoreRule(ruleID string) bool {
	for _, id := range c.IgnoreRules {
		if id == ruleID {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./pkg/config/ -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add pkg/config/
git commit -m "feat: implement config loader with defaults and YAML parsing"
```

---

### Task 10: CLI Wiring + Integration Test

**Files:**
- Modify: `cmd/blastradius/main.go`
- Create: `testdata/dangerous_plan.json`
- Modify: `go.mod` (tidy)

- [ ] **Step 1: Create a dangerous plan fixture for integration testing**

```json
// testdata/dangerous_plan.json
{
  "format_version": "1.2",
  "terraform_version": "1.7.0",
  "resource_changes": [
    {
      "address": "aws_db_instance.prod_main",
      "type": "aws_db_instance",
      "name": "prod_main",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["delete", "create"],
        "before": {
          "identifier": "prod-main-db",
          "engine": "postgres",
          "instance_class": "db.r5.xlarge",
          "tags": {"env": "prod", "Name": "prod-main-db"}
        },
        "after": {
          "identifier": "prod-main-db",
          "engine": "postgres",
          "instance_class": "db.r6g.xlarge",
          "tags": {"env": "prod", "Name": "prod-main-db"}
        },
        "after_unknown": {}
      }
    },
    {
      "address": "aws_security_group_rule.public_pg",
      "type": "aws_security_group_rule",
      "name": "public_pg",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "type": "ingress",
          "from_port": 5432,
          "to_port": 5432,
          "cidr_blocks": ["0.0.0.0/0"],
          "protocol": "tcp"
        },
        "after_unknown": {}
      }
    },
    {
      "address": "aws_iam_policy.admin_policy",
      "type": "aws_iam_policy",
      "name": "admin_policy",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["update"],
        "before": {
          "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}"
        },
        "after": {
          "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"
        },
        "after_unknown": {}
      }
    },
    {
      "address": "aws_s3_bucket.logs",
      "type": "aws_s3_bucket",
      "name": "logs",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["delete"],
        "before": {
          "bucket": "company-logs-prod",
          "tags": {"env": "prod"}
        },
        "after": null,
        "after_unknown": {}
      }
    },
    {
      "address": "aws_instance.worker",
      "type": "aws_instance",
      "name": "worker",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["update"],
        "before": {
          "instance_type": "t3.large",
          "tags": {"env": "prod"}
        },
        "after": {
          "instance_type": "t3.xlarge",
          "tags": {"env": "prod"}
        },
        "after_unknown": {}
      }
    },
    {
      "address": "aws_lambda_function.cron",
      "type": "aws_lambda_function",
      "name": "cron",
      "provider_name": "registry.terraform.io/hashicorp/aws",
      "change": {
        "actions": ["update"],
        "before": {"runtime": "python3.11"},
        "after": {"runtime": "python3.12"},
        "after_unknown": {}
      }
    }
  ],
  "configuration": {
    "root_module": {
      "resources": [
        {
          "address": "aws_db_instance.prod_main",
          "type": "aws_db_instance",
          "name": "prod_main",
          "expressions": {
            "vpc_security_group_ids": {
              "references": ["aws_security_group.db.id", "aws_security_group.db"]
            }
          }
        },
        {
          "address": "aws_instance.worker",
          "type": "aws_instance",
          "name": "worker",
          "expressions": {
            "subnet_id": {
              "references": ["aws_subnet.main.id", "aws_subnet.main"]
            }
          }
        }
      ]
    }
  }
}
```

- [ ] **Step 2: Implement the CLI with cobra**

```go
// cmd/blastradius/main.go
package main

import (
	"fmt"
	"os"

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
	)

	scan := &cobra.Command{
		Use:   "scan <plan.json>",
		Short: "Analyze a terraform plan JSON for risk",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(args[0], configPath, format)
		},
	}

	scan.Flags().StringVarP(&configPath, "config", "c", ".blastradius.yaml", "path to config file")
	scan.Flags().StringVarP(&format, "format", "f", "terminal", "output format: terminal, json, markdown")

	root.AddCommand(scan)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(planPath, configPath, format string) error {
	// Read plan file
	data, err := os.ReadFile(planPath)
	if err != nil {
		return fmt.Errorf("read plan file: %w", err)
	}

	// Parse plan
	plan, err := parser.Parse(data)
	if err != nil {
		return fmt.Errorf("parse plan: %w", err)
	}

	// Load config
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Load rules
	allRules, err := rules.LoadEmbedded()
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}

	// Filter ignored rules
	var activeRules []rules.Rule
	for _, r := range allRules {
		if !cfg.ShouldIgnoreRule(r.ID) {
			activeRules = append(activeRules, r)
		}
	}

	// Evaluate rules
	engine := rules.NewEngine(activeRules)
	findings := engine.Evaluate(plan.Resources)

	// Build dependency graph
	depGraph := graph.Build(plan.Resources)
	_, maxImpact := depGraph.MaxImpact()

	// Score
	result := scorer.Score(findings, plan, maxImpact)

	// Report
	switch format {
	case "json":
		return reporter.JSON(os.Stdout, result)
	case "markdown":
		reporter.Markdown(os.Stdout, result)
	default:
		reporter.Terminal(os.Stdout, result, true)
	}

	// Exit with non-zero for HIGH/CRITICAL (useful for CI)
	if result.Level == "CRITICAL" || result.Level == "HIGH" {
		os.Exit(2)
	}
	return nil
}
```

- [ ] **Step 3: Run `go mod tidy` and build**

Run:
```bash
cd /Users/ruima/Desktop/app_dev/blastradius && go mod tidy && go build ./cmd/blastradius/
```
Expected: builds successfully, produces `blastradius` binary

- [ ] **Step 4: Integration test — run against dangerous plan**

Run:
```bash
cd /Users/ruima/Desktop/app_dev/blastradius && ./blastradius scan testdata/dangerous_plan.json; echo "exit: $?"
```
Expected output (approximately):
```
  Blast Radius: CRITICAL (10.0/10)

  Summary
    6 resources affected (1 update, 1 destroy, 1 replace, ...)

  Risks
    [CRITICAL] aws_db_instance.prod_main
             Database instance will be REPLACED — causes downtime and potential data loss
    [HIGH] aws_security_group_rule.public_pg
             Security group rule opens access to 0.0.0.0/0
    [HIGH] aws_iam_policy.admin_policy
             IAM policy modified — review permission scope
    [HIGH] aws_s3_bucket.logs
             S3 bucket will be deleted — all objects lost

exit: 2
```

- [ ] **Step 5: Test JSON output**

Run:
```bash
cd /Users/ruima/Desktop/app_dev/blastradius && ./blastradius scan testdata/dangerous_plan.json -f json 2>/dev/null || true
```
Expected: valid JSON output with level, findings, etc.

- [ ] **Step 6: Test markdown output**

Run:
```bash
cd /Users/ruima/Desktop/app_dev/blastradius && ./blastradius scan testdata/dangerous_plan.json -f markdown 2>/dev/null || true
```
Expected: markdown table with risks

- [ ] **Step 7: Run all tests**

Run: `cd /Users/ruima/Desktop/app_dev/blastradius && go test ./... -v`
Expected: ALL PASS

- [ ] **Step 8: Commit**

```bash
git add cmd/blastradius/main.go testdata/dangerous_plan.json go.mod go.sum
git commit -m "feat: wire CLI with cobra, complete scan pipeline, exit code for CI"
```

---

### Task 11: Example Config + README Update

**Files:**
- Create: `.blastradius.yaml.example`
- Modify: `README.md`

- [ ] **Step 1: Create example config**

```yaml
# .blastradius.yaml.example
# BlastRadius configuration
# Copy to .blastradius.yaml in your repo root

# Tags that identify production resources
production_tags:
  - "env:prod"
  - "env:production"
  - "environment:prod"
  - "environment:production"

# Resources that are always treated as critical
critical_resources:
  - "aws_db_instance.main"
  # - "aws_kms_key.master"

# Rules to skip (by rule ID)
ignore_rules: []
  # - "iam_role_change"

# Scoring weight multipliers (default 1.0)
weights:
  destruction: 1.0
  security: 1.0
  network: 1.0
  stateful: 1.0
```

- [ ] **Step 2: Update README**

```markdown
# BlastRadius

> Infracost tells you how much it costs. We tell you how dangerous it is.

Terraform plan blast radius analyzer. Scores every `terraform apply` by destruction risk — catches database replacements, public security groups, IAM escalations, and more.

## Install

```bash
go install github.com/rickyruima/blastradius/cmd/blastradius@latest
```

## Quick Start

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
blastradius scan plan.json
```

Output:
```
  Blast Radius: CRITICAL (8.4/10)

  Summary
    6 resources affected (2 create, 3 update, 1 replace)

  Risks
    [CRITICAL] aws_db_instance.prod_main
               Database instance will be REPLACED — causes downtime and potential data loss
    [HIGH]     aws_security_group_rule.public_pg
               Security group rule opens access to 0.0.0.0/0
    [HIGH]     aws_s3_bucket.logs
               S3 bucket will be deleted — all objects lost
```

## Output Formats

```bash
blastradius scan plan.json              # terminal (default, colored)
blastradius scan plan.json -f json      # JSON (for CI pipelines)
blastradius scan plan.json -f markdown  # Markdown (for PR comments)
```

## CI Integration

Exit code 2 when risk is HIGH or CRITICAL:
```yaml
- run: blastradius scan plan.json
  continue-on-error: false
```

## Configuration

Create `.blastradius.yaml` in your repo root:

```yaml
production_tags:
  - "env:prod"
critical_resources:
  - "aws_db_instance.main"
ignore_rules:
  - "iam_role_change"
weights:
  destruction: 1.5
```

See `.blastradius.yaml.example` for full options.

## Built-in Rules

24 rules across 4 categories:
- **Destruction** — database replacement/deletion, S3 bucket deletion, EKS/ECS deletion
- **Security** — IAM changes, KMS deletion, public security groups, secrets deletion
- **Network** — VPC deletion, route changes, NAT gateway, load balancer deletion
- **Stateful** — DynamoDB, EBS, EFS, SQS, SNS deletion

## Status

v0.1 — functional CLI. See PRD.md for roadmap.
```

- [ ] **Step 3: Commit**

```bash
git add .blastradius.yaml.example README.md
git commit -m "docs: add example config and update README with usage"
```

---

## Self-Review Checklist

**Spec coverage:**
- ✅ CLI tool: `blastradius scan plan.json` (Task 10)
- ✅ AWS resource support via rules (Task 4 — 24 rules covering RDS, EC2, IAM, S3, Lambda, VPC, SG, ELB, ECS, EKS, DynamoDB, KMS, etc.)
- ✅ JSON / Markdown / Terminal output (Tasks 7, 8)
- ✅ Dependency graph analysis (Task 5)
- ✅ Config file `.blastradius.yaml` (Task 9)
- ✅ Risk scoring 0-10 with dimensions (Task 6)
- ✅ Exit code for CI (Task 10)
- ⏭️ GitHub Action (v0.5 — not in v0.1 scope)

**Placeholder scan:** No TBDs, TODOs, or vague steps found.

**Type consistency:**
- `model.ResourceChange` used consistently across parser, rules, graph, scorer
- `rules.Finding` used consistently in engine, scorer, reporter
- `scorer.Result` used consistently in scorer output and reporter input
- `config.Config` used in CLI to filter rules
