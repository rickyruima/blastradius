package rules

import (
	"fmt"
	"strings"

	"github.com/rickyruima/blastradius/pkg/model"
)

type Engine struct {
	rules []Rule
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

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
	return dedup(findings)
}

// dedup keeps only the highest-severity finding per (resource address, category) pair.
func dedup(findings []Finding) []Finding {
	type key struct {
		address  string
		category Category
	}
	best := make(map[key]Finding)
	for _, f := range findings {
		k := key{address: f.Resource.Address, category: f.Rule.Category}
		existing, ok := best[k]
		if !ok || SeverityWeight(f.Rule.Severity) > SeverityWeight(existing.Rule.Severity) {
			best[k] = f
		}
	}
	result := make([]Finding, 0, len(best))
	for _, f := range best {
		result = append(result, f)
	}
	return result
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
