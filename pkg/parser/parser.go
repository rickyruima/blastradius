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
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

// extractReferences builds address->[]referenced_address from plan configuration.
func extractReferences(plan *tfjson.Plan) map[string][]string {
	refs := make(map[string][]string)
	if plan.Config == nil || plan.Config.RootModule == nil {
		return refs
	}
	for _, res := range plan.Config.RootModule.Resources {
		addr := res.Type + "." + res.Name
		seen := make(map[string]bool)
		for _, expr := range res.Expressions {
			if expr == nil || expr.ExpressionData == nil {
				continue
			}
			for _, ref := range expr.References {
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
