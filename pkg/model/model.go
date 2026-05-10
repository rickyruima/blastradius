package model

// Action represents a terraform resource change action.
type Action string

const (
	ActionCreate  Action = "create"
	ActionRead    Action = "read"
	ActionUpdate  Action = "update"
	ActionDelete  Action = "delete"
	ActionReplace Action = "replace"
	ActionNoOp    Action = "no-op"
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
