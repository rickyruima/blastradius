package rules

import "github.com/rickyruima/blastradius/pkg/model"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type Category string

const (
	CatDestruction Category = "destruction"
	CatSecurity    Category = "security"
	CatNetwork     Category = "network"
	CatStateful    Category = "stateful"
)

type Rule struct {
	ID            string   `yaml:"id"`
	Severity      Severity `yaml:"severity"`
	Category      Category `yaml:"category"`
	Description   string   `yaml:"description"`
	ResourceTypes []string `yaml:"resource_types"`
	Actions       []string `yaml:"actions"`
	Condition     string   `yaml:"condition,omitempty"`
}

type Finding struct {
	Rule     Rule
	Resource model.ResourceChange
	Message  string
}

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
