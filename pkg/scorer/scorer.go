package scorer

import (
	"math"

	"github.com/rickyruima/blastradius/pkg/model"
	"github.com/rickyruima/blastradius/pkg/rules"
)

type Dimension string

const (
	DimDestruction Dimension = "destruction"
	DimSecurity    Dimension = "security"
	DimNetwork     Dimension = "network"
	DimStateful    Dimension = "stateful"
	DimBlastRadius Dimension = "blast_radius"
)

type Result struct {
	Overall    float64
	Level      string
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

	for _, f := range findings {
		dim := categoryToDimension(f.Rule.Category)
		weight := rules.SeverityWeight(f.Rule.Severity)
		dims[dim] = math.Min(10, dims[dim]+weight)
	}

	if maxImpact > 0 {
		dims[DimBlastRadius] = math.Min(10, float64(maxImpact)*1.5)
	}

	overall := 0.0
	for _, v := range dims {
		if v > overall {
			overall = v
		}
	}
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
