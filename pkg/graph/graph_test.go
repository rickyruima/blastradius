package graph

import (
	"testing"

	"github.com/rickyruima/blastradius/pkg/model"
)

func TestBuildGraph_ImpactCount(t *testing.T) {
	resources := []model.ResourceChange{
		{Address: "aws_vpc.main", References: nil},
		{Address: "aws_subnet.a", References: []string{"aws_vpc.main"}},
		{Address: "aws_subnet.b", References: []string{"aws_vpc.main"}},
		{Address: "aws_instance.web", References: []string{"aws_subnet.a"}},
		{Address: "aws_db_instance.main", References: []string{"aws_subnet.b"}},
	}

	g := Build(resources)

	impact := g.ImpactCount("aws_vpc.main")
	if impact != 4 {
		t.Errorf("aws_vpc.main impact: expected 4, got %d", impact)
	}

	impact = g.ImpactCount("aws_subnet.a")
	if impact != 1 {
		t.Errorf("aws_subnet.a impact: expected 1, got %d", impact)
	}

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
