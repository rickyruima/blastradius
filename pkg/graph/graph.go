package graph

import "github.com/rickyruima/blastradius/pkg/model"

// DependencyGraph represents resource dependencies for impact analysis.
type DependencyGraph struct {
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
