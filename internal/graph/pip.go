package graph

import (
	"path/filepath"

	"github.com/Tmwakalasya/deadcheck/internal/model"
	"github.com/Tmwakalasya/deadcheck/internal/parser"
)

func (b *Builder) resolvePip(target string) (subgraph, error) {
	manifest := filepath.Join(target, "requirements.txt")
	parsed, err := (parser.PipParser{}).Parse(manifest)
	if err != nil {
		return subgraph{}, err
	}
	root := rootID(model.EcosystemPyPI, "requirements.txt")
	g := subgraph{
		root: root,
		nodes: map[string]Node{root: {
			ID:        root,
			Name:      "requirements.txt",
			Ecosystem: model.EcosystemPyPI,
			Source:    manifest,
			Root:      true,
		}},
		warnings: append(parsed.Warnings, model.Warning{
			Kind:    "transitive_unavailable",
			Message: "Python graph is direct-only until a supported lockfile is present",
			Source:  manifest,
		}),
	}
	for _, dependency := range parsed.Dependencies {
		id := dependencyID(model.EcosystemPyPI, dependency.Name, dependency.ResolvedVersion, "")
		g.nodes[id] = Node{
			ID:        id,
			Name:      dependency.Name,
			Version:   dependency.ResolvedVersion,
			Ecosystem: model.EcosystemPyPI,
			Source:    manifest,
			Direct:    true,
		}
		g.edges = append(g.edges, Edge{From: root, To: id, Kind: "requirement", Constraint: dependency.Constraint})
	}
	return finalizeSubgraph(g, nil), nil
}
