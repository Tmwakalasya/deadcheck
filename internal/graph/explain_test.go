package graph

import (
	"testing"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

func TestExplainFindsAlternateAndDuplicateInstallPaths(t *testing.T) {
	t.Parallel()

	result := explanationFixture()
	explanation := Explain(result, ExplainOptions{Query: "shared", MaxPaths: 10})
	if explanation.MatchCount != 2 {
		t.Fatalf("expected two physical matches, got %#v", explanation.Matches)
	}

	hoisted := findWhyMatch(t, explanation.Matches, "node_modules/shared")
	if len(hoisted.Paths) != 2 || hoisted.Truncated {
		t.Fatalf("expected two complete paths to hoisted dependency, got %#v", hoisted)
	}
	assertWhyPathNames(t, hoisted.Paths[0], "app", "alpha", "shared")
	assertWhyPathNames(t, hoisted.Paths[1], "app", "bravo", "shared")

	nested := findWhyMatch(t, explanation.Matches, "node_modules/alpha/node_modules/shared")
	if len(nested.Paths) != 1 {
		t.Fatalf("expected one path to nested installation, got %#v", nested.Paths)
	}
	assertWhyPathNames(t, nested.Paths[0], "app", "alpha", "shared")
}

func TestExplainCapsPathsAndSurvivesCycles(t *testing.T) {
	t.Parallel()

	result := explanationFixture()
	result.Edges = append(result.Edges, Edge{
		From: "npm:path:node_modules/shared",
		To:   "npm:path:node_modules/alpha",
		Kind: "peer",
	})
	explanation := Explain(result, ExplainOptions{Query: "shared", MaxPaths: 1})
	hoisted := findWhyMatch(t, explanation.Matches, "node_modules/shared")
	if len(hoisted.Paths) != 1 || !hoisted.Truncated {
		t.Fatalf("expected one returned path with truncation, got %#v", hoisted)
	}
	assertWhyPathNames(t, hoisted.Paths[0], "app", "alpha", "shared")
}

func TestExplainFiltersAndSuggestsNames(t *testing.T) {
	t.Parallel()

	result := explanationFixture()
	filtered := Explain(result, ExplainOptions{
		Query:     "SHARED",
		Version:   "1.0.0",
		Ecosystem: model.EcosystemNPM,
		MaxPaths:  10,
	})
	if filtered.MatchCount != 2 {
		t.Fatalf("expected case-insensitive npm matches, got %#v", filtered.Matches)
	}

	missingVersion := Explain(result, ExplainOptions{
		Query:     "shared",
		Version:   "9.0.0",
		Ecosystem: model.EcosystemNPM,
		MaxPaths:  10,
	})
	if missingVersion.MatchCount != 0 {
		t.Fatalf("expected version filter to remove matches, got %#v", missingVersion.Matches)
	}

	suggested := Explain(result, ExplainOptions{Query: "share", MaxPaths: 10})
	if suggested.MatchCount != 0 || len(suggested.Suggestions) != 1 || suggested.Suggestions[0] != "shared" {
		t.Fatalf("expected shared suggestion, got %#v", suggested)
	}
}

func explanationFixture() Result {
	root := Node{
		ID:        "npm:root:app",
		Name:      "app",
		Ecosystem: model.EcosystemNPM,
		Root:      true,
	}
	alpha := Node{
		ID:          "npm:path:node_modules/alpha",
		Name:        "alpha",
		Version:     "1.0.0",
		Ecosystem:   model.EcosystemNPM,
		InstallPath: "node_modules/alpha",
		Direct:      true,
	}
	bravo := Node{
		ID:          "npm:path:node_modules/bravo",
		Name:        "bravo",
		Version:     "1.0.0",
		Ecosystem:   model.EcosystemNPM,
		InstallPath: "node_modules/bravo",
		Direct:      true,
	}
	hoisted := Node{
		ID:          "npm:path:node_modules/shared",
		Name:        "shared",
		Version:     "1.0.0",
		Ecosystem:   model.EcosystemNPM,
		InstallPath: "node_modules/shared",
	}
	nested := Node{
		ID:          "npm:path:node_modules/alpha/node_modules/shared",
		Name:        "shared",
		Version:     "1.0.0",
		Ecosystem:   model.EcosystemNPM,
		InstallPath: "node_modules/alpha/node_modules/shared",
	}
	return Result{
		Path:  "/tmp/app",
		Roots: []string{root.ID},
		Nodes: []Node{root, alpha, bravo, hoisted, nested},
		Edges: []Edge{
			{From: root.ID, To: alpha.ID, Kind: "require"},
			{From: root.ID, To: bravo.ID, Kind: "require"},
			{From: root.ID, To: hoisted.ID, Kind: "require"},
			{From: alpha.ID, To: hoisted.ID, Kind: "require"},
			{From: alpha.ID, To: nested.ID, Kind: "require"},
			{From: bravo.ID, To: hoisted.ID, Kind: "require"},
		},
		Ecosystems: []model.Ecosystem{model.EcosystemNPM},
	}
}

func findWhyMatch(t *testing.T, matches []WhyMatch, installPath string) WhyMatch {
	t.Helper()
	for _, match := range matches {
		if match.Dependency.InstallPath == installPath {
			return match
		}
	}
	t.Fatalf("match at %q not found in %#v", installPath, matches)
	return WhyMatch{}
}

func assertWhyPathNames(t *testing.T, path WhyPath, expected ...string) {
	t.Helper()
	if len(path.Nodes) != len(expected) {
		t.Fatalf("expected path %v, got %#v", expected, path.Nodes)
	}
	for index, name := range expected {
		if path.Nodes[index].Name != name {
			t.Fatalf("expected path %v, got %#v", expected, path.Nodes)
		}
	}
	if len(path.Edges) != len(path.Nodes)-1 {
		t.Fatalf("expected one edge per hop, got nodes=%d edges=%d", len(path.Nodes), len(path.Edges))
	}
}
