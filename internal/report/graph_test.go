package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Tmwakalasya/deadcheck/internal/graph"
	"github.com/Tmwakalasya/deadcheck/internal/model"
)

func TestWriteGraphPlainTextShowsDepthSharedNodesAndWarnings(t *testing.T) {
	t.Parallel()

	result := graph.Result{
		Path:            "/tmp/project",
		Roots:           []string{"npm:root:app"},
		DependencyCount: 3,
		DirectCount:     2,
		TransitiveCount: 1,
		DurationMS:      25,
		Ecosystems:      []model.Ecosystem{model.EcosystemNPM},
		Nodes: []graph.Node{
			{ID: "npm:root:app", Name: "app", Ecosystem: model.EcosystemNPM, Root: true},
			{ID: "npm:path:alpha", Name: "alpha", Version: "1.0.0", Ecosystem: model.EcosystemNPM, Direct: true, Depth: 1},
			{ID: "npm:path:beta", Name: "beta", Version: "1.0.0", Ecosystem: model.EcosystemNPM, Direct: true, Depth: 1},
			{ID: "npm:path:shared", Name: "shared", Version: "2.0.0", Ecosystem: model.EcosystemNPM, Depth: 2},
		},
		Edges: []graph.Edge{
			{From: "npm:root:app", To: "npm:path:alpha", Kind: "require"},
			{From: "npm:root:app", To: "npm:path:beta", Kind: "require"},
			{From: "npm:path:alpha", To: "npm:path:shared", Kind: "require"},
			{From: "npm:path:beta", To: "npm:path:shared", Kind: "require"},
		},
		Warnings: []model.Warning{{Kind: "partial", Message: "fixture warning", Source: "/tmp/project/package-lock.json"}},
	}

	var stdout, stderr bytes.Buffer
	if err := WriteGraph(&stdout, &stderr, result, GraphOptions{Version: "v0.2.0", MaxDepth: 0}); err != nil {
		t.Fatalf("WriteGraph returned error: %v", err)
	}
	for _, want := range []string{"DEADCHECK GRAPH  v0.2.0", "3 dependencies  /  2 direct  /  1 transitive", "NPM  app", "alpha 1.0.0 [direct]", "shared 2.0.0", "[shared]"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("expected stdout to contain %q\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "\x1b[") {
		t.Fatalf("plain output must not contain ANSI escapes: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "GRAPH WARNINGS") || !strings.Contains(stderr.String(), "fixture warning") {
		t.Fatalf("expected graph warning on stderr, got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if err := WriteGraph(&stdout, &stderr, result, GraphOptions{MaxDepth: 1}); err != nil {
		t.Fatalf("WriteGraph with depth returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "... 1 immediate dependency") {
		t.Fatalf("expected depth truncation marker, got %s", stdout.String())
	}
}

func TestWriteGraphJSON(t *testing.T) {
	t.Parallel()

	result := graph.Result{
		Roots:      []string{},
		Nodes:      []graph.Node{},
		Edges:      []graph.Edge{},
		Warnings:   []model.Warning{},
		Ecosystems: []model.Ecosystem{},
	}
	var output bytes.Buffer
	if err := WriteGraphJSON(&output, result); err != nil {
		t.Fatalf("WriteGraphJSON returned error: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(output.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, field := range []string{"roots", "nodes", "edges", "warnings", "ecosystems"} {
		if _, ok := payload[field].([]any); !ok {
			t.Fatalf("expected %s to be a JSON array, got %#v", field, payload[field])
		}
	}
}

func TestGraphDisplayCollapsesRedundantRootEdges(t *testing.T) {
	t.Parallel()

	root := graph.Node{ID: "go:root:app", Name: "app", Root: true}
	direct := graph.Node{ID: "go:direct", Name: "direct", Direct: true}
	transitive := graph.Node{ID: "go:transitive", Name: "transitive"}
	isolated := graph.Node{ID: "go:isolated", Name: "isolated"}
	nodes := map[string]graph.Node{
		root.ID:       root,
		direct.ID:     direct,
		transitive.ID: transitive,
		isolated.ID:   isolated,
	}
	result := graph.Result{
		Roots: []string{root.ID},
		Nodes: []graph.Node{root, direct, transitive, isolated},
		Edges: []graph.Edge{
			{From: root.ID, To: direct.ID},
			{From: root.ID, To: transitive.ID},
			{From: root.ID, To: isolated.ID},
			{From: direct.ID, To: transitive.ID},
		},
	}

	adjacency := graphAdjacency(graph.ExplanationEdges(result), nodes)
	if len(adjacency[root.ID]) != 2 {
		t.Fatalf("expected direct and isolated root edges, got %#v", adjacency[root.ID])
	}
	if !containsGraphEdge(adjacency[root.ID], direct.ID) {
		t.Fatal("expected direct root edge to remain")
	}
	if containsGraphEdge(adjacency[root.ID], transitive.ID) {
		t.Fatal("expected redundant transitive root edge to collapse")
	}
	if !containsGraphEdge(adjacency[root.ID], isolated.ID) {
		t.Fatal("expected unreachable requirement component to remain attached")
	}
}

func containsGraphEdge(edges []graph.Edge, target string) bool {
	for _, edge := range edges {
		if edge.To == target {
			return true
		}
	}
	return false
}
