package graph

import (
	"path/filepath"
	"testing"
)

func TestResolveNPMModernLockfilePreservesPhysicalTree(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeTestFile(t, filepath.Join(project, "package.json"), `{
  "name": "demo",
  "version": "1.0.0",
  "dependencies": {
    "alpha": "^1.0.0",
    "shared": "1.5.0"
  },
  "devDependencies": {
    "test-runner": "2.0.0"
  }
}`)
	writeTestFile(t, filepath.Join(project, "package-lock.json"), `{
  "name": "demo",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo",
      "version": "1.0.0"
    },
    "node_modules/alpha": {
      "version": "1.2.0",
      "dependencies": {
        "nested": "1.0.0",
        "shared": "^1.0.0"
      }
    },
    "node_modules/alpha/node_modules/nested": {
      "version": "1.0.0"
    },
    "node_modules/shared": {
      "version": "1.5.0"
    },
    "node_modules/test-runner": {
      "version": "2.0.0",
      "dev": true,
      "dependencies": {
        "dev-child": "3.0.0"
      }
    },
    "node_modules/dev-child": {
      "version": "3.0.0",
      "dev": true
    },
    "node_modules/orphan": {
      "version": "9.9.9"
    }
  }
}`)

	graph, err := New().resolveNPM(project, Options{})
	if err != nil {
		t.Fatalf("resolveNPM returned error: %v", err)
	}
	if len(graph.nodes) != 6 {
		t.Fatalf("expected root plus 5 reachable dependencies, got %d nodes: %#v", len(graph.nodes), graph.nodes)
	}
	if len(graph.edges) != 6 {
		t.Fatalf("expected 6 reachable edges, got %d: %#v", len(graph.edges), graph.edges)
	}
	if len(graph.warnings) != 0 {
		t.Fatalf("expected complete graph without warnings, got %#v", graph.warnings)
	}

	alpha := findNodeInMap(t, graph.nodes, "node_modules/alpha")
	shared := findNodeInMap(t, graph.nodes, "node_modules/shared")
	nested := findNodeInMap(t, graph.nodes, "node_modules/alpha/node_modules/nested")
	testRunner := findNodeInMap(t, graph.nodes, "node_modules/test-runner")
	devChild := findNodeInMap(t, graph.nodes, "node_modules/dev-child")
	if !alpha.Direct || alpha.Depth != 1 {
		t.Fatalf("unexpected alpha node: %#v", alpha)
	}
	if !shared.Direct || shared.Depth != 1 {
		t.Fatalf("expected hoisted shared package to be direct at depth 1, got %#v", shared)
	}
	if nested.Direct || nested.Depth != 2 {
		t.Fatalf("expected nested package at depth 2, got %#v", nested)
	}
	if !testRunner.Direct || !testRunner.Dev || testRunner.Depth != 1 {
		t.Fatalf("unexpected dev root: %#v", testRunner)
	}
	if devChild.Direct || !devChild.Dev || devChild.Depth != 2 {
		t.Fatalf("unexpected dev child: %#v", devChild)
	}
	if _, ok := nodeAtInstallPath(graph.nodes, "node_modules/orphan"); ok {
		t.Fatal("expected unreachable lockfile entry to be pruned")
	}
	if !hasEdge(graph.edges, alpha.ID, shared.ID) {
		t.Fatal("expected alpha to resolve its shared dependency to the hoisted package")
	}
}

func TestResolveNPMProductionOnlyPrunesDevSubtree(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeNPMDevFixture(t, project)
	graph, err := New().resolveNPM(project, Options{ProductionOnly: true})
	if err != nil {
		t.Fatalf("resolveNPM returned error: %v", err)
	}

	if len(graph.nodes) != 3 {
		t.Fatalf("expected root, runtime dependency, and runtime child; got %#v", graph.nodes)
	}
	if _, ok := nodeAtInstallPath(graph.nodes, "node_modules/test-runner"); ok {
		t.Fatal("expected devDependency to be pruned")
	}
	if _, ok := nodeAtInstallPath(graph.nodes, "node_modules/dev-child"); ok {
		t.Fatal("expected dev-only subtree to be pruned")
	}
}

func TestResolveNPMLegacyLockfileResolvesHoistedDependency(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeTestFile(t, filepath.Join(project, "package.json"), `{
  "name": "legacy-app",
  "dependencies": {
    "alpha": "1.0.0"
  }
}`)
	writeTestFile(t, filepath.Join(project, "package-lock.json"), `{
  "name": "legacy-app",
  "lockfileVersion": 1,
  "dependencies": {
    "alpha": {
      "version": "1.0.0",
      "requires": {
        "beta": "^2.0.0"
      }
    },
    "beta": {
      "version": "2.1.0"
    },
    "orphan": {
      "version": "9.9.9"
    }
  }
}`)

	graph, err := New().resolveNPM(project, Options{})
	if err != nil {
		t.Fatalf("resolveNPM returned error: %v", err)
	}
	alpha := findNodeInMap(t, graph.nodes, "node_modules/alpha")
	beta := findNodeInMap(t, graph.nodes, "node_modules/beta")
	if !alpha.Direct || beta.Direct || beta.Depth != 2 {
		t.Fatalf("unexpected legacy nodes: alpha=%#v beta=%#v", alpha, beta)
	}
	if !hasEdge(graph.edges, alpha.ID, beta.ID) {
		t.Fatal("expected legacy alpha dependency to resolve to hoisted beta")
	}
	if _, ok := nodeAtInstallPath(graph.nodes, "node_modules/orphan"); ok {
		t.Fatal("expected unreachable legacy lock entry to be pruned")
	}
}

func TestResolveNPMUsesShrinkwrapBeforePackageLock(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeTestFile(t, filepath.Join(project, "package.json"), `{"name":"demo","dependencies":{"alpha":"^2.0.0"}}`)
	writeTestFile(t, filepath.Join(project, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/alpha": {"version": "1.0.0"}
  }
}`)
	writeTestFile(t, filepath.Join(project, "npm-shrinkwrap.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/alpha": {"version": "2.1.0"}
  }
}`)

	graph, err := New().resolveNPM(project, Options{})
	if err != nil {
		t.Fatalf("resolveNPM returned error: %v", err)
	}
	alpha := findNodeInMap(t, graph.nodes, "node_modules/alpha")
	if alpha.Version != "2.1.0" || filepath.Base(alpha.Source) != "npm-shrinkwrap.json" {
		t.Fatalf("expected shrinkwrap dependency, got %#v", alpha)
	}
}

func TestResolveNPMSkipsLinkedWorkspaceWithoutDuplicateWarning(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeTestFile(t, filepath.Join(project, "package.json"), `{
  "name": "workspace-root",
  "dependencies": {"workspace-pkg": "workspace:*"}
}`)
	writeTestFile(t, filepath.Join(project, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/workspace-pkg": {
      "resolved": "packages/workspace-pkg",
      "link": true
    },
    "packages/workspace-pkg": {
      "name": "workspace-pkg",
      "version": "1.0.0"
    }
  }
}`)

	graph, err := New().resolveNPM(project, Options{})
	if err != nil {
		t.Fatalf("resolveNPM returned error: %v", err)
	}
	if len(graph.nodes) != 1 {
		t.Fatalf("expected linked workspace to be pruned, got %#v", graph.nodes)
	}
	if len(graph.warnings) != 1 || graph.warnings[0].Kind != "workspace_skipped" {
		t.Fatalf("expected one workspace warning, got %#v", graph.warnings)
	}
}

func TestResolveNPMDirectFallbackIncludesOptionalDependency(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeTestFile(t, filepath.Join(project, "package.json"), `{
  "name": "fallback",
  "dependencies": {"runtime": "1.0.0"},
  "optionalDependencies": {"optional-lib": "^2.0.0"}
}`)

	graph, err := New().resolveNPM(project, Options{})
	if err != nil {
		t.Fatalf("resolveNPM returned error: %v", err)
	}
	if len(graph.nodes) != 3 {
		t.Fatalf("expected root and both direct dependencies, got %#v", graph.nodes)
	}
	optional := findNodeByName(t, graph.nodes, "optional-lib")
	if !optional.Direct {
		t.Fatalf("expected optional dependency to be direct, got %#v", optional)
	}
	if !hasEdgeKind(graph.edges, graph.root, optional.ID, "optional") {
		t.Fatalf("expected optional edge, got %#v", graph.edges)
	}
}

func writeNPMDevFixture(t *testing.T, project string) {
	t.Helper()
	writeTestFile(t, filepath.Join(project, "package.json"), `{
  "name": "demo",
  "dependencies": {"runtime": "1.0.0"},
  "devDependencies": {"test-runner": "2.0.0"}
}`)
	writeTestFile(t, filepath.Join(project, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/runtime": {
      "version": "1.0.0",
      "dependencies": {"runtime-child": "1.1.0"}
    },
    "node_modules/runtime-child": {"version": "1.1.0"},
    "node_modules/test-runner": {
      "version": "2.0.0",
      "dev": true,
      "dependencies": {"dev-child": "2.1.0"}
    },
    "node_modules/dev-child": {"version": "2.1.0", "dev": true}
  }
}`)
}

func findNodeInMap(t *testing.T, nodes map[string]Node, installPath string) Node {
	t.Helper()
	node, ok := nodeAtInstallPath(nodes, installPath)
	if !ok {
		t.Fatalf("node at %q not found in %#v", installPath, nodes)
	}
	return node
}

func nodeAtInstallPath(nodes map[string]Node, installPath string) (Node, bool) {
	for _, node := range nodes {
		if node.InstallPath == installPath {
			return node, true
		}
	}
	return Node{}, false
}

func hasEdge(edges []Edge, from, to string) bool {
	for _, edge := range edges {
		if edge.From == from && edge.To == to {
			return true
		}
	}
	return false
}

func findNodeByName(t *testing.T, nodes map[string]Node, name string) Node {
	t.Helper()
	for _, node := range nodes {
		if node.Name == name {
			return node
		}
	}
	t.Fatalf("node named %q not found in %#v", name, nodes)
	return Node{}
}

func hasEdgeKind(edges []Edge, from, to, kind string) bool {
	for _, edge := range edges {
		if edge.From == from && edge.To == to && edge.Kind == kind {
			return true
		}
	}
	return false
}
