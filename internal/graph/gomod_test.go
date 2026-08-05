package graph

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type stubCommandRunner struct {
	output []byte
	err    error
	name   string
	args   []string
	env    []string
}

func (s *stubCommandRunner) Run(_ context.Context, _ string, env []string, name string, args ...string) ([]byte, error) {
	s.name = name
	s.args = append([]string(nil), args...)
	s.env = append([]string(nil), env...)
	return s.output, s.err
}

func TestResolveGoBuildsRequirementGraph(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeTestFile(t, filepath.Join(project, "go.mod"), `module example.com/app

go 1.23

require (
	example.com/direct v1.2.0
	example.com/indirect v1.0.0 // indirect
)
`)
	runner := &stubCommandRunner{output: []byte(strings.Join([]string{
		"example.com/app example.com/direct@v1.2.0",
		"example.com/app example.com/indirect@v1.0.0",
		"example.com/direct@v1.2.0 example.com/transitive@v0.5.0",
		"example.com/indirect@v1.0.0 example.com/direct@v1.1.0",
		"example.com/direct@v1.2.0 go@1.23",
	}, "\n"))}

	result, err := newWithRunner(runner).Build(context.Background(), project, Options{})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if result.DependencyCount != 4 || result.DirectCount != 1 || result.TransitiveCount != 3 {
		t.Fatalf("unexpected graph counts: dependencies=%d direct=%d transitive=%d", result.DependencyCount, result.DirectCount, result.TransitiveCount)
	}
	direct := findNode(t, result.Nodes, "example.com/direct", "v1.2.0")
	if !direct.Direct || direct.Depth != 1 {
		t.Fatalf("expected selected direct module at depth 1, got %#v", direct)
	}
	indirect := findNode(t, result.Nodes, "example.com/indirect", "v1.0.0")
	if indirect.Direct || indirect.Depth != 1 {
		t.Fatalf("expected // indirect module to remain non-direct at depth 1, got %#v", indirect)
	}
	older := findNode(t, result.Nodes, "example.com/direct", "v1.1.0")
	if older.Direct || older.Depth != 2 {
		t.Fatalf("expected older module version to remain transitive, got %#v", older)
	}
	if runner.name != "go" || strings.Join(runner.args, " ") != "mod graph" {
		t.Fatalf("unexpected graph command: %s %v", runner.name, runner.args)
	}
	if !containsString(runner.env, "GOFLAGS=-mod=readonly") || !containsString(runner.env, "GOWORK=off") {
		t.Fatalf("expected readonly isolated Go environment, got %v", runner.env)
	}
}

func TestResolveGoMarksVersionedReplacementDirect(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeTestFile(t, filepath.Join(project, "go.mod"), `module example.com/app

go 1.23

require example.com/old v1.0.0

replace example.com/old => example.com/new v2.0.0
`)
	runner := &stubCommandRunner{output: []byte("example.com/app example.com/new@v2.0.0\n")}
	result, err := newWithRunner(runner).Build(context.Background(), project, Options{})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	replacement := findNode(t, result.Nodes, "example.com/new", "v2.0.0")
	if !replacement.Direct {
		t.Fatalf("expected replacement target to be direct, got %#v", replacement)
	}
}

func TestResolveGoFallsBackToDirectDependencies(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeTestFile(t, filepath.Join(project, "go.mod"), `module example.com/app

go 1.23

require (
	example.com/direct v1.2.0
	example.com/indirect v1.0.0 // indirect
)
`)
	runner := &stubCommandRunner{err: errors.New("go command unavailable")}
	result, err := newWithRunner(runner).Build(context.Background(), project, Options{})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if result.DependencyCount != 1 || result.DirectCount != 1 || result.TransitiveCount != 0 {
		t.Fatalf("unexpected fallback counts: %#v", result)
	}
	if !result.Partial || !hasWarning(result, "graph_fallback") {
		t.Fatalf("expected graph_fallback warning, got %#v", result.Warnings)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func findNode(t *testing.T, nodes []Node, name, version string) Node {
	t.Helper()
	for _, node := range nodes {
		if node.Name == name && node.Version == version {
			return node
		}
	}
	t.Fatalf("node %s@%s not found in %#v", name, version, nodes)
	return Node{}
}

func hasWarning(result Result, kind string) bool {
	for _, warning := range result.Warnings {
		if warning.Kind == kind {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
