package graph

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestBuildRequirementsGraphIsDirectOnlyAndPartial(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeTestFile(t, filepath.Join(project, "requirements.txt"), "Requests==2.31.0\n")

	result, err := New().Build(context.Background(), project, Options{})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if result.DependencyCount != 1 || result.DirectCount != 1 || result.TransitiveCount != 0 {
		t.Fatalf("unexpected Python graph counts: %#v", result)
	}
	if !result.Partial || !hasWarning(result, "transitive_unavailable") {
		t.Fatalf("expected direct-only warning, got %#v", result.Warnings)
	}
	dependency := findNode(t, result.Nodes, "requests", "2.31.0")
	if dependency.Ecosystem != "pypi" || dependency.Depth != 1 {
		t.Fatalf("unexpected normalized Python node: %#v", dependency)
	}
}

func TestBuildReturnsNoManifestError(t *testing.T) {
	t.Parallel()

	_, err := New().Build(context.Background(), t.TempDir(), Options{})
	if !errors.Is(err, ErrNoSupportedManifest) {
		t.Fatalf("expected ErrNoSupportedManifest, got %v", err)
	}
}

func TestEnvWithOverridesReplacesExistingValues(t *testing.T) {
	t.Parallel()

	env := envWithOverrides(
		[]string{"PATH=/bin", "GOFLAGS=-mod=mod", "GOWORK=/tmp/go.work"},
		"GOFLAGS=-mod=readonly",
		"GOWORK=off",
	)
	if len(env) != 3 {
		t.Fatalf("expected 3 environment values, got %v", env)
	}
	for _, want := range []string{"PATH=/bin", "GOFLAGS=-mod=readonly", "GOWORK=off"} {
		if !containsString(env, want) {
			t.Fatalf("expected environment to contain %q, got %v", want, env)
		}
	}
	for _, unwanted := range []string{"GOFLAGS=-mod=mod", "GOWORK=/tmp/go.work"} {
		if containsString(env, unwanted) {
			t.Fatalf("expected environment to exclude %q, got %v", unwanted, env)
		}
	}
}

func TestBuildEmptyManifestStillReportsEcosystem(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	writeTestFile(t, filepath.Join(project, "package.json"), `{"name":"empty"}`)
	result, err := New().Build(context.Background(), project, Options{})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if len(result.Ecosystems) != 1 || result.Ecosystems[0] != "npm" {
		t.Fatalf("expected npm ecosystem for empty manifest, got %#v", result.Ecosystems)
	}
}
