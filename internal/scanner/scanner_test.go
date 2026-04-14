package scanner

import (
	"testing"

	"github.com/Tmwakalasya/deadcheck/internal/model"
	"github.com/Tmwakalasya/deadcheck/internal/parser"
)

func TestFilterProductionOnlyRemovesDevDependenciesAndTheirWarnings(t *testing.T) {
	t.Parallel()

	result := parser.Result{
		Dependencies: []model.Dependency{
			{
				Name:            "lodash",
				Ecosystem:       model.EcosystemNPM,
				Source:          "/tmp/package.json",
				ResolvedVersion: "4.17.21",
			},
			{
				Name:            "vitest",
				Ecosystem:       model.EcosystemNPM,
				Source:          "/tmp/package.json",
				ResolvedVersion: "1.2.0",
				Dev:             true,
			},
		},
		Warnings: []model.Warning{
			{
				Kind:       "unsupported_source",
				Message:    "skipping remote checks for non-registry dependency source",
				Dependency: "vitest",
				Source:     "/tmp/package.json",
			},
			{
				Kind:       "lookup_failed",
				Message:    "registry timed out",
				Dependency: "lodash",
				Source:     "/tmp/package.json",
			},
		},
	}

	filtered := filterProductionOnly(result)
	if len(filtered.Dependencies) != 1 {
		t.Fatalf("expected 1 dependency after filtering, got %d", len(filtered.Dependencies))
	}
	if filtered.Dependencies[0].Name != "lodash" {
		t.Fatalf("expected lodash to remain, got %q", filtered.Dependencies[0].Name)
	}
	if len(filtered.Warnings) != 1 {
		t.Fatalf("expected 1 warning after filtering, got %d", len(filtered.Warnings))
	}
	if filtered.Warnings[0].Dependency != "lodash" {
		t.Fatalf("expected only prod warning to remain, got %#v", filtered.Warnings[0])
	}
}

func TestFilterProductionOnlyKeepsWarningsWhenDependencyExistsInProdAndDev(t *testing.T) {
	t.Parallel()

	result := parser.Result{
		Dependencies: []model.Dependency{
			{
				Name:            "shared-lib",
				Ecosystem:       model.EcosystemNPM,
				Source:          "/tmp/package.json",
				ResolvedVersion: "1.0.0",
			},
			{
				Name:            "shared-lib",
				Ecosystem:       model.EcosystemNPM,
				Source:          "/tmp/package.json",
				ResolvedVersion: "1.0.0",
				Dev:             true,
			},
		},
		Warnings: []model.Warning{
			{
				Kind:       "unsupported_version",
				Message:    "unable to safely normalize version constraint; vulnerability checks will be skipped",
				Dependency: "shared-lib",
				Source:     "/tmp/package.json",
			},
		},
	}

	filtered := filterProductionOnly(result)
	if len(filtered.Dependencies) != 1 {
		t.Fatalf("expected 1 dependency after filtering, got %d", len(filtered.Dependencies))
	}
	if len(filtered.Warnings) != 1 {
		t.Fatalf("expected warning to remain when prod dependency still exists, got %d", len(filtered.Warnings))
	}
}
