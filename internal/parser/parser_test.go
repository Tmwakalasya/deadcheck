package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

func TestGoModParserSkipsIndirectAndFlagsLocalReplace(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	content := `module example.com/test

go 1.22

require (
	github.com/acme/one v1.2.3
	github.com/acme/two v1.9.0 // indirect
	github.com/acme/local v0.0.1
)

replace github.com/acme/local => ../local
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := GoModParser{}.Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(result.Dependencies) != 2 {
		t.Fatalf("expected 2 direct dependencies, got %d", len(result.Dependencies))
	}
	if result.Dependencies[1].SkipReason == "" {
		t.Fatalf("expected local replace dependency to include skip reason")
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Kind != "local_replace" {
		t.Fatalf("expected local replace warning, got %#v", result.Warnings)
	}
}

func TestNPMParserNormalizesVersionsAndFlagsUnsupportedSources(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	content := `{
  "dependencies": {
    "lodash": "^4.17.19",
    "@types/node": "~20.10.0",
    "local-lib": "file:../local-lib"
  },
  "devDependencies": {
    "vitest": "1.2.x"
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := NPMParser{}.Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(result.Dependencies) != 4 {
		t.Fatalf("expected 4 dependencies, got %d", len(result.Dependencies))
	}

	byName := make(map[string]model.Dependency, len(result.Dependencies))
	for _, dep := range result.Dependencies {
		byName[dep.Name] = dep
	}
	if byName["lodash"].ResolvedVersion == "" {
		t.Fatalf("expected normalized version for lodash")
	}
	if !byName["vitest"].Dev {
		t.Fatalf("expected dev dependency flag to be preserved")
	}
	if byName["local-lib"].SkipReason == "" {
		t.Fatalf("expected non-registry dependency source to be skipped")
	}
	if len(result.Warnings) < 1 {
		t.Fatalf("expected warnings for unsupported sources")
	}
}

func TestPipParserNormalizesRequirementsAndSkipsUnsupportedLines(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	content := `
requests[socks]>=2.31.0 ; python_version >= "3.10"
urllib3==2.2.1 # pinned
-r other.txt
git+https://github.com/acme/project.git
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := PipParser{}.Parse(path)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(result.Dependencies) != 2 {
		t.Fatalf("expected 2 parsed dependencies, got %d", len(result.Dependencies))
	}
	if result.Dependencies[0].Name != "requests" || result.Dependencies[0].ResolvedVersion != "2.31.0" {
		t.Fatalf("unexpected normalization result: %#v", result.Dependencies[0])
	}
	if result.Dependencies[1].Ecosystem != model.EcosystemPyPI {
		t.Fatalf("expected PyPI ecosystem, got %q", result.Dependencies[1].Ecosystem)
	}
	if len(result.Warnings) != 2 {
		t.Fatalf("expected 2 warnings for unsupported lines, got %d", len(result.Warnings))
	}
}
