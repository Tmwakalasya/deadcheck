package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIJSONOutputAndFailBelow(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"dependencies":{"local-lib":"file:../local-lib"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLI(t, "http://127.0.0.1:1", "--json", project)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d\nstderr=%s", code, stderr)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}

	var payload struct {
		Score           int `json:"score"`
		DependencyCount int `json:"dependency_count"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("failed to decode JSON output: %v\nstdout=%s", err, stdout)
	}
	if payload.DependencyCount != 1 {
		t.Fatalf("expected dependency_count 1, got %d", payload.DependencyCount)
	}
	if payload.Score != 100 {
		t.Fatalf("expected score 100 for skipped local dependency, got %d", payload.Score)
	}

	_, _, code = runCLI(t, "http://127.0.0.1:1", "--json", "--fail-below", "101", project)
	if code != 1 {
		t.Fatalf("expected exit code 1 for fail-below threshold, got %d", code)
	}
}

func TestCLIGitHubSummaryKeepsJSONOutput(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"dependencies":{"local-lib":"file:../local-lib"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	summaryPath := filepath.Join(t.TempDir(), "summary.md")
	stdout, stderr, code := runCLIWithEnv(t, "http://127.0.0.1:1", []string{"GITHUB_STEP_SUMMARY=" + summaryPath}, "--json", "--github-summary", project)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d\nstderr=%s", code, stderr)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}

	var payload struct {
		Score int `json:"score"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("failed to decode JSON output: %v\nstdout=%s", err, stdout)
	}
	if payload.Score != 100 {
		t.Fatalf("expected score 100, got %d", payload.Score)
	}

	summary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("expected GitHub summary to be written: %v", err)
	}
	if !strings.Contains(string(summary), "## deadcheck report") {
		t.Fatalf("expected GitHub summary content, got %q", string(summary))
	}
}

func TestCLIProductionOnlyExcludesDevDependencies(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"dependencies":{"lodash":"4.17.21"},"devDependencies":{"vitest":"1.2.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, _, code := runCLI(t, "http://127.0.0.1:1", "--json", project)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	var full struct {
		DependencyCount int `json:"dependency_count"`
		Dependencies    []struct {
			Dependency struct {
				Name string `json:"name"`
				Dev  bool   `json:"dev"`
			} `json:"dependency"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(stdout), &full); err != nil {
		t.Fatalf("failed to decode full JSON output: %v\nstdout=%s", err, stdout)
	}
	if full.DependencyCount != 2 {
		t.Fatalf("expected dependency_count 2 without --production-only, got %d", full.DependencyCount)
	}

	stdout, _, code = runCLI(t, "http://127.0.0.1:1", "--json", "--production-only", project)
	if code != 0 {
		t.Fatalf("expected exit code 0 with --production-only, got %d", code)
	}

	var filtered struct {
		DependencyCount int `json:"dependency_count"`
		Dependencies    []struct {
			Dependency struct {
				Name string `json:"name"`
				Dev  bool   `json:"dev"`
			} `json:"dependency"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(stdout), &filtered); err != nil {
		t.Fatalf("failed to decode filtered JSON output: %v\nstdout=%s", err, stdout)
	}
	if filtered.DependencyCount != 1 {
		t.Fatalf("expected dependency_count 1 with --production-only, got %d", filtered.DependencyCount)
	}
	if len(filtered.Dependencies) != 1 {
		t.Fatalf("expected 1 dependency in JSON with --production-only, got %d", len(filtered.Dependencies))
	}
	if filtered.Dependencies[0].Dependency.Name != "lodash" {
		t.Fatalf("expected lodash to remain, got %q", filtered.Dependencies[0].Dependency.Name)
	}
	if filtered.Dependencies[0].Dependency.Dev {
		t.Fatalf("expected remaining dependency to be non-dev")
	}
}

func TestCLINoManifestProducesFatalJSON(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	stdout, _, code := runCLI(t, "http://127.0.0.1:1", "--json", project)
	if code != 3 {
		t.Fatalf("expected exit code 3, got %d", code)
	}

	var payload struct {
		Error string `json:"error"`
		Code  int    `json:"code"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("failed to decode JSON output: %v", err)
	}
	if payload.Code != 3 || payload.Error == "" {
		t.Fatalf("unexpected fatal payload: %#v", payload)
	}
}

func TestCLINoTUIUsesPlainReport(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"dependencies":{"local-lib":"file:../local-lib"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLI(t, "http://127.0.0.1:1", "--no-tui", project)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d\nstderr=%s", code, stderr)
	}
	for _, want := range []string{"DEADCHECK", "HEALTH SCORE", "No findings at or above the selected severity."} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected stdout to contain %q\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Fatalf("expected redirected output without ANSI escapes, got %q", stdout)
	}
	if !strings.Contains(stderr, "SCAN WARNINGS") {
		t.Fatalf("expected skipped local dependency warning, got %q", stderr)
	}
}

func TestCLIGraphJSONAndPlainText(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{
  "name": "cli-graph",
  "dependencies": {"alpha": "1.0.0"}
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package-lock.json"), []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/alpha": {
      "version": "1.0.0",
      "dependencies": {"beta": "2.0.0"}
    },
    "node_modules/beta": {"version": "2.0.0"}
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLI(t, "http://127.0.0.1:1", "graph", "--json", project)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d\nstderr=%s", code, stderr)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Fatalf("expected empty JSON stderr, got %q", stderr)
	}
	var payload struct {
		DependencyCount int `json:"dependency_count"`
		DirectCount     int `json:"direct_count"`
		TransitiveCount int `json:"transitive_count"`
		Nodes           []struct {
			Name        string `json:"name"`
			InstallPath string `json:"install_path"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("failed to decode graph JSON: %v\nstdout=%s", err, stdout)
	}
	if payload.DependencyCount != 2 || payload.DirectCount != 1 || payload.TransitiveCount != 1 {
		t.Fatalf("unexpected graph counts: %#v", payload)
	}
	foundPhysicalPath := false
	for _, node := range payload.Nodes {
		if node.Name == "beta" && node.InstallPath == "node_modules/beta" {
			foundPhysicalPath = true
		}
	}
	if !foundPhysicalPath {
		t.Fatalf("expected beta physical install path, got %#v", payload.Nodes)
	}

	stdout, stderr, code = runCLI(t, "http://127.0.0.1:1", "graph", "--depth", "1", project)
	if code != 0 {
		t.Fatalf("expected plain graph exit code 0, got %d\nstderr=%s", code, stderr)
	}
	for _, want := range []string{"DEADCHECK GRAPH", "2 dependencies  /  1 direct  /  1 transitive", "alpha 1.0.0 [direct]", "... 1 immediate dependency"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected graph output to contain %q\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Fatalf("expected redirected graph output without ANSI escapes, got %q", stdout)
	}
}

func TestCLIGraphNoManifestProducesFatalJSON(t *testing.T) {
	t.Parallel()

	stdout, _, code := runCLI(t, "http://127.0.0.1:1", "graph", "--json", t.TempDir())
	if code != 3 {
		t.Fatalf("expected exit code 3, got %d", code)
	}
	var payload struct {
		Error string `json:"error"`
		Code  int    `json:"code"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("failed to decode graph fatal JSON: %v\nstdout=%s", err, stdout)
	}
	if payload.Code != 3 || payload.Error == "" {
		t.Fatalf("unexpected graph fatal payload: %#v", payload)
	}
}

func TestCLIGraphRejectsConflictingPaths(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	other := t.TempDir()
	stdout, _, code := runCLI(t, "http://127.0.0.1:1", "graph", "--json", "--path", project, other)
	if code != 2 {
		t.Fatalf("expected usage exit code 2, got %d", code)
	}
	var payload struct {
		Error string `json:"error"`
		Code  int    `json:"code"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("failed to decode graph usage JSON: %v\nstdout=%s", err, stdout)
	}
	if payload.Code != 2 || !strings.Contains(payload.Error, "must match") {
		t.Fatalf("unexpected graph usage payload: %#v", payload)
	}
}

func TestCLIWhyJSONPlainTextAndNoMatch(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{
  "name": "why-app",
  "dependencies": {
    "alpha": "1.0.0",
    "bravo": "1.0.0"
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package-lock.json"), []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/alpha": {
      "version": "1.0.0",
      "dependencies": {"shared": "2.0.0"}
    },
    "node_modules/bravo": {
      "version": "1.0.0",
      "dependencies": {"shared": "2.0.0"}
    },
    "node_modules/shared": {"version": "2.0.0"}
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLI(t, "http://127.0.0.1:1", "why", "shared", "--json", project)
	if code != 0 {
		t.Fatalf("expected why exit code 0, got %d\nstderr=%s", code, stderr)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Fatalf("expected empty why JSON stderr, got %q", stderr)
	}
	var payload struct {
		MatchCount int `json:"match_count"`
		Matches    []struct {
			Dependency struct {
				Name        string `json:"name"`
				InstallPath string `json:"install_path"`
			} `json:"dependency"`
			Paths []struct {
				Nodes []struct {
					Name string `json:"name"`
				} `json:"nodes"`
			} `json:"paths"`
		} `json:"matches"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("failed to decode why JSON: %v\nstdout=%s", err, stdout)
	}
	if payload.MatchCount != 1 || len(payload.Matches) != 1 {
		t.Fatalf("expected one physical match, got %#v", payload)
	}
	if payload.Matches[0].Dependency.Name != "shared" || payload.Matches[0].Dependency.InstallPath != "node_modules/shared" {
		t.Fatalf("unexpected matched dependency: %#v", payload.Matches[0].Dependency)
	}
	if len(payload.Matches[0].Paths) != 2 {
		t.Fatalf("expected two causal paths, got %#v", payload.Matches[0].Paths)
	}

	stdout, stderr, code = runCLI(t, "http://127.0.0.1:1", "why", "--path", project, "shared")
	if code != 0 {
		t.Fatalf("expected plain why exit code 0, got %d\nstderr=%s", code, stderr)
	}
	for _, want := range []string{"DEADCHECK WHY", "QUERY  shared", "1 match  /  2 paths", "PATH 1", "PATH 2", "-> alpha 1.0.0 [direct]", "-> bravo 1.0.0 [direct]"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected why output to contain %q\n%s", want, stdout)
		}
	}

	stdout, stderr, code = runCLI(t, "http://127.0.0.1:1", "why", "share", "--json", project)
	if code != 1 {
		t.Fatalf("expected no-match exit code 1, got %d\nstderr=%s", code, stderr)
	}
	var missing struct {
		MatchCount  int      `json:"match_count"`
		Suggestions []string `json:"suggestions"`
	}
	if err := json.Unmarshal([]byte(stdout), &missing); err != nil {
		t.Fatalf("failed to decode no-match JSON: %v\nstdout=%s", err, stdout)
	}
	if missing.MatchCount != 0 || len(missing.Suggestions) != 1 || missing.Suggestions[0] != "shared" {
		t.Fatalf("unexpected no-match payload: %#v", missing)
	}
}

func TestCLIHelpExitsCleanly(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"--help"},
		{"graph", "--help"},
		{"why", "--help"},
		{"init", "ci", "--help"},
	} {
		_, stderr, code := runCLI(t, "http://127.0.0.1:1", args...)
		if code != 0 {
			t.Fatalf("%v: expected help exit code 0, got %d", args, code)
		}
		if !strings.Contains(stderr, "Usage") {
			t.Fatalf("%v: expected usage text, got %q", args, stderr)
		}
		if strings.Contains(stderr, "flag: help requested") {
			t.Fatalf("%v: help should not be reported as an error: %q", args, stderr)
		}
	}

	_, stderr, _ := runCLI(t, "http://127.0.0.1:1", "--help")
	for _, command := range []string{"deadcheck graph", "deadcheck why", "deadcheck init ci"} {
		if !strings.Contains(stderr, command) {
			t.Fatalf("expected top-level help to advertise %q, got %q", command, stderr)
		}
	}
}

func TestCLIInitCICreatesWorkflow(t *testing.T) {
	t.Parallel()

	project := t.TempDir()
	stdout, stderr, code := runCLI(t, "http://127.0.0.1:1", "init", "ci", "--path", project, "--production-only", "--fail-below", "70")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d\nstderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, ".github/workflows/deadcheck.yml") {
		t.Fatalf("expected stdout to mention workflow path, got %q", stdout)
	}

	workflow, err := os.ReadFile(filepath.Join(project, ".github", "workflows", "deadcheck.yml"))
	if err != nil {
		t.Fatalf("expected workflow to be created: %v", err)
	}
	content := string(workflow)
	for _, want := range []string{
		"schedule:",
		"deadcheck --json --github-summary --production-only --fail-below 70 > deadcheck-report.json",
		"actions/upload-artifact@v4",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected workflow to contain %q\n%s", want, content)
		}
	}
}

func runCLI(t *testing.T, baseURL string, args ...string) (string, string, int) {
	t.Helper()
	return runCLIWithEnv(t, baseURL, nil, args...)
}

func runCLIWithEnv(t *testing.T, baseURL string, extraEnv []string, args ...string) (string, string, int) {
	t.Helper()

	binary := buildCLI(t)
	cmd := exec.Command(binary, args...)
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(),
		"DEADCHECK_GO_PROXY_URL="+baseURL,
		"DEADCHECK_NPM_REGISTRY_URL="+baseURL,
		"DEADCHECK_PYPI_URL="+baseURL,
		"DEADCHECK_OSV_URL="+baseURL,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("go run failed unexpectedly: %v", err)
	}
	return stdout.String(), stderr.String(), exitErr.ExitCode()
}

func buildCLI(t *testing.T) string {
	t.Helper()

	target := filepath.Join(t.TempDir(), "deadcheck")
	cmd := exec.Command("go", "build", "-o", target, ".")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, string(output))
	}
	return target
}
