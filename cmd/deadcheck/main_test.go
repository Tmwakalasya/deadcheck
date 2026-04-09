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

func runCLI(t *testing.T, baseURL string, args ...string) (string, string, int) {
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
