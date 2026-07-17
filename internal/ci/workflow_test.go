package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderWorkflowIncludesScheduledScan(t *testing.T) {
	t.Parallel()

	workflow := RenderWorkflow(Options{
		Schedule:       "15 9 * * 2",
		FailBelow:      75,
		ProductionOnly: true,
	})

	for _, want := range []string{
		"name: deadcheck",
		"workflow_dispatch:",
		"cron: \"15 9 * * 2\"",
		"go install github.com/Tmwakalasya/deadcheck@latest",
		"deadcheck --json --github-summary --production-only --fail-below 75 > deadcheck-report.json",
		"actions/upload-artifact@v4",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("expected workflow to contain %q\n%s", want, workflow)
		}
	}
}

func TestInitWorkflowCreatesWorkflowAndProtectsExistingFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path, err := InitWorkflow(Options{
		Path:      dir,
		FailBelow: 80,
	})
	if err != nil {
		t.Fatalf("InitWorkflow returned error: %v", err)
	}

	wantPath := filepath.Join(dir, ".github", "workflows", "deadcheck.yml")
	if path != wantPath {
		t.Fatalf("expected workflow path %q, got %q", wantPath, path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected workflow file to exist: %v", err)
	}

	if _, err := InitWorkflow(Options{Path: dir}); err == nil {
		t.Fatalf("expected existing workflow to require --force")
	}
}
