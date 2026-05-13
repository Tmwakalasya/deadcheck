package ci

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const WorkflowPath = ".github/workflows/deadcheck.yml"

type Options struct {
	Path           string
	Schedule       string
	FailBelow      int
	ProductionOnly bool
	Force          bool
}

func InitWorkflow(opts Options) (string, error) {
	if opts.Path == "" {
		opts.Path = "."
	}
	if opts.Schedule == "" {
		opts.Schedule = "0 14 * * 1"
	}
	if opts.FailBelow < 0 {
		return "", fmt.Errorf("--fail-below must be greater than or equal to 0")
	}

	targetDir, err := filepath.Abs(opts.Path)
	if err != nil {
		return "", fmt.Errorf("resolve target path: %w", err)
	}

	path := filepath.Join(targetDir, WorkflowPath)
	if _, err := os.Stat(path); err == nil && !opts.Force {
		return "", fmt.Errorf("%s already exists; rerun with --force to overwrite", WorkflowPath)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("check existing workflow: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create workflow directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(RenderWorkflow(opts)), 0o644); err != nil {
		return "", fmt.Errorf("write workflow: %w", err)
	}
	return path, nil
}

func RenderWorkflow(opts Options) string {
	schedule := opts.Schedule
	if schedule == "" {
		schedule = "0 14 * * 1"
	}

	args := []string{"--json"}
	if opts.ProductionOnly {
		args = append(args, "--production-only")
	}
	if opts.FailBelow > 0 {
		args = append(args, "--fail-below", fmt.Sprintf("%d", opts.FailBelow))
	}

	return fmt.Sprintf(`name: deadcheck

on:
  workflow_dispatch:
  schedule:
    - cron: %q
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-go@v6
        with:
          go-version: stable
      - name: Install deadcheck
        run: go install github.com/Tmwakalasya/deadcheck@latest
      - name: Run deadcheck
        run: $(go env GOPATH)/bin/deadcheck %s > deadcheck-report.json
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: deadcheck-report
          path: deadcheck-report.json
`, schedule, strings.Join(args, " "))
}
