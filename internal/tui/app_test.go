package tui

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

func TestModelFiltersAndNavigatesResults(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newModel(ctx, cancel, Options{MinSeverity: model.SeverityWarning}, nil)
	m.phase = phaseResults
	m.result = sampleResult()
	m.width = 120
	m.height = 32

	if got := len(m.filteredReports()); got != 2 {
		t.Fatalf("expected 2 issue reports, got %d", got)
	}
	if selected := m.selectedReport(); selected == nil || selected.Dependency.Name != "critical-lib" {
		t.Fatalf("expected critical-lib to be selected, got %#v", selected)
	}

	m.moveCursor(1)
	if selected := m.selectedReport(); selected == nil || selected.Dependency.Name != "warning-lib" {
		t.Fatalf("expected warning-lib after moving down, got %#v", selected)
	}

	m.tab = int(filterInfo)
	m.resetSelection()
	if got := len(m.filteredReports()); got != 1 || m.filteredReports()[0].Dependency.Name != "info-lib" {
		t.Fatalf("expected the info filter to expose info-lib, got %#v", m.filteredReports())
	}

	m.tab = int(filterClean)
	if got := len(m.filteredReports()); got != 1 || m.filteredReports()[0].Dependency.Name != "clean-lib" {
		t.Fatalf("expected the clean filter to expose clean-lib, got %#v", m.filteredReports())
	}
}

func TestResultsViewContainsSummaryAndFindingDetail(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newModel(ctx, cancel, Options{Version: "v0.1.0", Path: ".", MinSeverity: model.SeverityWarning}, nil)
	m.phase = phaseResults
	m.result = sampleResult()
	m.width = 120
	m.height = 34

	view := m.View().Content
	for _, want := range []string{"DEADCHECK", "72", "critical-lib", "CVE-2026-1000", "upgrade to 2.0.0"} {
		if !strings.Contains(view, want) {
			t.Fatalf("expected view to contain %q\n%s", want, view)
		}
	}
}

func TestResultsViewFallsBackOnTinyTerminals(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newModel(ctx, cancel, Options{Version: "v0.1.0", Path: ".", MinSeverity: model.SeverityWarning}, nil)
	m.phase = phaseResults
	m.result = sampleResult()
	m.width = 40
	m.height = 14

	view := m.View().Content
	for _, want := range []string{"DEADCHECK", "72 / 100", "Resize to 60x18"} {
		if !strings.Contains(view, want) {
			t.Fatalf("expected compact view to contain %q\n%s", want, view)
		}
	}
}

func TestRunReturnsScanErrors(t *testing.T) {
	t.Parallel()

	want := errors.New("manifest exploded")
	var output bytes.Buffer
	_, err := Run(context.Background(), nil, &output, Options{Path: "."}, func(context.Context) (model.ScanResult, error) {
		return model.ScanResult{}, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("expected scan error %v, got %v", want, err)
	}
}

func TestExitSummary(t *testing.T) {
	t.Parallel()

	summary := exitSummary(sampleResult())
	for _, want := range []string{"72/100 good", "1 critical", "1 warning", "4 dependencies", "1.2s"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("expected summary to contain %q, got %q", want, summary)
		}
	}
}

func TestEnabledHonorsNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if Enabled(bytes.NewReader(nil), &bytes.Buffer{}) {
		t.Fatal("expected NO_COLOR to disable the interactive TUI")
	}
}

func sampleResult() model.ScanResult {
	return model.ScanResult{
		Path:            "/tmp/project",
		Score:           72,
		Grade:           model.GradeGood,
		DependencyCount: 4,
		DurationMS:      1200,
		Ecosystems:      []model.Ecosystem{model.EcosystemNPM},
		Manifests:       []model.Manifest{{Filename: "package.json", Path: "/tmp/project/package.json"}},
		Warnings: []model.Warning{{
			Kind:       "lookup_failed",
			Dependency: "warning-lib",
			Message:    "registry unavailable",
		}},
		Dependencies: []model.DependencyReport{
			{
				Dependency:  model.Dependency{Name: "critical-lib", Ecosystem: model.EcosystemNPM, ResolvedVersion: "1.0.0", Source: "/tmp/project/package.json", Constraint: "^1.0.0"},
				MaxSeverity: model.SeverityCritical,
				Findings: []model.Finding{{
					Kind:       "cve",
					Severity:   model.SeverityCritical,
					Title:      "CVE-2026-1000",
					Detail:     "remote code execution",
					Suggestion: "upgrade to 2.0.0",
				}},
			},
			{
				Dependency:  model.Dependency{Name: "warning-lib", Ecosystem: model.EcosystemNPM, ResolvedVersion: "1.0.0"},
				MaxSeverity: model.SeverityWarning,
				Findings:    []model.Finding{{Kind: "stale", Severity: model.SeverityWarning, Title: "STALE", Detail: "last release was 500 days ago"}},
			},
			{
				Dependency:  model.Dependency{Name: "info-lib", Ecosystem: model.EcosystemNPM, ResolvedVersion: "1.0.0"},
				MaxSeverity: model.SeverityInfo,
				Findings:    []model.Finding{{Kind: "stale", Severity: model.SeverityInfo, Title: "AGING", Detail: "last release was 200 days ago"}},
			},
			{
				Dependency:  model.Dependency{Name: "clean-lib", Ecosystem: model.EcosystemNPM, ResolvedVersion: "1.0.0"},
				MaxSeverity: model.SeverityOK,
			},
		},
	}
}
