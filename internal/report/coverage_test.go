package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

func TestIncompleteReportsExposeCoverageWithoutHealthyScore(t *testing.T) {
	t.Parallel()
	result := model.ScanResult{
		Partial: true, Grade: model.GradeIncomplete, DependencyCount: 2, CheckedDependencyCount: 1,
		Dependencies: []model.DependencyReport{
			{Dependency: model.Dependency{Name: "checked-lib"}, Complete: true, MaxSeverity: model.SeverityOK},
			{Dependency: model.Dependency{Name: "unknown-lib"}, MaxSeverity: model.SeverityOK, Checks: []model.CheckResult{{Name: "vulnerability", Status: model.CheckFailed}}},
		},
		Warnings: []model.Warning{{Dependency: "unknown-lib", Kind: "lookup_failed", Message: "vulnerability: unavailable"}},
	}
	var stdout, stderr, summary, jsonOut bytes.Buffer
	if err := WriteTable(&stdout, &stderr, result, TableOptions{MinSeverity: model.SeverityWarning}); err != nil {
		t.Fatal(err)
	}
	if err := WriteGitHubSummary(&summary, result); err != nil {
		t.Fatal(err)
	}
	for name, output := range map[string]string{"terminal": stdout.String(), "github": summary.String()} {
		for _, want := range []string{"INCOMPLETE", "unavailable", "checked-lib", "unknown-lib", "vulnerability: failed", "in completed checks"} {
			if !strings.Contains(output, want) {
				t.Errorf("%s missing %q: %s", name, want, output)
			}
		}
		for _, forbidden := range []string{"100/100", "100 / 100", "EXCELLENT", "excellent"} {
			if strings.Contains(output, forbidden) {
				t.Errorf("%s suggests healthy score: %s", name, output)
			}
		}
	}
	if !strings.Contains(stdout.String(), "1 / 2 dependencies fully checked") || !strings.Contains(summary.String(), "1/2 dependencies fully checked") {
		t.Fatal("missing coverage counts")
	}
	if err := WriteJSON(&jsonOut, result); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(jsonOut.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if score, ok := payload["score"]; !ok || score != nil {
		t.Fatalf("expected explicit null score: %s", jsonOut.String())
	}
	if payload["grade"] != "incomplete" || payload["checked_dependency_count"] != float64(1) {
		t.Fatalf("unexpected JSON: %s", jsonOut.String())
	}
}
