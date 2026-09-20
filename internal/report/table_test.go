package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

func TestWriteTablePlainText(t *testing.T) {
	t.Parallel()

	score := 85
	result := model.ScanResult{
		Path:                   "/tmp/project",
		Score:                  &score,
		CheckedDependencyCount: 1,
		Grade:                  model.GradeGood,
		DependencyCount:        1,
		DurationMS:             250,
		Ecosystems:             []model.Ecosystem{model.EcosystemNPM},
		Manifests:              []model.Manifest{{Filename: "package.json", Path: "/tmp/project/package.json"}},
		Dependencies: []model.DependencyReport{{
			Complete:    true,
			Dependency:  model.Dependency{Name: "old-lib", ResolvedVersion: "1.0.0", Source: "/tmp/project/package.json"},
			MaxSeverity: model.SeverityWarning,
			Findings:    []model.Finding{{Kind: "stale", Severity: model.SeverityWarning, Title: "STALE", Detail: "last release was 500 days ago"}},
		}},
	}

	var stdout, stderr bytes.Buffer
	err := WriteTable(&stdout, &stderr, result, TableOptions{
		Version:     "v0.1.0",
		MinSeverity: model.SeverityWarning,
		Colorize:    false,
	})
	if err != nil {
		t.Fatalf("WriteTable returned error: %v", err)
	}

	output := stdout.String()
	for _, want := range []string{"DEADCHECK  v0.1.0", "HEALTH SCORE  85 / 100  GOOD", "WARNING  1", "old-lib  1.0.0"} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q\n%s", want, output)
		}
	}
	if strings.Contains(output, "\x1b[") {
		t.Fatalf("plain output must not contain ANSI escapes: %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no warnings on stderr, got %q", stderr.String())
	}
}
