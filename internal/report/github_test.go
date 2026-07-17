package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

func TestWriteGitHubSummary(t *testing.T) {
	t.Parallel()

	result := model.ScanResult{
		Score:           72,
		Grade:           model.GradeGood,
		DependencyCount: 2,
		Ecosystems:      []model.Ecosystem{model.EcosystemNPM},
		DurationMS:      1200,
		Dependencies: []model.DependencyReport{
			{
				Dependency:  model.Dependency{Name: "lodash", Ecosystem: model.EcosystemNPM},
				MaxSeverity: model.SeverityCritical,
				Findings: []model.Finding{
					{
						Kind:     "cve",
						Severity: model.SeverityCritical,
						Title:    "CVE-2021-23337",
						Detail:   "command injection",
					},
				},
			},
			{
				Dependency:  model.Dependency{Name: "express", Ecosystem: model.EcosystemNPM},
				MaxSeverity: model.SeverityOK,
			},
		},
		Warnings: []model.Warning{{Kind: "lookup_failed", Message: "registry unavailable"}},
	}

	var out bytes.Buffer
	if err := WriteGitHubSummary(&out, result); err != nil {
		t.Fatalf("WriteGitHubSummary returned error: %v", err)
	}

	summary := out.String()
	for _, want := range []string{
		"## deadcheck report",
		"**Health Score:** 72/100 (good)",
		"**Scanned:** 2 dependencies across 1 ecosystem in 1.2s",
		"| critical | 1 |",
		"| scan warnings | 1 |",
		"| critical | `lodash` | CVE-2021-23337 - command injection |",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("expected summary to contain %q\n%s", want, summary)
		}
	}
}
