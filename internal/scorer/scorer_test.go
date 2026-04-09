package scorer

import (
	"testing"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

func TestScoreAppliesHighestVulnerabilityAndStalenessPenalties(t *testing.T) {
	t.Parallel()

	score, grade := Score([]model.DependencyReport{
		{
			Findings: []model.Finding{
				{Kind: "cve", Severity: model.SeverityCritical},
				{Kind: "cve", Severity: model.SeverityInfo},
				{Kind: "deprecated", Severity: model.SeverityWarning},
				{Kind: "stale", Severity: model.SeverityWarning, Title: "ABANDONED"},
			},
		},
		{
			Findings: []model.Finding{
				{Kind: "stale", Severity: model.SeverityWarning, Title: "STALE"},
			},
		},
	})

	if score != 68 {
		t.Fatalf("expected score 68, got %d", score)
	}
	if grade != model.GradeNeedsAttention {
		t.Fatalf("expected needs_attention, got %q", grade)
	}
}
