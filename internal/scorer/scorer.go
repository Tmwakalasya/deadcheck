package scorer

import "github.com/Tmwakalasya/deadcheck/internal/model"

func Score(reports []model.DependencyReport) (int, model.Grade) {
	score := 100
	for _, report := range reports {
		score -= vulnerabilityPenalty(report.Findings)
		if hasKind(report.Findings, "deprecated") {
			score -= 10
		}
		score -= stalePenalty(report.Findings)
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score, gradeForScore(score)
}

func vulnerabilityPenalty(findings []model.Finding) int {
	highest := model.SeverityOK
	for _, finding := range findings {
		if finding.Kind != "cve" {
			continue
		}
		highest = model.MaxSeverity(highest, finding.Severity)
	}
	switch highest {
	case model.SeverityCritical:
		return 15
	case model.SeverityWarning:
		return 8
	case model.SeverityInfo:
		return 3
	default:
		return 0
	}
}

func stalePenalty(findings []model.Finding) int {
	for _, finding := range findings {
		if finding.Kind != "stale" {
			continue
		}
		switch finding.Title {
		case "ABANDONED":
			return 5
		case "STALE":
			return 2
		}
	}
	return 0
}

func gradeForScore(score int) model.Grade {
	switch {
	case score >= 90:
		return model.GradeExcellent
	case score >= 70:
		return model.GradeGood
	case score >= 50:
		return model.GradeNeedsAttention
	default:
		return model.GradeCritical
	}
}

func hasKind(findings []model.Finding, kind string) bool {
	for _, finding := range findings {
		if finding.Kind == kind {
			return true
		}
	}
	return false
}
