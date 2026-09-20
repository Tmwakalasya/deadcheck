package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

func WriteGitHubSummaryFromEnv(result model.ScanResult) error {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return fmt.Errorf("--github-summary requires GITHUB_STEP_SUMMARY to be set")
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open GitHub step summary: %w", err)
	}
	defer file.Close()

	return WriteGitHubSummary(file, result)
}

func WriteGitHubSummary(w io.Writer, result model.ScanResult) error {
	counts := severityCounts(result.Dependencies)
	if _, err := fmt.Fprintln(w, "## deadcheck report"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	score := "unavailable (INCOMPLETE)"
	if result.Score != nil && !result.Partial {
		score = fmt.Sprintf("%d/100 (%s)", *result.Score, gradeLabel(result.Grade))
	}
	if _, err := fmt.Fprintf(w, "**Health Score:** %s\n\n", score); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "**Scanned:** %d dependencies across %d %s in %.1fs\n\n", result.DependencyCount, len(result.Ecosystems), pluralize("ecosystem", len(result.Ecosystems)), float64(result.DurationMS)/1000); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "**Coverage:** %d/%d dependencies fully checked (direct dependencies only).\n\n", result.CheckedDependencyCount, result.DependencyCount); err != nil {
		return err
	}
	if result.Partial {
		if _, err := fmt.Fprintln(w, "**Scan incomplete:** unchecked dependencies may have additional findings.\n\n| Dependency | Checks |\n| --- | --- |"); err != nil {
			return err
		}
		for _, dep := range result.Dependencies {
			status := "complete"
			if !dep.Complete {
				status = "incomplete"
				if checks := incompleteChecks(dep); checks != "" {
					status += ": " + checks
				}
			}
			if _, err := fmt.Fprintf(w, "| %s | %s |\n", escapeMarkdownCell(dep.Dependency.Name), escapeMarkdownCell(status)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, "| Severity | Dependencies |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| --- | ---: |"); err != nil {
		return err
	}
	for _, severity := range []model.Severity{model.SeverityCritical, model.SeverityWarning, model.SeverityInfo} {
		if _, err := fmt.Fprintf(w, "| %s | %d |\n", severity, counts[severity]); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "| scan warnings | %d |\n", len(result.Warnings)); err != nil {
		return err
	}

	risky := riskyReports(result.Dependencies, 10)
	if len(risky) == 0 {
		if result.Partial {
			_, err := fmt.Fprintln(w, "\nNo critical or warning findings in completed checks.")
			return err
		}
		_, err := fmt.Fprintln(w, "\nNo critical or warning findings.")
		return err
	}

	if _, err := fmt.Fprintln(w, "\n### Top findings"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| Severity | Dependency | Finding |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| --- | --- | --- |"); err != nil {
		return err
	}
	for _, report := range risky {
		if _, err := fmt.Fprintf(w, "| %s | `%s` | %s |\n",
			report.MaxSeverity,
			escapeMarkdownCell(report.Dependency.Name),
			escapeMarkdownCell(summaryFinding(report.Findings)),
		); err != nil {
			return err
		}
	}
	return nil
}

func severityCounts(reports []model.DependencyReport) map[model.Severity]int {
	counts := make(map[model.Severity]int)
	for _, report := range reports {
		counts[report.MaxSeverity]++
	}
	return counts
}

func riskyReports(reports []model.DependencyReport, limit int) []model.DependencyReport {
	out := make([]model.DependencyReport, 0, limit)
	for _, report := range reports {
		if report.MaxSeverity.Rank() < model.SeverityWarning.Rank() {
			continue
		}
		out = append(out, report)
		if len(out) == limit {
			return out
		}
	}
	return out
}

func summaryFinding(findings []model.Finding) string {
	if len(findings) == 0 {
		return "No finding details"
	}
	finding := findings[0]
	if finding.Detail == "" {
		return finding.Title
	}
	return finding.Title + " - " + finding.Detail
}

func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

func pluralize(word string, count int) string {
	if count == 1 {
		return word
	}
	if len(word) > 1 && word[len(word)-1] == 'y' && !strings.ContainsRune("aeiou", rune(word[len(word)-2])) {
		return word[:len(word)-1] + "ies"
	}
	return word + "s"
}
