package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"

	"github.com/tuntufye/deadcheck/internal/model"
)

type TableOptions struct {
	Version     string
	MinSeverity model.Severity
	Colorize    bool
}

func WriteTable(stdout, stderr io.Writer, result model.ScanResult, opts TableOptions) error {
	configureColor(opts.Colorize)

	if _, err := fmt.Fprintf(stdout, "deadcheck %s - scanning %s\n\n", opts.Version, result.Path); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "Found: %s\n\n", manifestSummary(result.Manifests, result.Dependencies)); err != nil {
		return err
	}

	for _, severity := range []model.Severity{model.SeverityCritical, model.SeverityWarning, model.SeverityInfo} {
		if severity.Rank() < opts.MinSeverity.Rank() {
			continue
		}
		group := reportsBySeverity(result.Dependencies, severity)
		if len(group) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(stdout, "%s (%d)\n", severityHeading(severity), len(group)); err != nil {
			return err
		}
		for _, dep := range group {
			if _, err := fmt.Fprintf(stdout, "  %s %s %s\n", severityGlyph(severity), dep.Dependency.Name, displayVersion(dep.Dependency.ResolvedVersion)); err != nil {
				return err
			}
			lines := summarizeFindings(dep.Findings, opts.MinSeverity)
			for _, line := range lines {
				if _, err := fmt.Fprintf(stdout, "    %s\n", line); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(stdout); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintf(stdout, "Health Score: %d/100 %s\n", result.Score, gradeLabel(result.Grade)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "Scanned %d dependencies across %d ecosystems in %.1fs\n", result.DependencyCount, len(result.Ecosystems), float64(result.DurationMS)/1000); err != nil {
		return err
	}

	if len(result.Warnings) > 0 {
		if _, err := fmt.Fprintln(stderr, "\nScan warnings:"); err != nil {
			return err
		}
		for _, warning := range result.Warnings {
			line := warning.Message
			if warning.Dependency != "" {
				line = warning.Dependency + ": " + line
			}
			if warning.Source != "" {
				line += fmt.Sprintf(" [%s]", warning.Source)
			}
			if _, err := fmt.Fprintf(stderr, "  - %s\n", line); err != nil {
				return err
			}
		}
	}

	return nil
}

func configureColor(enabled bool) {
	color.NoColor = !enabled
}

func manifestSummary(manifests []model.Manifest, reports []model.DependencyReport) string {
	counts := make(map[string]int)
	for _, report := range reports {
		counts[report.Dependency.Source]++
	}
	parts := make([]string, 0, len(manifests))
	for _, manifest := range manifests {
		parts = append(parts, fmt.Sprintf("%s (%d deps)", manifest.Filename, counts[manifest.Path]))
	}
	return strings.Join(parts, ", ")
}

func reportsBySeverity(reports []model.DependencyReport, severity model.Severity) []model.DependencyReport {
	group := make([]model.DependencyReport, 0)
	for _, report := range reports {
		if report.MaxSeverity == severity {
			group = append(group, report)
		}
	}
	return group
}

func severityHeading(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return color.New(color.FgRed, color.Bold).Sprint("CRITICAL")
	case model.SeverityWarning:
		return color.New(color.FgYellow, color.Bold).Sprint("WARNING")
	default:
		return color.New(color.FgCyan, color.Bold).Sprint("INFO")
	}
}

func severityGlyph(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return color.New(color.FgRed).Sprint("!")
	case model.SeverityWarning:
		return color.New(color.FgYellow).Sprint("~")
	default:
		return color.New(color.FgCyan).Sprint("i")
	}
}

func summarizeFindings(findings []model.Finding, minSeverity model.Severity) []string {
	filtered := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Severity.Rank() >= minSeverity.Rank() {
			filtered = append(filtered, finding)
		}
	}
	if len(filtered) == 0 {
		return nil
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].Kind != filtered[j].Kind {
			return filtered[i].Kind < filtered[j].Kind
		}
		return filtered[i].Title < filtered[j].Title
	})

	lines := make([]string, 0, len(filtered))
	vulnLines := make([]model.Finding, 0)
	for _, finding := range filtered {
		if finding.Kind == "cve" {
			vulnLines = append(vulnLines, finding)
			continue
		}
		lines = append(lines, formatFinding(finding))
		if finding.Suggestion != "" {
			lines = append(lines, "Fix: "+finding.Suggestion)
		}
	}

	if len(vulnLines) > 0 {
		prefix := []string{formatVulnerabilitySummary(vulnLines)}
		if suggestion := vulnLines[0].Suggestion; suggestion != "" {
			prefix = append(prefix, "Fix: "+suggestion)
		}
		lines = append(prefix, lines...)
	}

	return lines
}

func formatVulnerabilitySummary(findings []model.Finding) string {
	top := findings[0]
	label := top.Title
	if top.CVSS != nil {
		label += fmt.Sprintf(" (CVSS %.1f)", *top.CVSS)
	}
	label += " - " + top.Detail
	if len(findings) > 1 {
		label += fmt.Sprintf(" (+%d more)", len(findings)-1)
	}
	return label
}

func formatFinding(finding model.Finding) string {
	label := finding.Title
	if finding.Detail != "" {
		label += " - " + finding.Detail
	}
	return label
}

func displayVersion(version string) string {
	if version == "" {
		return "(version unknown)"
	}
	return version
}

func gradeLabel(grade model.Grade) string {
	switch grade {
	case model.GradeExcellent:
		return "excellent"
	case model.GradeGood:
		return "good"
	case model.GradeNeedsAttention:
		return "needs attention"
	default:
		return "critical"
	}
}

func ColorEnabled() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
