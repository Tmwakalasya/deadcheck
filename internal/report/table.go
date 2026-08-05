package report

import (
	"fmt"
	"image/color"
	"io"
	"os"
	"sort"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/term"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

type TableOptions struct {
	Version     string
	MinSeverity model.Severity
	Colorize    bool
}

func WriteTable(stdout, stderr io.Writer, result model.ScanResult, opts TableOptions) error {
	brand := renderStyle(opts.Colorize, "DEADCHECK", reportAccent, true)
	version := renderStyle(opts.Colorize, opts.Version, reportMuted, false)
	if _, err := fmt.Fprintf(stdout, "%s  %s\n%s\n", brand, version, result.Path); err != nil {
		return err
	}

	grade := strings.ToUpper(gradeLabel(result.Grade))
	score := renderStyle(opts.Colorize, fmt.Sprintf("%d / 100", result.Score), gradeColor(result.Grade), true)
	if _, err := fmt.Fprintf(stdout, "\nHEALTH SCORE  %s  %s\n", score, grade); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "%d %s  /  %d %s  /  %.1fs\n",
		result.DependencyCount,
		pluralize("dependency", result.DependencyCount),
		len(result.Ecosystems),
		pluralize("ecosystem", len(result.Ecosystems)),
		float64(result.DurationMS)/1000,
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "Manifests: %s\n\n", manifestSummary(result.Manifests, result.Dependencies)); err != nil {
		return err
	}

	printed := false
	for _, severity := range []model.Severity{model.SeverityCritical, model.SeverityWarning, model.SeverityInfo} {
		if severity.Rank() < opts.MinSeverity.Rank() {
			continue
		}
		group := reportsBySeverity(result.Dependencies, severity)
		if len(group) == 0 {
			continue
		}
		printed = true
		if _, err := fmt.Fprintf(stdout, "%s  %d\n", severityHeading(severity, opts.Colorize), len(group)); err != nil {
			return err
		}
		for _, dep := range group {
			if _, err := fmt.Fprintf(stdout, "  %s  %s  %s", severityGlyph(severity, opts.Colorize), dep.Dependency.Name, displayVersion(dep.Dependency.ResolvedVersion)); err != nil {
				return err
			}
			if dep.Dependency.Dev {
				if _, err := fmt.Fprint(stdout, "  [dev]"); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(stdout); err != nil {
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

	if !printed {
		if _, err := fmt.Fprintln(stdout, renderStyle(opts.Colorize, "No findings at or above the selected severity.", reportClean, true)); err != nil {
			return err
		}
	}

	if len(result.Warnings) > 0 {
		if _, err := fmt.Fprintln(stderr, "\nSCAN WARNINGS"); err != nil {
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

var (
	reportAccent   = lipgloss.Color("#51B7A8")
	reportCritical = lipgloss.Color("#E05D5D")
	reportWarning  = lipgloss.Color("#D89B35")
	reportInfo     = lipgloss.Color("#4F9DD9")
	reportClean    = lipgloss.Color("#63B47A")
	reportMuted    = lipgloss.Color("#7D8790")
)

func renderStyle(enabled bool, value string, foreground color.Color, bold bool) string {
	if !enabled {
		return value
	}
	return lipgloss.NewStyle().Foreground(foreground).Bold(bold).Render(value)
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

func severityHeading(severity model.Severity, colorize bool) string {
	switch severity {
	case model.SeverityCritical:
		return renderStyle(colorize, "CRITICAL", reportCritical, true)
	case model.SeverityWarning:
		return renderStyle(colorize, "WARNING", reportWarning, true)
	default:
		return renderStyle(colorize, "INFO", reportInfo, true)
	}
}

func severityGlyph(severity model.Severity, colorize bool) string {
	switch severity {
	case model.SeverityCritical:
		return renderStyle(colorize, "!", reportCritical, true)
	case model.SeverityWarning:
		return renderStyle(colorize, "~", reportWarning, true)
	default:
		return renderStyle(colorize, "i", reportInfo, true)
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

func gradeColor(grade model.Grade) color.Color {
	switch grade {
	case model.GradeExcellent:
		return reportClean
	case model.GradeGood:
		return reportAccent
	case model.GradeNeedsAttention:
		return reportWarning
	default:
		return reportCritical
	}
}

func ColorEnabled(w io.Writer) bool {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	file, ok := w.(interface{ Fd() uintptr })
	return ok && term.IsTerminal(file.Fd())
}
