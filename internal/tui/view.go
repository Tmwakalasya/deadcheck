package tui

import (
	"fmt"
	"image/color"
	"path/filepath"
	"strings"
	"time"

	"charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

var (
	accentColor   = lipgloss.Color("#51B7A8")
	criticalColor = lipgloss.Color("#E05D5D")
	warningColor  = lipgloss.Color("#D89B35")
	infoColor     = lipgloss.Color("#4F9DD9")
	cleanColor    = lipgloss.Color("#63B47A")
	mutedColor    = lipgloss.Color("#7D8790")
	borderColor   = lipgloss.Color("#52606B")
)

func (m appModel) View() tea.View {
	content := m.loadingView()
	if m.phase == phaseResults {
		content = m.resultsView()
	}

	view := tea.NewView(content)
	view.AltScreen = true
	view.WindowTitle = "deadcheck - dependency health"
	return view
}

func (m appModel) loadingView() string {
	frames := []string{"|", "/", "-", "\\"}
	status := []string{
		"detecting dependency manifests",
		"querying package registries",
		"matching versions against OSV",
		"building your health report",
	}
	statusIndex := int(time.Since(m.started)/(1200*time.Millisecond)) % len(status)
	spinner := lipgloss.NewStyle().Foreground(accentColor).Bold(true).Render(frames[m.frame%len(frames)])
	brand := lipgloss.NewStyle().Bold(true).Foreground(accentColor).Render("deadcheck")
	path := lipgloss.NewStyle().Foreground(mutedColor).Render(truncate(m.opts.Path, 66))
	elapsed := lipgloss.NewStyle().Foreground(mutedColor).Render(fmt.Sprintf("%.1fs elapsed", time.Since(m.started).Seconds()))

	body := strings.Join([]string{
		brand + "  " + lipgloss.NewStyle().Foreground(mutedColor).Render(m.opts.Version),
		"",
		spinner + "  " + status[statusIndex],
		"",
		path,
		elapsed,
		"",
		lipgloss.NewStyle().Foreground(mutedColor).Render("q / esc  cancel scan"),
	}, "\n")

	panelWidth := min(max(m.width-4, 12), 76)
	panel := lipgloss.NewStyle().
		Width(panelWidth).
		Padding(1).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Render(body)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, panel)
}

func (m appModel) resultsView() string {
	if m.width < 60 || m.height < 18 {
		return m.compactResultsView()
	}

	contentWidth := min(max(m.width-4, 48), 132)
	panelHeight := max(m.height-13, 7)

	header := m.headerView(contentWidth)
	summary := m.summaryView(contentWidth)
	tabs := m.tabsView(contentWidth)
	panels := m.panelsView(contentWidth, panelHeight)
	footer := m.footerView(contentWidth)

	content := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		"",
		summary,
		"",
		tabs,
		panels,
		footer,
	)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Top, content)
}

func (m appModel) compactResultsView() string {
	grade := strings.ToUpper(strings.ReplaceAll(string(m.result.Grade), "_", " "))
	score := "unavailable"
	if m.result.Score != nil && !m.result.Partial {
		score = fmt.Sprintf("%d / 100", *m.result.Score)
	} else {
		grade = "INCOMPLETE"
	}
	body := strings.Join([]string{
		lipgloss.NewStyle().Bold(true).Foreground(accentColor).Render("DEADCHECK"),
		"",
		lipgloss.NewStyle().Bold(true).Foreground(gradeColor(m.result.Grade)).Render(score),
		grade,
		"",
		fmt.Sprintf("%d/%d dependencies checked", m.result.CheckedDependencyCount, m.result.DependencyCount),
		fmt.Sprintf("%d scan warnings", len(m.result.Warnings)),
		"",
		lipgloss.NewStyle().Foreground(mutedColor).Render("Resize to 60x18 for the full inspector."),
		lipgloss.NewStyle().Foreground(mutedColor).Render("q / esc  quit"),
	}, "\n")
	width := min(max(m.width-2, 12), 54)
	panel := panelStyle(width, min(max(m.height-2, 8), 14)).Render(body)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, panel)
}

func (m appModel) headerView(width int) string {
	brand := lipgloss.NewStyle().Bold(true).Foreground(accentColor).Render("DEADCHECK")
	version := lipgloss.NewStyle().Foreground(mutedColor).Render(m.opts.Version)
	left := brand + "  " + version

	path := m.result.Path
	if path == "" {
		path = m.opts.Path
	}
	right := lipgloss.NewStyle().Foreground(mutedColor).Render(truncate(path, max(width-lipgloss.Width(left)-4, 12)))
	return spaceBetween(left, right, width)
}

func (m appModel) summaryView(width int) string {
	counts := severityCounts(m.result.Dependencies)
	grade := strings.ToUpper(strings.ReplaceAll(string(m.result.Grade), "_", " "))
	gradeStyle := lipgloss.NewStyle().Bold(true).Foreground(gradeColor(m.result.Grade))
	score := "unavailable"
	if m.result.Score != nil && !m.result.Partial {
		score = fmt.Sprintf("%d / 100", *m.result.Score)
	} else {
		grade = "INCOMPLETE"
	}

	scoreBody := lipgloss.NewStyle().Foreground(mutedColor).Render("HEALTH SCORE") + "\n" +
		lipgloss.NewStyle().Bold(true).Foreground(gradeColor(m.result.Grade)).Render(score) + "\n" +
		gradeStyle.Render(grade)

	partial := "complete scan"
	if m.result.Partial {
		partial = "incomplete scan"
	}
	metrics := []string{
		metric(fmt.Sprintf("%d/%d", m.result.CheckedDependencyCount, m.result.DependencyCount), "CHECKED"),
		metric(fmt.Sprintf("%d", len(m.result.Manifests)), "MANIFESTS"),
		metric(fmt.Sprintf("%d", len(m.result.Ecosystems)), "ECOSYSTEMS"),
		metric(fmt.Sprintf("%.1fs", float64(m.result.DurationMS)/1000), strings.ToUpper(partial)),
	}
	countsLine := strings.Join([]string{
		severityStat("CRITICAL", counts[model.SeverityCritical], criticalColor),
		severityStat("WARNING", counts[model.SeverityWarning], warningColor),
		severityStat("INFO", counts[model.SeverityInfo], infoColor),
		severityStat("CLEAN", counts[model.SeverityOK], cleanColor),
		severityStat("SCAN WARN", len(m.result.Warnings), mutedColor),
	}, "   ")

	if width < 78 {
		body := scoreBody + "\n\n" + strings.Join(metrics, "   ") + "\n" + countsLine
		return panelStyle(width, 8).Render(body)
	}

	scoreWidth := 21
	scorePanel := panelStyle(scoreWidth, 5).Render(scoreBody)
	metricWidth := width - scoreWidth - 1
	metricBody := strings.Join(metrics, "    ") + "\n\n" + countsLine
	metricsPanel := panelStyle(metricWidth, 5).Render(metricBody)
	return lipgloss.JoinHorizontal(lipgloss.Top, scorePanel, " ", metricsPanel)
}

func (m appModel) tabsView(width int) string {
	counts := severityCounts(m.result.Dependencies)
	issueCount := 0
	for _, report := range m.result.Dependencies {
		if report.MaxSeverity.Rank() >= m.opts.MinSeverity.Rank() {
			issueCount++
		}
	}

	labels := []string{
		fmt.Sprintf("1 ISSUES %d", issueCount),
		fmt.Sprintf("2 CRIT %d", counts[model.SeverityCritical]),
		fmt.Sprintf("3 WARN %d", counts[model.SeverityWarning]),
		fmt.Sprintf("4 INFO %d", counts[model.SeverityInfo]),
		fmt.Sprintf("5 CLEAN %d", counts[model.SeverityOK]),
		fmt.Sprintf("6 SCAN WARN %d", len(m.result.Warnings)),
	}

	var tabs []string
	for i, label := range labels {
		style := lipgloss.NewStyle().Padding(0, 1).Foreground(mutedColor)
		if i == m.tab {
			style = style.Bold(true).Foreground(accentColor).Underline(true)
		}
		tabs = append(tabs, style.Render(label))
	}
	line := strings.Join(tabs, " ")
	if lipgloss.Width(line) > width {
		line = lipgloss.NewStyle().MaxWidth(width).Render(line)
	}
	return line
}

func (m appModel) panelsView(width, height int) string {
	if width < 72 {
		listHeight := max(height/2, 5)
		detailHeight := max(height-listHeight, 5)
		return lipgloss.JoinVertical(
			lipgloss.Left,
			m.listView(width, listHeight),
			m.detailView(width, detailHeight),
		)
	}

	listWidth := width * 42 / 100
	detailWidth := width - listWidth - 1
	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		m.listView(listWidth, height),
		" ",
		m.detailView(detailWidth, height),
	)
}

func (m appModel) listView(width, height int) string {
	innerWidth := max(width-4, 10)
	rows := max(height-6, 1)
	count := m.itemCount()
	title := "DEPENDENCIES"
	if m.activeFilter() == filterScanWarnings {
		title = "SCAN WARNINGS"
	}
	lines := []string{
		spaceBetween(
			lipgloss.NewStyle().Bold(true).Render(title),
			lipgloss.NewStyle().Foreground(mutedColor).Render(fmt.Sprintf("%d", count)),
			innerWidth,
		),
		"",
	}

	if count == 0 {
		lines = append(lines, lipgloss.NewStyle().Foreground(cleanColor).Render("Nothing in this view."))
	} else if m.activeFilter() == filterScanWarnings {
		end := min(m.offset+rows, len(m.result.Warnings))
		for i := m.offset; i < end; i++ {
			warning := m.result.Warnings[i]
			name := warning.Dependency
			if name == "" {
				name = warning.Kind
			}
			lines = append(lines, m.listRow(i, "~", name, warning.Kind, innerWidth, warningColor))
		}
	} else {
		reports := m.filteredReports()
		end := min(m.offset+rows, len(reports))
		for i := m.offset; i < end; i++ {
			report := reports[i]
			meta := string(report.Dependency.Ecosystem)
			if report.Dependency.Dev {
				meta += " / dev"
			}
			lines = append(lines, m.listRow(i, severityMarker(report.MaxSeverity), report.Dependency.Name, meta, innerWidth, severityColor(report.MaxSeverity)))
		}
	}

	if count > 0 {
		lines = append(lines, "", lipgloss.NewStyle().Foreground(mutedColor).Render(fmt.Sprintf("%d / %d", m.cursor+1, count)))
	}
	return panelStyle(width, height).Render(strings.Join(lines, "\n"))
}

func (m appModel) listRow(index int, marker, name, meta string, width int, foreground color.Color) string {
	selector := " "
	if index == m.cursor {
		selector = lipgloss.NewStyle().Bold(true).Foreground(accentColor).Render(">")
	}
	prefix := selector + " " + lipgloss.NewStyle().Bold(true).Foreground(foreground).Render(marker) + " "
	metaText := lipgloss.NewStyle().Foreground(mutedColor).Render(meta)
	nameWidth := max(width-lipgloss.Width(prefix)-lipgloss.Width(metaText)-1, 6)
	row := prefix + spaceBetween(truncate(name, nameWidth), metaText, width-lipgloss.Width(prefix))
	if index == m.cursor {
		return lipgloss.NewStyle().Bold(true).Width(width).Render(row)
	}
	return row
}

func (m appModel) detailView(width, height int) string {
	innerWidth := max(width-4, 12)
	innerHeight := max(height-2, 3)
	if m.activeFilter() == filterScanWarnings {
		return panelStyle(width, height).Render(m.warningDetail(innerWidth, innerHeight))
	}
	return panelStyle(width, height).Render(m.dependencyDetail(innerWidth, innerHeight))
}

func (m appModel) dependencyDetail(width, height int) string {
	report := m.selectedReport()
	if report == nil {
		return strings.Join([]string{
			lipgloss.NewStyle().Bold(true).Render("NO DEPENDENCIES IN THIS VIEW"),
			"",
			lipgloss.NewStyle().Foreground(mutedColor).Render("Switch filters with h/l or the number keys."),
		}, "\n")
	}

	dep := report.Dependency
	meta := fmt.Sprintf("%s / %s", dep.Ecosystem, displayVersion(dep.ResolvedVersion))
	if dep.Dev {
		meta += " / development"
	}
	lines := []string{
		lipgloss.NewStyle().Bold(true).Foreground(severityColor(report.MaxSeverity)).Render(truncate(dep.Name, width)),
		lipgloss.NewStyle().Foreground(mutedColor).Render(truncate(meta, width)),
		lipgloss.NewStyle().Foreground(mutedColor).Render(truncate(filepath.Base(dep.Source)+" / "+dep.Constraint, width)),
		"",
	}

	if len(report.Findings) == 0 {
		lines = append(lines,
			lipgloss.NewStyle().Bold(true).Foreground(cleanColor).Render("NO FINDINGS"),
			"",
			lipgloss.NewStyle().Foreground(mutedColor).Render("No vulnerability, deprecation, or staleness finding was reported."),
		)
		return takeLines(strings.Join(lines, "\n"), height)
	}

	for _, finding := range report.Findings {
		title := finding.Title
		if finding.CVSS != nil {
			title += fmt.Sprintf(" / CVSS %.1f", *finding.CVSS)
		}
		badge := lipgloss.NewStyle().Bold(true).Foreground(severityColor(finding.Severity)).Render(strings.ToUpper(string(finding.Severity)))
		lines = append(lines, badge+"  "+lipgloss.NewStyle().Bold(true).Render(title))
		if finding.Detail != "" {
			lines = append(lines, strings.Split(lipgloss.Wrap(finding.Detail, width, " -/"), "\n")...)
		}
		if finding.Suggestion != "" {
			fix := lipgloss.NewStyle().Foreground(accentColor).Render("FIX") + "  " + finding.Suggestion
			lines = append(lines, strings.Split(lipgloss.Wrap(fix, width, " -/"), "\n")...)
		}
		lines = append(lines, "")
	}
	return takeLines(strings.Join(lines, "\n"), height)
}

func (m appModel) warningDetail(width, height int) string {
	warning := m.selectedWarning()
	if warning == nil {
		return strings.Join([]string{
			lipgloss.NewStyle().Bold(true).Foreground(cleanColor).Render("NO SCAN WARNINGS"),
			"",
			lipgloss.NewStyle().Foreground(mutedColor).Render("Every configured lookup completed cleanly."),
		}, "\n")
	}

	title := strings.ToUpper(strings.ReplaceAll(warning.Kind, "_", " "))
	lines := []string{
		lipgloss.NewStyle().Bold(true).Foreground(warningColor).Render(title),
		"",
	}
	if warning.Dependency != "" {
		lines = append(lines, lipgloss.NewStyle().Bold(true).Render(warning.Dependency), "")
	}
	lines = append(lines, strings.Split(lipgloss.Wrap(warning.Message, width, " -/"), "\n")...)
	if warning.Source != "" {
		lines = append(lines, "", lipgloss.NewStyle().Foreground(mutedColor).Render(truncate(warning.Source, width)))
	}
	return takeLines(strings.Join(lines, "\n"), height)
}

func (m appModel) footerView(width int) string {
	help := "h/l filter   j/k select   pgup/pgdn jump   1-6 views   q quit"
	if width < 76 {
		help = "h/l filter   j/k select   q quit"
	}
	return lipgloss.NewStyle().Foreground(mutedColor).Width(width).Align(lipgloss.Right).Render(help)
}

func panelStyle(width, height int) lipgloss.Style {
	return lipgloss.NewStyle().
		Width(max(width, 1)).
		Height(max(height, 1)).
		Padding(0, 1).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor)
}

func metric(value, label string) string {
	return lipgloss.NewStyle().Bold(true).Render(value) + " " + lipgloss.NewStyle().Foreground(mutedColor).Render(label)
}

func severityStat(label string, count int, foreground color.Color) string {
	return lipgloss.NewStyle().Bold(true).Foreground(foreground).Render(fmt.Sprintf("%s %d", label, count))
}

func severityMarker(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return "!"
	case model.SeverityWarning:
		return "~"
	case model.SeverityInfo:
		return "i"
	default:
		return "+"
	}
}

func severityColor(severity model.Severity) color.Color {
	switch severity {
	case model.SeverityCritical:
		return criticalColor
	case model.SeverityWarning:
		return warningColor
	case model.SeverityInfo:
		return infoColor
	default:
		return cleanColor
	}
}

func gradeColor(grade model.Grade) color.Color {
	switch grade {
	case model.GradeIncomplete:
		return warningColor
	case model.GradeExcellent:
		return cleanColor
	case model.GradeGood:
		return accentColor
	case model.GradeNeedsAttention:
		return warningColor
	default:
		return criticalColor
	}
}

func displayVersion(version string) string {
	if version == "" {
		return "version unknown"
	}
	return version
}

func spaceBetween(left, right string, width int) string {
	gap := max(width-lipgloss.Width(left)-lipgloss.Width(right), 1)
	return left + strings.Repeat(" ", gap) + right
}

func truncate(value string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= width {
		return value
	}
	if width <= 3 {
		return string(runes[:width])
	}
	return string(runes[:width-3]) + "..."
}

func takeLines(value string, height int) string {
	lines := strings.Split(value, "\n")
	if len(lines) <= height {
		return value
	}
	if height <= 1 {
		return "..."
	}
	return strings.Join(append(lines[:height-1], "..."), "\n")
}
