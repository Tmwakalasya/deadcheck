package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/term"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

var ErrCanceled = errors.New("interactive scan canceled")

type ScanFunc func(context.Context) (model.ScanResult, error)

type Options struct {
	Version     string
	Path        string
	MinSeverity model.Severity
}

type phase int

const (
	phaseScanning phase = iota
	phaseResults
)

type filter int

const (
	filterIssues filter = iota
	filterCritical
	filterWarning
	filterInfo
	filterClean
	filterScanWarnings
)

var filters = []filter{
	filterIssues,
	filterCritical,
	filterWarning,
	filterInfo,
	filterClean,
	filterScanWarnings,
}

type scanFinishedMsg struct {
	result model.ScanResult
	err    error
}

type tickMsg time.Time

type appModel struct {
	ctx      context.Context
	cancel   context.CancelFunc
	scan     ScanFunc
	opts     Options
	phase    phase
	result   model.ScanResult
	err      error
	canceled bool
	started  time.Time
	frame    int
	width    int
	height   int
	tab      int
	cursor   int
	offset   int
}

func Run(ctx context.Context, stdin io.Reader, stdout io.Writer, opts Options, scan ScanFunc) (model.ScanResult, error) {
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	initial := newModel(scanCtx, cancel, opts, scan)
	program := tea.NewProgram(
		initial,
		tea.WithContext(ctx),
		tea.WithInput(stdin),
		tea.WithOutput(stdout),
		tea.WithEnvironment(os.Environ()),
	)

	final, err := program.Run()
	if err != nil {
		return model.ScanResult{}, err
	}
	state, ok := final.(appModel)
	if !ok {
		return model.ScanResult{}, fmt.Errorf("unexpected Bubble Tea model %T", final)
	}
	if state.err != nil {
		return model.ScanResult{}, state.err
	}
	if state.canceled || state.phase == phaseScanning {
		return model.ScanResult{}, ErrCanceled
	}

	if _, err := fmt.Fprintln(stdout, exitSummary(state.result)); err != nil {
		return model.ScanResult{}, err
	}
	return state.result, nil
}

func Enabled(stdin io.Reader, stdout io.Writer) bool {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	in, ok := stdin.(interface{ Fd() uintptr })
	if !ok || !term.IsTerminal(in.Fd()) {
		return false
	}
	out, ok := stdout.(interface{ Fd() uintptr })
	return ok && term.IsTerminal(out.Fd())
}

func newModel(ctx context.Context, cancel context.CancelFunc, opts Options, scan ScanFunc) appModel {
	return appModel{
		ctx:     ctx,
		cancel:  cancel,
		scan:    scan,
		opts:    opts,
		phase:   phaseScanning,
		started: time.Now(),
		width:   100,
		height:  32,
	}
}

func (m appModel) Init() tea.Cmd {
	return tea.Batch(m.runScan, nextTick())
}

func (m appModel) runScan() tea.Msg {
	result, err := m.scan(m.ctx)
	return scanFinishedMsg{result: result, err: err}
}

func nextTick() tea.Cmd {
	return tea.Tick(90*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = max(msg.Width, 1)
		m.height = max(msg.Height, 1)
		m.ensureCursorVisible()
		return m, nil
	case tickMsg:
		if m.phase == phaseScanning {
			m.frame++
			return m, nextTick()
		}
		return m, nil
	case scanFinishedMsg:
		if msg.err != nil {
			m.err = msg.err
			return m, tea.Quit
		}
		m.result = msg.result
		m.phase = phaseResults
		m.cursor = 0
		m.offset = 0
		return m, nil
	case tea.KeyPressMsg:
		return m.updateKey(msg)
	}
	return m, nil
}

func (m appModel) updateKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "q", "esc", "ctrl+c":
		if m.phase == phaseScanning {
			m.canceled = true
		}
		m.cancel()
		return m, tea.Quit
	}

	if m.phase != phaseResults {
		return m, nil
	}

	switch key {
	case "left", "h", "shift+tab":
		m.moveTab(-1)
	case "right", "l", "tab":
		m.moveTab(1)
	case "up", "k":
		m.moveCursor(-1)
	case "down", "j":
		m.moveCursor(1)
	case "pgup", "ctrl+u":
		m.moveCursor(-m.pageSize())
	case "pgdown", "ctrl+d":
		m.moveCursor(m.pageSize())
	case "home", "g":
		m.cursor = 0
		m.ensureCursorVisible()
	case "end", "G":
		m.cursor = max(m.itemCount()-1, 0)
		m.ensureCursorVisible()
	case "1", "2", "3", "4", "5", "6":
		m.tab = int(key[0] - '1')
		m.resetSelection()
	}
	return m, nil
}

func (m *appModel) moveTab(delta int) {
	m.tab = (m.tab + delta + len(filters)) % len(filters)
	m.resetSelection()
}

func (m *appModel) resetSelection() {
	m.cursor = 0
	m.offset = 0
}

func (m *appModel) moveCursor(delta int) {
	count := m.itemCount()
	if count == 0 {
		m.cursor = 0
		m.offset = 0
		return
	}
	m.cursor = min(max(m.cursor+delta, 0), count-1)
	m.ensureCursorVisible()
}

func (m *appModel) ensureCursorVisible() {
	page := m.pageSize()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+page {
		m.offset = m.cursor - page + 1
	}
	maxOffset := max(m.itemCount()-page, 0)
	m.offset = min(max(m.offset, 0), maxOffset)
}

func (m appModel) pageSize() int {
	panelHeight := max(m.height-13, 7)
	contentWidth := min(max(m.width-4, 48), 132)
	if contentWidth < 72 {
		panelHeight = max(panelHeight/2, 5)
	}
	return max(panelHeight-6, 1)
}

func (m appModel) itemCount() int {
	if m.activeFilter() == filterScanWarnings {
		return len(m.result.Warnings)
	}
	return len(m.filteredReports())
}

func (m appModel) activeFilter() filter {
	if m.tab < 0 || m.tab >= len(filters) {
		return filterIssues
	}
	return filters[m.tab]
}

func (m appModel) filteredReports() []model.DependencyReport {
	active := m.activeFilter()
	reports := make([]model.DependencyReport, 0, len(m.result.Dependencies))
	for _, report := range m.result.Dependencies {
		include := false
		switch active {
		case filterIssues:
			include = report.MaxSeverity.Rank() >= m.opts.MinSeverity.Rank()
		case filterCritical:
			include = report.MaxSeverity == model.SeverityCritical
		case filterWarning:
			include = report.MaxSeverity == model.SeverityWarning
		case filterInfo:
			include = report.MaxSeverity == model.SeverityInfo
		case filterClean:
			include = report.Complete && report.MaxSeverity == model.SeverityOK
		}
		if include {
			reports = append(reports, report)
		}
	}
	return reports
}

func (m appModel) selectedReport() *model.DependencyReport {
	reports := m.filteredReports()
	if len(reports) == 0 {
		return nil
	}
	index := min(max(m.cursor, 0), len(reports)-1)
	return &reports[index]
}

func (m appModel) selectedWarning() *model.Warning {
	if len(m.result.Warnings) == 0 {
		return nil
	}
	index := min(max(m.cursor, 0), len(m.result.Warnings)-1)
	return &m.result.Warnings[index]
}

func exitSummary(result model.ScanResult) string {
	counts := severityCounts(result.Dependencies)
	score := "INCOMPLETE (score unavailable)"
	if result.Score != nil && !result.Partial {
		score = fmt.Sprintf("%d/100 %s", *result.Score, strings.ReplaceAll(string(result.Grade), "_", " "))
	}
	return fmt.Sprintf(
		"deadcheck: %s | %d critical, %d warning | %d dependencies in %.1fs | %d/%d fully checked",
		score,
		counts[model.SeverityCritical],
		counts[model.SeverityWarning],
		result.DependencyCount,
		float64(result.DurationMS)/1000,
		result.CheckedDependencyCount,
		result.DependencyCount,
	)
}

func severityCounts(reports []model.DependencyReport) map[model.Severity]int {
	counts := make(map[model.Severity]int)
	for _, report := range reports {
		if report.MaxSeverity == model.SeverityOK && !report.Complete {
			continue
		}
		counts[report.MaxSeverity]++
	}
	return counts
}
