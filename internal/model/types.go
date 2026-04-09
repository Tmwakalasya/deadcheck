package model

import (
	"path/filepath"
	"sort"
	"time"
)

type Ecosystem string

const (
	EcosystemGo   Ecosystem = "go"
	EcosystemNPM  Ecosystem = "npm"
	EcosystemPyPI Ecosystem = "pypi"
)

type Severity string

const (
	SeverityOK       Severity = "ok"
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func MaxSeverity(a, b Severity) Severity {
	if a.Rank() >= b.Rank() {
		return a
	}
	return b
}

func ParseSeverity(value string) (Severity, bool) {
	switch value {
	case "info":
		return SeverityInfo, true
	case "warning":
		return SeverityWarning, true
	case "critical":
		return SeverityCritical, true
	default:
		return SeverityOK, false
	}
}

type Dependency struct {
	Name            string    `json:"name"`
	Ecosystem       Ecosystem `json:"ecosystem"`
	Source          string    `json:"source"`
	Constraint      string    `json:"constraint"`
	ResolvedVersion string    `json:"resolved_version"`
	Direct          bool      `json:"direct"`
	Dev             bool      `json:"dev"`
	SkipReason      string    `json:"skip_reason,omitempty"`
}

func (d Dependency) Key() string {
	return string(d.Ecosystem) + "|" + d.Name + "|" + d.ResolvedVersion
}

type Finding struct {
	Kind        string    `json:"kind"`
	Severity    Severity  `json:"severity"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail"`
	Suggestion  string    `json:"suggestion,omitempty"`
	CVSS        *float64  `json:"cvss,omitempty"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	References  []string  `json:"references,omitempty"`
}

type Warning struct {
	Kind       string `json:"kind"`
	Message    string `json:"message"`
	Dependency string `json:"dependency,omitempty"`
	Source     string `json:"source,omitempty"`
}

type Manifest struct {
	Filename string `json:"filename"`
	Path     string `json:"path"`
}

type DependencyReport struct {
	Dependency       Dependency `json:"dependency"`
	Findings         []Finding  `json:"findings"`
	MaxSeverity      Severity   `json:"max_severity"`
	VulnerabilityIDs []string   `json:"vulnerability_ids,omitempty"`
}

type Grade string

const (
	GradeExcellent      Grade = "excellent"
	GradeGood           Grade = "good"
	GradeNeedsAttention Grade = "needs_attention"
	GradeCritical       Grade = "critical"
)

type ScanResult struct {
	Path            string             `json:"path"`
	Manifests       []Manifest         `json:"manifests"`
	Dependencies    []DependencyReport `json:"dependencies"`
	Warnings        []Warning          `json:"warnings"`
	Score           int                `json:"score"`
	Grade           Grade              `json:"grade"`
	Partial         bool               `json:"partial"`
	DependencyCount int                `json:"dependency_count"`
	Ecosystems      []Ecosystem        `json:"ecosystems"`
	DurationMS      int64              `json:"duration_ms"`
	StartedAt       time.Time          `json:"started_at"`
	CompletedAt     time.Time          `json:"completed_at"`
}

type FatalResult struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}

func EcosystemsFromReports(reports []DependencyReport) []Ecosystem {
	seen := make(map[Ecosystem]struct{})
	out := make([]Ecosystem, 0, len(reports))
	for _, report := range reports {
		if _, ok := seen[report.Dependency.Ecosystem]; ok {
			continue
		}
		seen[report.Dependency.Ecosystem] = struct{}{}
		out = append(out, report.Dependency.Ecosystem)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i] < out[j]
	})
	return out
}

func SortWarnings(warnings []Warning) {
	sort.SliceStable(warnings, func(i, j int) bool {
		if warnings[i].Source != warnings[j].Source {
			return filepath.Base(warnings[i].Source) < filepath.Base(warnings[j].Source)
		}
		if warnings[i].Dependency != warnings[j].Dependency {
			return warnings[i].Dependency < warnings[j].Dependency
		}
		if warnings[i].Kind != warnings[j].Kind {
			return warnings[i].Kind < warnings[j].Kind
		}
		return warnings[i].Message < warnings[j].Message
	})
}
