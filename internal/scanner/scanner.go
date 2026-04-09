package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/tuntufye/deadcheck/internal/checker"
	"github.com/tuntufye/deadcheck/internal/detector"
	"github.com/tuntufye/deadcheck/internal/model"
	"github.com/tuntufye/deadcheck/internal/parser"
	"github.com/tuntufye/deadcheck/internal/registry"
	"github.com/tuntufye/deadcheck/internal/scorer"
)

var ErrNoSupportedManifest = errors.New("no supported manifest found")

type Scanner struct {
	parsers  []parser.Parser
	checkers []checker.Checker
	workers  int
}

func New(httpClient *http.Client, urls registry.URLs, workers int) *Scanner {
	client := registry.NewClient(httpClient, urls)
	return &Scanner{
		parsers: []parser.Parser{
			parser.GoModParser{},
			parser.NPMParser{},
			parser.PipParser{},
		},
		checkers: []checker.Checker{
			checker.NewStaleness(client),
			checker.NewDeprecated(client),
			checker.NewVulnerability(client),
		},
		workers: workers,
	}
}

func (s *Scanner) Scan(ctx context.Context, target string) (model.ScanResult, error) {
	started := time.Now().UTC()
	absPath, err := filepath.Abs(target)
	if err != nil {
		return model.ScanResult{}, fmt.Errorf("resolve target path: %w", err)
	}

	manifests, err := detector.Detect(absPath)
	if err != nil {
		return model.ScanResult{}, err
	}
	if len(manifests) == 0 {
		return model.ScanResult{}, ErrNoSupportedManifest
	}

	var (
		allDeps  []model.Dependency
		warnings []model.Warning
	)
	for _, manifest := range manifests {
		parser := s.parserFor(manifest.Filename)
		if parser == nil {
			continue
		}
		result, err := parser.Parse(manifest.Path)
		if err != nil {
			return model.ScanResult{}, err
		}
		allDeps = append(allDeps, result.Dependencies...)
		warnings = append(warnings, result.Warnings...)
	}

	deduped := dedupeDependencies(allDeps)
	reports := make([]model.DependencyReport, len(deduped))
	partial := false

	g, groupCtx := errgroup.WithContext(ctx)
	g.SetLimit(s.workers)
	var mu sync.Mutex
	for i, dep := range deduped {
		i, dep := i, dep
		g.Go(func() error {
			report, depWarnings, depPartial := s.scanDependency(groupCtx, dep)
			mu.Lock()
			reports[i] = report
			warnings = append(warnings, depWarnings...)
			partial = partial || depPartial
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	if errors.Is(groupCtx.Err(), context.DeadlineExceeded) {
		partial = true
		warnings = append(warnings, model.Warning{
			Kind:    "timeout",
			Message: "scan timeout reached before all dependency checks completed",
			Source:  absPath,
		})
	}

	sortReports(reports)
	model.SortWarnings(warnings)
	score, grade := scorer.Score(reports)

	result := model.ScanResult{
		Path:            absPath,
		Manifests:       manifests,
		Dependencies:    reports,
		Warnings:        warnings,
		Score:           score,
		Grade:           grade,
		Partial:         partial || len(warnings) > 0,
		DependencyCount: len(reports),
		Ecosystems:      model.EcosystemsFromReports(reports),
		DurationMS:      time.Since(started).Milliseconds(),
		StartedAt:       started,
		CompletedAt:     time.Now().UTC(),
	}
	return result, nil
}

func (s *Scanner) parserFor(filename string) parser.Parser {
	for _, item := range s.parsers {
		if item.CanParse(filename) {
			return item
		}
	}
	return nil
}

func (s *Scanner) scanDependency(ctx context.Context, dep model.Dependency) (model.DependencyReport, []model.Warning, bool) {
	report := model.DependencyReport{
		Dependency:  dep,
		MaxSeverity: model.SeverityOK,
	}
	if dep.SkipReason != "" {
		return report, nil, true
	}

	var (
		findings []model.Finding
		warnings []model.Warning
		mu       sync.Mutex
		partial  bool
	)

	g, _ := errgroup.WithContext(ctx)
	for _, item := range s.checkers {
		item := item
		g.Go(func() error {
			result, itemWarnings, err := item.Check(ctx, dep)
			mu.Lock()
			defer mu.Unlock()
			findings = append(findings, result...)
			warnings = append(warnings, itemWarnings...)
			if len(itemWarnings) > 0 {
				partial = true
			}
			if err != nil {
				partial = true
				warnings = append(warnings, model.Warning{
					Kind:       "lookup_failed",
					Message:    err.Error(),
					Dependency: dep.Name,
					Source:     dep.Source,
				})
			}
			return nil
		})
	}
	_ = g.Wait()

	sortFindings(findings)
	report.Findings = findings
	for _, finding := range findings {
		report.MaxSeverity = model.MaxSeverity(report.MaxSeverity, finding.Severity)
		if finding.Kind == "cve" {
			report.VulnerabilityIDs = append(report.VulnerabilityIDs, finding.Title)
		}
	}
	return report, warnings, partial
}

func dedupeDependencies(deps []model.Dependency) []model.Dependency {
	index := make(map[string]int)
	out := make([]model.Dependency, 0, len(deps))
	for _, dep := range deps {
		key := dep.Key()
		if existing, ok := index[key]; ok {
			if !dep.Dev {
				out[existing].Dev = false
			}
			if out[existing].SkipReason == "" {
				out[existing].SkipReason = dep.SkipReason
			}
			continue
		}
		index[key] = len(out)
		out = append(out, dep)
	}
	return out
}

func sortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity.Rank() > findings[j].Severity.Rank()
		}
		if findings[i].Kind != findings[j].Kind {
			return findings[i].Kind < findings[j].Kind
		}
		return findings[i].Title < findings[j].Title
	})
}

func sortReports(reports []model.DependencyReport) {
	sort.SliceStable(reports, func(i, j int) bool {
		if reports[i].MaxSeverity != reports[j].MaxSeverity {
			return reports[i].MaxSeverity.Rank() > reports[j].MaxSeverity.Rank()
		}
		if reports[i].Dependency.Ecosystem != reports[j].Dependency.Ecosystem {
			return reports[i].Dependency.Ecosystem < reports[j].Dependency.Ecosystem
		}
		return reports[i].Dependency.Name < reports[j].Dependency.Name
	})
}
