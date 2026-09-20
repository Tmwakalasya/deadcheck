package graph

import (
	"path/filepath"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/Tmwakalasya/deadcheck/internal/model"
	"github.com/Tmwakalasya/deadcheck/internal/parser"
)

// ResolveNPMDirect shares the graph resolver's lockfile precedence and physical
// package resolution, while preserving the health scan's direct-only scope.
func ResolveNPMDirect(manifest string) (parser.Result, error) {
	parsed, err := (parser.NPMParser{}).Parse(manifest)
	if err != nil {
		return parser.Result{}, err
	}
	g, err := New().resolveNPM(filepath.Dir(manifest), Options{})
	if err != nil {
		return parser.Result{}, err
	}
	locked := make(map[string]Node)
	for _, node := range g.nodes {
		if node.Direct && node.InstallPath != "" {
			locked[node.InstallPath] = node
		}
	}
	missingLock := false
	for _, warning := range g.warnings {
		if warning.Kind == "lockfile_missing" {
			missingLock = true
		}
	}

	// Manifest normalization is useful for the direct-only graph fallback, but
	// a range's lower bound is not an installed version suitable for OSV queries.
	warnings := make([]model.Warning, 0)
	for _, warning := range parsed.Warnings {
		if warning.Kind != "unsupported_version" {
			warnings = append(warnings, warning)
		}
	}
	for i := range parsed.Dependencies {
		dep := &parsed.Dependencies[i]
		dep.ResolvedVersion = ""
		if dep.SkipReason != "" {
			continue
		}
		if node, ok := locked["node_modules/"+dep.Name]; ok && node.Name == dep.Name {
			if version, exact := exactNPMVersion(node.Version); exact {
				dep.ResolvedVersion = version
				dep.VersionSource = node.Source
			}
		} else if missingLock {
			if version, exact := exactNPMVersion(dep.Constraint); exact {
				dep.ResolvedVersion = version
				dep.VersionSource = manifest
			}
		}
		if dep.ResolvedVersion == "" {
			warnings = append(warnings, model.Warning{
				Kind:       "unresolved_version",
				Message:    "no exact registry version could be resolved; provide a valid npm lockfile (an exact manifest version is accepted when no lockfile exists)",
				Dependency: dep.Name,
				Source:     manifest,
			})
		}
	}
	parsed.Warnings = warnings
	return parsed, nil
}

func exactNPMVersion(value string) (string, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	core, _, _ := strings.Cut(value, "-")
	core, _, _ = strings.Cut(core, "+")
	return value, len(strings.Split(core, ".")) == 3 && semver.IsValid("v"+value)
}
