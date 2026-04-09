package parser

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tuntufye/deadcheck/internal/model"
)

type NPMParser struct{}

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func (p NPMParser) CanParse(filename string) bool {
	return filename == "package.json"
}

func (p NPMParser) Parse(path string) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, fmt.Errorf("read package.json: %w", err)
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return Result{}, fmt.Errorf("parse package.json: %w", err)
	}

	deps := make([]model.Dependency, 0, len(pkg.Dependencies)+len(pkg.DevDependencies))
	warnings := make([]model.Warning, 0)
	appendDeps := func(items map[string]string, dev bool) {
		for name, constraint := range items {
			dep := model.Dependency{
				Name:       name,
				Ecosystem:  model.EcosystemNPM,
				Source:     path,
				Constraint: constraint,
				Direct:     true,
				Dev:        dev,
			}
			if version, ok := normalizeNPMConstraint(constraint); ok {
				dep.ResolvedVersion = version
			} else {
				warnings = append(warnings, model.Warning{
					Kind:       "unsupported_version",
					Message:    "unable to safely normalize version constraint; vulnerability checks will be skipped",
					Dependency: name,
					Source:     path,
				})
			}
			if unsupportedPrefix(constraint, npmUnsupportedPrefixes) {
				dep.SkipReason = "package.json uses a non-registry dependency source"
				warnings = append(warnings, model.Warning{
					Kind:       "unsupported_source",
					Message:    "skipping remote checks for non-registry dependency source",
					Dependency: name,
					Source:     path,
				})
			}
			deps = append(deps, dep)
		}
	}

	appendDeps(pkg.Dependencies, false)
	appendDeps(pkg.DevDependencies, true)

	return Result{Dependencies: deps, Warnings: warnings}, nil
}
