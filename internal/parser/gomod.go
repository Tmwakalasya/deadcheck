package parser

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

type GoModParser struct{}

func (p GoModParser) CanParse(filename string) bool {
	return filename == "go.mod"
}

func (p GoModParser) Parse(path string) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, fmt.Errorf("read go.mod: %w", err)
	}

	file, err := modfile.Parse(path, data, nil)
	if err != nil {
		return Result{}, fmt.Errorf("parse go.mod: %w", err)
	}

	replaces := make(map[string]*modfile.Replace)
	for _, replace := range file.Replace {
		replaces[replace.Old.Path] = replace
	}

	deps := make([]model.Dependency, 0, len(file.Require))
	warnings := make([]model.Warning, 0)
	for _, req := range file.Require {
		if req.Indirect {
			continue
		}
		dep := model.Dependency{
			Name:            req.Mod.Path,
			Ecosystem:       model.EcosystemGo,
			Source:          path,
			Constraint:      req.Mod.Version,
			ResolvedVersion: req.Mod.Version,
			Direct:          true,
		}

		if replace, ok := replaces[req.Mod.Path]; ok {
			switch {
			case replace.New.Version == "":
				dep.SkipReason = "go.mod replace points to a local path"
				warnings = append(warnings, model.Warning{
					Kind:       "local_replace",
					Message:    "skipping remote checks for dependency replaced with a local path",
					Dependency: req.Mod.Path,
					Source:     path,
				})
			default:
				dep.Name = replace.New.Path
				dep.Constraint = replace.New.Version
				dep.ResolvedVersion = replace.New.Version
			}
		}

		deps = append(deps, dep)
	}

	return Result{Dependencies: deps, Warnings: warnings}, nil
}

func goModSourcePath(path string) string {
	return filepath.Clean(path)
}
