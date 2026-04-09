package parser

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

type PipParser struct{}

var requirementPattern = regexp.MustCompile(`^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?\s*([<>=~!,].+)?$`)

func (p PipParser) CanParse(filename string) bool {
	return filename == "requirements.txt"
}

func (p PipParser) Parse(path string) (Result, error) {
	file, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("open requirements.txt: %w", err)
	}
	defer file.Close()

	var (
		deps     []model.Dependency
		warnings []model.Warning
	)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = stripInlineComment(line)
		if unsupportedPrefix(line, pythonUnsupportedPrefixes) {
			warnings = append(warnings, model.Warning{
				Kind:   "unsupported_source",
				Message: "skipping unsupported requirements.txt directive or VCS/URL dependency",
				Source: path,
			})
			continue
		}

		parts := strings.SplitN(line, ";", 2)
		line = strings.TrimSpace(parts[0])

		matches := requirementPattern.FindStringSubmatch(line)
		if len(matches) == 0 {
			warnings = append(warnings, model.Warning{
				Kind:   "unsupported_version",
				Message: "unable to parse requirement line",
				Source: path,
			})
			continue
		}

		name := normalizePythonName(matches[1])
		constraint := strings.TrimSpace(matches[2])
		dep := model.Dependency{
			Name:       name,
			Ecosystem:  model.EcosystemPyPI,
			Source:     path,
			Constraint: constraint,
			Direct:     true,
		}
		if version, ok := normalizePythonConstraint(constraint); ok {
			dep.ResolvedVersion = version
		} else if constraint != "" {
			warnings = append(warnings, model.Warning{
				Kind:       "unsupported_version",
				Message:    "unable to safely normalize version constraint; vulnerability checks will be skipped",
				Dependency: name,
				Source:     path,
			})
		}

		deps = append(deps, dep)
	}

	if err := scanner.Err(); err != nil {
		return Result{}, fmt.Errorf("scan requirements.txt: %w", err)
	}

	return Result{Dependencies: deps, Warnings: warnings}, nil
}

func stripInlineComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] != '#' {
			continue
		}
		if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
			return strings.TrimSpace(line[:i])
		}
	}
	return strings.TrimSpace(line)
}
