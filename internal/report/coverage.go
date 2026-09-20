package report

import (
	"strings"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

func incompleteChecks(dep model.DependencyReport) string {
	if dep.Dependency.SkipReason != "" {
		return dep.Dependency.SkipReason
	}
	var checks []string
	for _, check := range dep.Checks {
		if check.Status != model.CheckComplete {
			checks = append(checks, check.Name+": "+string(check.Status))
		}
	}
	return strings.Join(checks, ", ")
}
