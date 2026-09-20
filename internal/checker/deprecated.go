package checker

import (
	"context"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

type DeprecatedChecker struct {
	registry metadataProvider
}

func (DeprecatedChecker) Name() string { return "deprecation" }

func NewDeprecated(reg metadataProvider) DeprecatedChecker {
	return DeprecatedChecker{registry: reg}
}

func (c DeprecatedChecker) Check(ctx context.Context, dep model.Dependency) ([]model.Finding, []model.Warning, error) {
	if dep.SkipReason != "" {
		return nil, nil, nil
	}
	if dep.Ecosystem == model.EcosystemNPM && dep.ResolvedVersion == "" {
		return nil, []model.Warning{{Kind: "unresolved_version", Message: "deprecation check skipped because an exact npm version is unavailable", Dependency: dep.Name, Source: dep.Source}}, nil
	}
	meta, err := c.registry.PackageMetadata(ctx, dep)
	if err != nil {
		return nil, nil, err
	}
	if meta.DeprecationError != nil {
		return nil, nil, meta.DeprecationError
	}
	if meta.DeprecationMessage == "" && !meta.Inactive {
		return nil, nil, nil
	}

	suggestion := "upgrade or replace this dependency"
	if meta.Inactive {
		suggestion = "replace this package with an actively maintained alternative"
	}

	return []model.Finding{{
		Kind:       "deprecated",
		Severity:   model.SeverityWarning,
		Title:      "DEPRECATED",
		Detail:     meta.DeprecationMessage,
		Suggestion: suggestion,
	}}, nil, nil
}
