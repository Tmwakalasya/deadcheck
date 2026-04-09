package checker

import (
	"context"
	"fmt"
	"time"

	"github.com/Tmwakalasya/deadcheck/internal/model"
	"github.com/Tmwakalasya/deadcheck/internal/registry"
)

type metadataProvider interface {
	PackageMetadata(ctx context.Context, dep model.Dependency) (registry.PackageMetadata, error)
}

type StalenessChecker struct {
	now      func() time.Time
	registry metadataProvider
}

func NewStaleness(reg metadataProvider) StalenessChecker {
	return StalenessChecker{
		now:      time.Now,
		registry: reg,
	}
}

func (c StalenessChecker) Check(ctx context.Context, dep model.Dependency) ([]model.Finding, []model.Warning, error) {
	if dep.SkipReason != "" {
		return nil, nil, nil
	}
	meta, err := c.registry.PackageMetadata(ctx, dep)
	if err != nil {
		return nil, nil, err
	}
	if meta.LatestRelease.IsZero() {
		return nil, nil, nil
	}

	ageDays := int(c.now().UTC().Sub(meta.LatestRelease.UTC()).Hours() / 24)
	switch {
	case ageDays >= 730:
		return []model.Finding{{
			Kind:       "stale",
			Severity:   model.SeverityWarning,
			Title:      "ABANDONED",
			Detail:     fmt.Sprintf("last release was %d days ago", ageDays),
			Suggestion: staleSuggestion(meta.LatestVersion),
		}}, nil, nil
	case ageDays >= 365:
		return []model.Finding{{
			Kind:       "stale",
			Severity:   model.SeverityWarning,
			Title:      "STALE",
			Detail:     fmt.Sprintf("last release was %d days ago", ageDays),
			Suggestion: staleSuggestion(meta.LatestVersion),
		}}, nil, nil
	case ageDays >= 180:
		return []model.Finding{{
			Kind:       "stale",
			Severity:   model.SeverityInfo,
			Title:      "AGING",
			Detail:     fmt.Sprintf("last release was %d days ago", ageDays),
			Suggestion: staleSuggestion(meta.LatestVersion),
		}}, nil, nil
	default:
		return nil, nil, nil
	}
}

func staleSuggestion(latest string) string {
	if latest == "" {
		return "review this dependency for newer releases"
	}
	return fmt.Sprintf("review upgrade to %s", latest)
}
