package checker

import (
	"context"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

type Checker interface {
	Name() string
	Check(ctx context.Context, dep model.Dependency) ([]model.Finding, []model.Warning, error)
}
