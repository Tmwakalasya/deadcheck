package checker

import (
	"context"

	"github.com/tuntufye/deadcheck/internal/model"
)

type Checker interface {
	Check(ctx context.Context, dep model.Dependency) ([]model.Finding, []model.Warning, error)
}
