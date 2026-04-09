package parser

import "github.com/Tmwakalasya/deadcheck/internal/model"

type Result struct {
	Dependencies []model.Dependency
	Warnings     []model.Warning
}

type Parser interface {
	CanParse(filename string) bool
	Parse(path string) (Result, error)
}
