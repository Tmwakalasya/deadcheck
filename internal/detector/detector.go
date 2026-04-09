package detector

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tuntufye/deadcheck/internal/model"
)

var supported = []string{"go.mod", "package.json", "requirements.txt"}

func Detect(target string) ([]model.Manifest, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("stat target: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("target must be a directory")
	}

	manifests := make([]model.Manifest, 0, len(supported))
	for _, filename := range supported {
		path := filepath.Join(target, filename)
		if _, err := os.Stat(path); err == nil {
			manifests = append(manifests, model.Manifest{Filename: filename, Path: path})
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat manifest %s: %w", filename, err)
		}
	}

	return manifests, nil
}
