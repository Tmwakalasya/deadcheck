// Package testutil provides synthetic projects for repeatable, offline tests.
package testutil

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func PackageName(index int) string { return fmt.Sprintf("pkg-%05d", index) }

// NPMProject creates a reachable tree with three children per parent and shared
// paths from the direct dependencies to its last leaf. It never installs code.
func NPMProject(tb testing.TB, direct, total int) string {
	tb.Helper()
	if direct < 1 || total < direct {
		tb.Fatal("invalid fixture size")
	}
	dir := tb.TempDir()
	type pkg struct {
		Version      string            `json:"version,omitempty"`
		Dependencies map[string]string `json:"dependencies,omitempty"`
	}
	dependencies := make(map[string]string, direct)
	packages := make(map[string]*pkg, total+1)
	packages[""] = &pkg{}
	for i := 0; i < total; i++ {
		name := PackageName(i)
		packages["node_modules/"+name] = &pkg{Version: "1.2.3", Dependencies: make(map[string]string)}
		if i < direct {
			dependencies[name] = "^1.0.0"
		}
		if i >= direct {
			parent := PackageName((i - direct) / 3)
			packages["node_modules/"+parent].Dependencies[name] = "^1.0.0"
		}
	}
	if total > direct {
		for i := 0; i < direct; i++ {
			packages["node_modules/"+PackageName(i)].Dependencies[PackageName(total-1)] = "^1.0.0"
		}
	}
	files := map[string]any{
		"package.json":      map[string]any{"name": "benchmark-app", "dependencies": dependencies},
		"package-lock.json": map[string]any{"name": "benchmark-app", "lockfileVersion": 3, "packages": packages},
	}
	for name, value := range files {
		data, err := json.Marshal(value)
		if err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			tb.Fatal(err)
		}
	}
	return dir
}
