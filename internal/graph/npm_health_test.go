package graph

import (
	"path/filepath"
	"testing"
)

func TestNPMHealthResolution(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, constraint, lock, shrinkwrap, version, source string
	}{
		{name: "v1", constraint: "^1.0.0", lock: `{"lockfileVersion":1,"dependencies":{"alpha":{"version":"1.2.3"}}}`, version: "1.2.3", source: "package-lock.json"},
		{name: "v2", constraint: "~1.0.0", lock: `{"lockfileVersion":2,"packages":{"":{},"node_modules/alpha":{"version":"1.0.8"}}}`, version: "1.0.8", source: "package-lock.json"},
		{name: "v3", constraint: "*", lock: `{"lockfileVersion":3,"packages":{"":{},"node_modules/alpha":{"version":"2.0.0"}}}`, version: "2.0.0", source: "package-lock.json"},
		{name: "shrinkwrap precedence", constraint: "^1.0.0", lock: `{"lockfileVersion":1,"dependencies":{"alpha":{"version":"1.2.3"}}}`, shrinkwrap: `{"lockfileVersion":1,"dependencies":{"alpha":{"version":"1.4.0"}}}`, version: "1.4.0", source: "npm-shrinkwrap.json"},
		{name: "exact without lock", constraint: "1.2.3", version: "1.2.3", source: "package.json"},
		{name: "prerelease without lock", constraint: "1.2.3-beta.1+build.2", version: "1.2.3-beta.1+build.2", source: "package.json"},
		{name: "range without lock", constraint: "^1.2.3"},
		{name: "wildcard without lock", constraint: "1.2.x"},
		{name: "invalid lock", constraint: "1.2.3", lock: `{broken`},
		{name: "invalid shrinkwrap takes precedence", constraint: "1.2.3", shrinkwrap: `{broken`, lock: `{"lockfileVersion":1,"dependencies":{"alpha":{"version":"1.2.3"}}}`},
		{name: "missing direct entry", constraint: "1.2.3", lock: `{"lockfileVersion":3,"packages":{"":{},"node_modules/other":{"version":"1.2.3"}}}`},
		{name: "invalid locked version", constraint: "^1.0.0", lock: `{"lockfileVersion":3,"packages":{"":{},"node_modules/alpha":{"version":"^1.2.3"}}}`},
		{name: "linked dependency", constraint: "^1.0.0", lock: `{"lockfileVersion":3,"packages":{"":{},"node_modules/alpha":{"link":true,"version":"1.2.3"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			manifest := filepath.Join(dir, "package.json")
			writeTestFile(t, manifest, `{"dependencies":{"alpha":"`+tc.constraint+`"}}`)
			if tc.lock != "" {
				writeTestFile(t, filepath.Join(dir, "package-lock.json"), tc.lock)
			}
			if tc.shrinkwrap != "" {
				writeTestFile(t, filepath.Join(dir, "npm-shrinkwrap.json"), tc.shrinkwrap)
			}
			result, err := ResolveNPMDirect(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Dependencies) != 1 {
				t.Fatalf("unexpected result: %#v", result)
			}
			dep := result.Dependencies[0]
			if dep.ResolvedVersion != tc.version {
				t.Errorf("got version %q, want %q", dep.ResolvedVersion, tc.version)
			}
			if tc.source != "" && dep.VersionSource != filepath.Join(dir, tc.source) {
				t.Errorf("unexpected version source: %s", dep.VersionSource)
			}
			if (len(result.Warnings) > 0) != (tc.version == "") {
				t.Errorf("unexpected warnings: %#v", result.Warnings)
			}
		})
	}
}

func TestNPMHealthNeverScansLocalSourceAsRegistryPackage(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	writeTestFile(t, manifest, `{"dependencies":{"alpha":"file:../alpha"}}`)
	writeTestFile(t, filepath.Join(dir, "package-lock.json"), `{"lockfileVersion":3,"packages":{"":{},"node_modules/alpha":{"version":"1.2.3"}}}`)
	result, err := ResolveNPMDirect(manifest)
	if err != nil {
		t.Fatal(err)
	}
	dep := result.Dependencies[0]
	if dep.SkipReason == "" || dep.ResolvedVersion != "" || len(result.Warnings) == 0 {
		t.Fatalf("local source was not skipped: %#v", result)
	}
}
