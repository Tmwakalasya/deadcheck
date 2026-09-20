package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Tmwakalasya/deadcheck/internal/model"
	"github.com/Tmwakalasya/deadcheck/internal/registry"
)

type scanTransport func(*http.Request) (*http.Response, error)

func (f scanTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fixtureScanner(handler func(*http.Request) (int, string), productionOnly bool) *Scanner {
	client := &http.Client{Transport: scanTransport(func(r *http.Request) (*http.Response, error) {
		if err := r.Context().Err(); err != nil {
			return nil, err
		}
		status, body := handler(r)
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	return New(client, registry.URLs{NPM: "https://fixture.test", OSV: "https://fixture.test", GoProxy: "https://fixture.test"}, Options{Workers: 2, ProductionOnly: productionOnly})
}

func scanProject(t *testing.T, manifest string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func healthyMetadata(version string) string {
	return fmt.Sprintf(`{"dist-tags":{"latest":%q},"time":{%q:%q},"versions":{%q:{}}}`, version, version, time.Now().UTC().Format(time.RFC3339), version)
}

func TestScanUsesLockedVersionForVulnerabilityAndDeprecation(t *testing.T) {
	t.Parallel()
	dir := scanProject(t, `{"dependencies":{"alpha":"^1.0.0"}}`)
	lockPath := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(lockPath, []byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/alpha":{"version":"1.2.3","dependencies":{"child":"1.0.0"}},"node_modules/child":{"version":"1.0.0"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int32
	s := fixtureScanner(func(r *http.Request) (int, string) {
		if r.URL.Path == "/v1/query" {
			var query struct {
				Version string `json:"version"`
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
			}
			if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
				t.Error(err)
			}
			if query.Version != "1.2.3" || query.Package.Name != "alpha" {
				t.Errorf("unexpected OSV query: %#v", query)
			}
			queries.Add(1)
			return 200, `{"vulns":[]}`
		}
		if r.URL.Path != "/alpha" {
			t.Errorf("unexpected metadata request: %s", r.URL.Path)
		}
		return 200, healthyMetadata("1.2.3")
	}, false)
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Partial || result.Score == nil || *result.Score != 100 || result.CheckedDependencyCount != 1 || result.DependencyCount != 1 {
		t.Fatalf("expected complete direct-only scan, got %#v", result)
	}
	dep := result.Dependencies[0]
	if !dep.Complete || dep.Dependency.VersionSource != lockPath || queries.Load() != 1 {
		t.Fatalf("unexpected resolved dependency: %#v, queries=%d", dep, queries.Load())
	}
	for _, check := range dep.Checks {
		if check.Status != model.CheckComplete {
			t.Errorf("unexpected check: %#v", check)
		}
	}
}

func TestScanFailureCoverage(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"registry", "osv", "release_date", "deprecation_version"} {
		t.Run(failure, func(t *testing.T) {
			dir := scanProject(t, `{"dependencies":{"good":"1.0.0","broken":"1.0.0"}}`)
			s := fixtureScanner(func(r *http.Request) (int, string) {
				if r.URL.Path == "/v1/query" {
					var q struct {
						Package struct {
							Name string `json:"name"`
						} `json:"package"`
					}
					if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
						t.Error(err)
					}
					if q.Package.Name == "broken" && failure == "osv" {
						return 503, "unavailable"
					}
					if q.Package.Name == "broken" && failure == "registry" {
						return 200, `{"vulns":[{"id":"TEST-ADVISORY","summary":"fixture finding","database_specific":{"severity":"HIGH"}}]}`
					}
					return 200, `{"vulns":[]}`
				}
				if r.URL.Path == "/broken" {
					switch failure {
					case "registry":
						return 503, "unavailable"
					case "release_date":
						return 200, `{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}`
					case "deprecation_version":
						return 200, healthyMetadata("2.0.0")
					}
				}
				return 200, healthyMetadata("1.0.0")
			}, false)
			result, err := s.Scan(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Partial || result.Score != nil || result.Grade != model.GradeIncomplete || result.CheckedDependencyCount != 1 {
				t.Fatalf("failed checks must not produce a healthy score: %#v", result)
			}
			for _, dep := range result.Dependencies {
				if dep.Complete != (dep.Dependency.Name == "good") {
					t.Errorf("incorrect completeness: %#v", dep)
				}
				if dep.Dependency.Name == "broken" {
					if failure == "registry" && (len(dep.Findings) != 1 || dep.MaxSeverity != model.SeverityCritical) {
						t.Errorf("incomplete scan lost confirmed findings: %#v", dep)
					}
					wantName, wantStatus := "staleness", model.CheckFailed
					switch failure {
					case "osv":
						wantName = "vulnerability"
					case "release_date":
						wantStatus = model.CheckSkipped
					case "deprecation_version":
						wantName = "deprecation"
					}
					for _, check := range dep.Checks {
						if check.Name == wantName && check.Status != wantStatus {
							t.Errorf("incorrect check status: %#v", check)
						}
					}
				}
			}
		})
	}
}

func TestScanExpiredContextHasNoScore(t *testing.T) {
	t.Parallel()
	dir := scanProject(t, `{"dependencies":{"alpha":"1.0.0"}}`)
	s := fixtureScanner(func(*http.Request) (int, string) { t.Error("expired scan reached a registry"); return 200, `{}` }, false)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	result, err := s.Scan(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Partial || result.Score != nil || result.CheckedDependencyCount != 0 {
		t.Fatalf("unexpected expired result: %#v", result)
	}
	for _, check := range result.Dependencies[0].Checks {
		if check.Status != model.CheckFailed {
			t.Errorf("expected failed check, got %#v", check)
		}
	}
}

func TestScanUnresolvedRangeSkipsVersionChecks(t *testing.T) {
	t.Parallel()
	dir := scanProject(t, `{"dependencies":{"alpha":"^1.0.0"}}`)
	s := fixtureScanner(func(r *http.Request) (int, string) {
		if r.URL.Path == "/v1/query" {
			t.Error("must not query OSV with a range lower bound")
		}
		return 200, healthyMetadata("1.2.3")
	}, false)
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Partial || result.Score != nil || result.CheckedDependencyCount != 0 {
		t.Fatalf("unexpected unresolved result: %#v", result)
	}
	for _, check := range result.Dependencies[0].Checks {
		want := model.CheckSkipped
		if check.Name == "staleness" {
			want = model.CheckComplete
		}
		if check.Status != want {
			t.Errorf("unexpected coverage: %#v", check)
		}
	}
}

func TestProductionScanIgnoresUnresolvedDevDependencies(t *testing.T) {
	t.Parallel()
	dir := scanProject(t, `{"dependencies":{"alpha":"1.0.0"},"devDependencies":{"dev-only":"*"}}`)
	s := fixtureScanner(func(r *http.Request) (int, string) {
		if r.URL.Path == "/v1/query" {
			return 200, `{"vulns":[]}`
		}
		if r.URL.Path != "/alpha" {
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
		return 200, healthyMetadata("1.0.0")
	}, true)
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Partial || result.Score == nil || *result.Score != 100 || result.CheckedDependencyCount != 1 || result.DependencyCount != 1 {
		t.Fatalf("unexpected production scan: %#v", result)
	}
}

func TestGoDeprecationFailureRemainsVisible(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/app\n\ngo 1.22\n\nrequire example.com/lib v1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := fixtureScanner(func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/example.com/lib/@latest":
			return 200, fmt.Sprintf(`{"Version":"v1.0.0","Time":%q}`, time.Now().UTC().Format(time.RFC3339))
		case "/example.com/lib/@v/v1.0.0.mod":
			return 503, "unavailable"
		case "/v1/query":
			return 200, `{"vulns":[]}`
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			return 404, "not found"
		}
	}, false)
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Partial || result.Score != nil || result.CheckedDependencyCount != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
	for _, check := range result.Dependencies[0].Checks {
		want := model.CheckComplete
		if check.Name == "deprecation" {
			want = model.CheckFailed
		}
		if check.Status != want {
			t.Errorf("unexpected check: %#v", check)
		}
	}
}
