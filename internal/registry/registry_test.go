package registry

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

func TestGoMetadataFallbackAndDeprecation(t *testing.T) {
	t.Parallel()

	client := fixtureHTTPClient(func(r *http.Request) (int, string) {
		switch r.URL.Path {
		case "/example.com/mod/@latest":
			return http.StatusNotFound, "not found"
		case "/example.com/mod/@v/list":
			return http.StatusOK, "v1.0.0\nv1.2.0"
		case "/example.com/mod/@v/v1.2.0.info":
			return http.StatusOK, `{"Version":"v1.2.0","Time":"2024-01-02T15:04:05Z"}`
		case "/example.com/mod/@v/v1.2.0.mod":
			return http.StatusOK, "module example.com/mod\n// Deprecated: use example.com/newmod\n"
		default:
			return http.StatusNotFound, "not found"
		}
	})

	registryClient := NewClient(client, URLs{
		GoProxy: "https://fixture.test",
		NPM:     "https://fixture.test",
		PyPI:    "https://fixture.test",
		OSV:     "https://fixture.test",
	})
	meta, err := registryClient.PackageMetadata(context.Background(), model.Dependency{
		Name:      "example.com/mod",
		Ecosystem: model.EcosystemGo,
	})
	if err != nil {
		t.Fatalf("PackageMetadata returned error: %v", err)
	}
	if meta.LatestVersion != "v1.2.0" {
		t.Fatalf("expected latest version v1.2.0, got %q", meta.LatestVersion)
	}
	if meta.DeprecationMessage != "use example.com/newmod" {
		t.Fatalf("unexpected deprecation message: %q", meta.DeprecationMessage)
	}
}

func TestNPMMetadataIncludesVersionDeprecation(t *testing.T) {
	t.Parallel()

	client := fixtureHTTPClient(func(r *http.Request) (int, string) {
		if r.URL.Path != "/lodash" {
			return http.StatusNotFound, "not found"
		}
		return http.StatusOK, `{
			"dist-tags":{"latest":"4.17.21"},
			"time":{"4.17.21":"2024-03-01T00:00:00Z"},
			"versions":{
				"4.17.19":{"deprecated":"use 4.17.21"},
				"4.17.21":{}
			}
		}`
	})

	registryClient := NewClient(client, URLs{
		GoProxy: "https://fixture.test",
		NPM:     "https://fixture.test",
		PyPI:    "https://fixture.test",
		OSV:     "https://fixture.test",
	})
	meta, err := registryClient.PackageMetadata(context.Background(), model.Dependency{
		Name:            "lodash",
		Ecosystem:       model.EcosystemNPM,
		ResolvedVersion: "4.17.19",
	})
	if err != nil {
		t.Fatalf("PackageMetadata returned error: %v", err)
	}
	if meta.LatestVersion != "4.17.21" {
		t.Fatalf("expected latest version 4.17.21, got %q", meta.LatestVersion)
	}
	if meta.DeprecationMessage != "use 4.17.21" {
		t.Fatalf("unexpected deprecation message: %q", meta.DeprecationMessage)
	}
}

func TestPyPIMetadataMarksInactivePackages(t *testing.T) {
	t.Parallel()

	client := fixtureHTTPClient(func(r *http.Request) (int, string) {
		if r.URL.Path != "/pypi/legacy/json" {
			return http.StatusNotFound, "not found"
		}
		return http.StatusOK, `{
			"info":{"version":"1.0.0","classifiers":["Development Status :: 7 - Inactive"]},
			"releases":{"1.0.0":[{"upload_time_iso_8601":"2023-01-02T03:04:05Z"}]}
		}`
	})

	registryClient := NewClient(client, URLs{
		GoProxy: "https://fixture.test",
		NPM:     "https://fixture.test",
		PyPI:    "https://fixture.test",
		OSV:     "https://fixture.test",
	})
	meta, err := registryClient.PackageMetadata(context.Background(), model.Dependency{
		Name:      "legacy",
		Ecosystem: model.EcosystemPyPI,
	})
	if err != nil {
		t.Fatalf("PackageMetadata returned error: %v", err)
	}
	if !meta.Inactive {
		t.Fatalf("expected inactive package")
	}
	if meta.LatestRelease.IsZero() {
		t.Fatalf("expected latest release timestamp")
	}
}

func TestOSVVulnerabilitiesParsesCVSSAndFixedVersion(t *testing.T) {
	t.Parallel()

	client := fixtureHTTPClient(func(r *http.Request) (int, string) {
		if r.URL.Path != "/v1/query" {
			return http.StatusNotFound, "not found"
		}
		return http.StatusOK, `{
			"vulns":[{
				"id":"GHSA-1234",
				"aliases":["CVE-2024-0001"],
				"summary":"critical bug",
				"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
				"references":[{"url":"https://example.com/advisory"}],
				"affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]
			}]
		}`
	})

	registryClient := NewClient(client, URLs{
		GoProxy: "https://fixture.test",
		NPM:     "https://fixture.test",
		PyPI:    "https://fixture.test",
		OSV:     "https://fixture.test",
	})
	vulns, err := registryClient.Vulnerabilities(context.Background(), model.Dependency{
		Name:            "lodash",
		Ecosystem:       model.EcosystemNPM,
		ResolvedVersion: "4.17.19",
	})
	if err != nil {
		t.Fatalf("Vulnerabilities returned error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].CVSS == nil || *vulns[0].CVSS < 9.0 {
		t.Fatalf("expected parsed CVSS score, got %#v", vulns[0].CVSS)
	}
	if vulns[0].FixedVersion != "4.17.21" {
		t.Fatalf("expected fixed version 4.17.21, got %q", vulns[0].FixedVersion)
	}
	if vulns[0].Severity != model.SeverityCritical {
		t.Fatalf("expected critical severity, got %q", vulns[0].Severity)
	}
}

func TestParseCVSSv3Vector(t *testing.T) {
	t.Parallel()

	score, ok := parseCVSSv3Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if !ok {
		t.Fatal("expected vector to parse")
	}
	if got, want := score, 9.8; got != want {
		t.Fatalf("expected %.1f, got %.1f", want, got)
	}
}

func TestLatestUploadReturnsMostRecentTimestamp(t *testing.T) {
	t.Parallel()

	got := latestUpload([]pypiFile{
		{UploadTimeISO8601: "2020-01-01T00:00:00Z"},
		{UploadTimeISO8601: "2024-06-01T12:00:00Z"},
	})
	want := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func fixtureHTTPClient(handler func(*http.Request) (int, string)) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			status, body := handler(r)
			return &http.Response{
				StatusCode: status,
				Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    r,
			}, nil
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}
