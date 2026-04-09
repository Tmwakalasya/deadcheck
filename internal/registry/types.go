package registry

import (
	"os"
	"strings"
	"time"

	"github.com/tuntufye/deadcheck/internal/model"
)

type URLs struct {
	GoProxy string
	NPM     string
	PyPI    string
	OSV     string
}

func URLsFromEnv() URLs {
	return URLs{
		GoProxy: envOrDefault("DEADCHECK_GO_PROXY_URL", "https://proxy.golang.org"),
		NPM:     envOrDefault("DEADCHECK_NPM_REGISTRY_URL", "https://registry.npmjs.org"),
		PyPI:    envOrDefault("DEADCHECK_PYPI_URL", "https://pypi.org"),
		OSV:     envOrDefault("DEADCHECK_OSV_URL", "https://api.osv.dev"),
	}
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return strings.TrimRight(value, "/")
}

type PackageMetadata struct {
	LatestVersion      string
	LatestRelease      time.Time
	DeprecationMessage string
	Inactive           bool
}

type Vulnerability struct {
	ID           string
	Aliases      []string
	Summary      string
	Details      string
	Severity     model.Severity
	CVSS         *float64
	FixedVersion string
	References   []string
}
