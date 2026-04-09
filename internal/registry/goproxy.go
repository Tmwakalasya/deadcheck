package registry

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

type goInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

func (c *Client) goMetadata(ctx context.Context, module string) (PackageMetadata, error) {
	escaped := escapeModulePath(module)
	info, err := c.fetchGoInfo(ctx, joinURL(c.urls.GoProxy, escaped, "@latest"))
	if err != nil {
		info, err = c.goLatestFallback(ctx, escaped)
		if err != nil {
			return PackageMetadata{}, err
		}
	}

	meta := PackageMetadata{
		LatestVersion: info.Version,
		LatestRelease: info.Time,
	}
	if message, err := c.fetchGoDeprecation(ctx, escaped, info.Version); err == nil {
		meta.DeprecationMessage = message
	}
	return meta, nil
}

func (c *Client) fetchGoInfo(ctx context.Context, endpoint string) (goInfo, error) {
	var info goInfo
	err := c.getJSON(ctx, endpoint, &info)
	return info, err
}

func (c *Client) goLatestFallback(ctx context.Context, escaped string) (goInfo, error) {
	listBody, err := c.getText(ctx, joinURL(c.urls.GoProxy, escaped, "@v", "list"))
	if err != nil {
		return goInfo{}, err
	}

	var best string
	for _, line := range strings.Split(listBody, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if best == "" || compareVersions(line, best) > 0 {
			best = line
		}
	}
	if best == "" {
		return goInfo{}, fmt.Errorf("module proxy returned no versions")
	}
	return c.fetchGoInfo(ctx, joinURL(c.urls.GoProxy, escaped, "@v", escapedURLPart(best)+".info"))
}

func (c *Client) fetchGoDeprecation(ctx context.Context, escapedModule, version string) (string, error) {
	if version == "" {
		return "", nil
	}
	body, err := c.getText(ctx, joinURL(c.urls.GoProxy, escapedModule, "@v", escapedURLPart(version)+".mod"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(body, "\n") {
		if idx := strings.Index(line, "Deprecated:"); idx >= 0 {
			return strings.TrimSpace(line[idx+len("Deprecated:"):]), nil
		}
	}
	return "", nil
}

func escapeModulePath(module string) string {
	var b strings.Builder
	for _, r := range module {
		if r >= 'A' && r <= 'Z' {
			b.WriteRune('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func compareVersions(a, b string) int {
	av := canonicalVersion(a)
	bv := canonicalVersion(b)
	if av == "" || bv == "" {
		switch {
		case a > b:
			return 1
		case a < b:
			return -1
		default:
			return 0
		}
	}
	return semver.Compare(av, bv)
}

func canonicalVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return semver.Canonical(v)
}
