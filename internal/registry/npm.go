package registry

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type npmPackument struct {
	DistTags map[string]string       `json:"dist-tags"`
	Time     map[string]string       `json:"time"`
	Versions map[string]npmVersion   `json:"versions"`
}

type npmVersion struct {
	Deprecated string `json:"deprecated"`
}

func (c *Client) npmMetadata(ctx context.Context, pkgName, resolvedVersion string) (PackageMetadata, error) {
	var packument npmPackument
	endpoint := joinURL(c.urls.NPM, escapeNPMPackage(pkgName))
	if err := c.getJSON(ctx, endpoint, &packument); err != nil {
		return PackageMetadata{}, err
	}

	latest := strings.TrimSpace(packument.DistTags["latest"])
	if latest == "" {
		for version := range packument.Versions {
			if latest == "" || compareVersions(version, latest) > 0 {
				latest = version
			}
		}
	}
	if latest == "" {
		return PackageMetadata{}, fmt.Errorf("npm registry returned no versions")
	}

	meta := PackageMetadata{LatestVersion: latest}
	if ts := packument.Time[latest]; ts != "" {
		release, err := time.Parse(time.RFC3339, ts)
		if err == nil {
			meta.LatestRelease = release
		}
	}
	if resolvedVersion != "" {
		if version, ok := packument.Versions[resolvedVersion]; ok {
			meta.DeprecationMessage = strings.TrimSpace(version.Deprecated)
		}
	}
	return meta, nil
}

func escapeNPMPackage(name string) string {
	escaped := url.PathEscape(name)
	return strings.Replace(escaped, "%40", "@", 1)
}
