package registry

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type pypiResponse struct {
	Info struct {
		Version     string   `json:"version"`
		Classifiers []string `json:"classifiers"`
	} `json:"info"`
	Releases map[string][]pypiFile `json:"releases"`
}

type pypiFile struct {
	UploadTimeISO8601 string `json:"upload_time_iso_8601"`
}

func (c *Client) pypiMetadata(ctx context.Context, pkgName string) (PackageMetadata, error) {
	var payload pypiResponse
	endpoint := joinURL(c.urls.PyPI, "pypi", url.PathEscape(pkgName), "json")
	if err := c.getJSON(ctx, endpoint, &payload); err != nil {
		return PackageMetadata{}, err
	}

	meta := PackageMetadata{LatestVersion: payload.Info.Version}
	if files := payload.Releases[payload.Info.Version]; len(files) > 0 {
		meta.LatestRelease = latestUpload(files)
	}
	if meta.LatestRelease.IsZero() {
		for _, files := range payload.Releases {
			if candidate := latestUpload(files); candidate.After(meta.LatestRelease) {
				meta.LatestRelease = candidate
			}
		}
	}
	for _, classifier := range payload.Info.Classifiers {
		if strings.EqualFold(classifier, "Development Status :: 7 - Inactive") {
			meta.Inactive = true
			meta.DeprecationMessage = "package is marked inactive on PyPI"
			break
		}
	}
	if meta.LatestVersion == "" && meta.LatestRelease.IsZero() {
		return PackageMetadata{}, fmt.Errorf("PyPI returned no release metadata")
	}
	return meta, nil
}

func latestUpload(files []pypiFile) time.Time {
	var latest time.Time
	for _, file := range files {
		if file.UploadTimeISO8601 == "" {
			continue
		}
		ts, err := time.Parse(time.RFC3339, file.UploadTimeISO8601)
		if err != nil {
			continue
		}
		if ts.After(latest) {
			latest = ts
		}
	}
	return latest
}
