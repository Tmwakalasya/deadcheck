package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

type osvQueryRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvQueryResponse struct {
	Vulns []osvVulnerability `json:"vulns"`
}

type osvVulnerability struct {
	ID                 string              `json:"id"`
	Aliases            []string            `json:"aliases"`
	Summary            string              `json:"summary"`
	Details            string              `json:"details"`
	Severity           []osvSeverity       `json:"severity"`
	References         []osvReference      `json:"references"`
	Affected           []osvAffected       `json:"affected"`
	DatabaseSpecific   map[string]any      `json:"database_specific"`
	EcosystemSpecific  map[string]any      `json:"ecosystem_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	URL string `json:"url"`
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Events []map[string]string `json:"events"`
}

func (c *Client) osvVulnerabilities(ctx context.Context, dep model.Dependency) ([]Vulnerability, error) {
	if dep.ResolvedVersion == "" {
		return nil, nil
	}
	reqBody := osvQueryRequest{Version: dep.ResolvedVersion}
	reqBody.Package.Name = dep.Name
	reqBody.Package.Ecosystem = osvEcosystem(dep.Ecosystem)

	var payload bytes.Buffer
	if err := json.NewEncoder(&payload).Encode(reqBody); err != nil {
		return nil, err
	}

	var response osvQueryResponse
	if err := c.postJSON(ctx, joinURL(c.urls.OSV, "v1", "query"), &payload, &response); err != nil {
		return nil, err
	}

	out := make([]Vulnerability, 0, len(response.Vulns))
	for _, vuln := range response.Vulns {
		item := Vulnerability{
			ID:           vuln.ID,
			Aliases:      vuln.Aliases,
			Summary:      strings.TrimSpace(vuln.Summary),
			Details:      strings.TrimSpace(vuln.Details),
			FixedVersion: extractFixedVersion(vuln.Affected),
			References:   collectReferences(vuln.References),
		}
		item.CVSS = parseOSVCVSS(vuln.Severity)
		item.Severity = severityFromOSV(item.CVSS, vuln)
		out = append(out, item)
	}
	return out, nil
}

func severityFromOSV(cvss *float64, vuln osvVulnerability) model.Severity {
	if cvss != nil {
		switch {
		case *cvss >= 7:
			return model.SeverityCritical
		case *cvss >= 4:
			return model.SeverityWarning
		default:
			return model.SeverityInfo
		}
	}

	for _, bucket := range []map[string]any{vuln.DatabaseSpecific, vuln.EcosystemSpecific} {
		for _, key := range []string{"severity", "cvss_v3_severity"} {
			value, ok := bucket[key].(string)
			if !ok {
				continue
			}
			switch strings.ToLower(value) {
			case "critical", "high":
				return model.SeverityCritical
			case "moderate", "medium":
				return model.SeverityWarning
			case "low":
				return model.SeverityInfo
			}
		}
	}

	return model.SeverityWarning
}

func osvEcosystem(ecosystem model.Ecosystem) string {
	switch ecosystem {
	case model.EcosystemGo:
		return "Go"
	case model.EcosystemNPM:
		return "npm"
	case model.EcosystemPyPI:
		return "PyPI"
	default:
		return ""
	}
}

func collectReferences(refs []osvReference) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.URL != "" {
			out = append(out, ref.URL)
		}
	}
	return out
}

func extractFixedVersion(affected []osvAffected) string {
	best := ""
	for _, item := range affected {
		for _, rng := range item.Ranges {
			for _, event := range rng.Events {
				if fixed := strings.TrimSpace(event["fixed"]); fixed != "" {
					if best == "" || compareVersions(fixed, best) < 0 {
						best = fixed
					}
				}
			}
		}
	}
	return best
}

func PreferredAdvisoryID(v Vulnerability) string {
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	if v.ID != "" {
		return v.ID
	}
	if len(v.Aliases) > 0 {
		return v.Aliases[0]
	}
	return "OSV-UNKNOWN"
}

func AdvisoryDetail(v Vulnerability) string {
	if v.Summary != "" {
		return v.Summary
	}
	if v.Details != "" {
		return v.Details
	}
	return "known vulnerability"
}

func AdvisorySuggestion(v Vulnerability) string {
	if v.FixedVersion != "" {
		return fmt.Sprintf("upgrade to %s", v.FixedVersion)
	}
	return "upgrade or replace this dependency"
}
