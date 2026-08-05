package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Tmwakalasya/deadcheck/internal/graph"
	"github.com/Tmwakalasya/deadcheck/internal/model"
)

func TestWriteWhyPlainText(t *testing.T) {
	t.Parallel()

	root := graph.Node{ID: "npm:root:app", Name: "app", Ecosystem: model.EcosystemNPM, Root: true}
	alpha := graph.Node{ID: "npm:path:alpha", Name: "alpha", Version: "1.0.0", Ecosystem: model.EcosystemNPM, Direct: true}
	shared := graph.Node{
		ID:          "npm:path:shared",
		Name:        "shared",
		Version:     "2.0.0",
		Ecosystem:   model.EcosystemNPM,
		InstallPath: "node_modules/shared",
	}
	result := graph.WhyResult{
		Path:       "/tmp/app",
		Query:      "shared",
		MatchCount: 1,
		Matches: []graph.WhyMatch{{
			Dependency: shared,
			Paths: []graph.WhyPath{{
				Nodes: []graph.Node{root, alpha, shared},
				Edges: []graph.Edge{
					{From: root.ID, To: alpha.ID, Kind: "require"},
					{From: alpha.ID, To: shared.ID, Kind: "require"},
				},
			}},
		}},
		Warnings: []model.Warning{{
			Kind:    "partial",
			Message: "fixture warning",
			Source:  "/tmp/app/package-lock.json",
		}},
	}

	var stdout, stderr bytes.Buffer
	if err := WriteWhy(&stdout, &stderr, result, WhyOptions{Version: "v0.2.0-dev"}); err != nil {
		t.Fatalf("WriteWhy returned error: %v", err)
	}
	for _, want := range []string{
		"DEADCHECK WHY  v0.2.0-dev",
		"QUERY  shared",
		"1 match  /  1 path",
		"NPM  shared 2.0.0",
		"Install: node_modules/shared",
		"PATH 1",
		"-> alpha 1.0.0 [direct]",
		"-> shared 2.0.0",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("expected stdout to contain %q\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "\x1b[") {
		t.Fatalf("plain output must not contain ANSI escapes: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "WHY WARNINGS") || !strings.Contains(stderr.String(), "fixture warning") {
		t.Fatalf("expected warning output, got %q", stderr.String())
	}
}

func TestWriteWhyNoMatchAndJSON(t *testing.T) {
	t.Parallel()

	result := graph.WhyResult{
		Path:        "/tmp/app",
		Query:       "share",
		Matches:     []graph.WhyMatch{},
		Suggestions: []string{"shared"},
		Warnings:    []model.Warning{},
	}
	var stdout, stderr bytes.Buffer
	if err := WriteWhy(&stdout, &stderr, result, WhyOptions{}); err != nil {
		t.Fatalf("WriteWhy returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "No dependency named \"share\" was found.") || !strings.Contains(stdout.String(), "Did you mean: shared") {
		t.Fatalf("unexpected no-match output: %s", stdout.String())
	}

	stdout.Reset()
	if err := WriteWhyJSON(&stdout, result); err != nil {
		t.Fatalf("WriteWhyJSON returned error: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("invalid why JSON: %v", err)
	}
	for _, field := range []string{"matches", "suggestions", "warnings"} {
		if _, ok := payload[field].([]any); !ok {
			t.Fatalf("expected %s to be a JSON array, got %#v", field, payload[field])
		}
	}
}
