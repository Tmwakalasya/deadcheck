package graph

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

var ErrNoSupportedManifest = errors.New("no supported manifest found for dependency graph")

type Options struct {
	ProductionOnly bool
}

type Node struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Version     string          `json:"version,omitempty"`
	Ecosystem   model.Ecosystem `json:"ecosystem"`
	Source      string          `json:"source"`
	InstallPath string          `json:"install_path,omitempty"`
	Depth       int             `json:"depth"`
	Root        bool            `json:"root"`
	Direct      bool            `json:"direct"`
	Dev         bool            `json:"dev"`
}

type Edge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Kind       string `json:"kind"`
	Constraint string `json:"constraint,omitempty"`
}

type Result struct {
	Path            string            `json:"path"`
	Roots           []string          `json:"roots"`
	Nodes           []Node            `json:"nodes"`
	Edges           []Edge            `json:"edges"`
	Warnings        []model.Warning   `json:"warnings"`
	Ecosystems      []model.Ecosystem `json:"ecosystems"`
	DependencyCount int               `json:"dependency_count"`
	DirectCount     int               `json:"direct_count"`
	TransitiveCount int               `json:"transitive_count"`
	Partial         bool              `json:"partial"`
	DurationMS      int64             `json:"duration_ms"`
	StartedAt       time.Time         `json:"started_at"`
	CompletedAt     time.Time         `json:"completed_at"`
}

type subgraph struct {
	root     string
	nodes    map[string]Node
	edges    []Edge
	warnings []model.Warning
}

func rootID(ecosystem model.Ecosystem, name string) string {
	return fmt.Sprintf("%s:root:%s", ecosystem, name)
}

func dependencyID(ecosystem model.Ecosystem, name, version, location string) string {
	if location != "" {
		return fmt.Sprintf("%s:path:%s", ecosystem, location)
	}
	return fmt.Sprintf("%s:%s@%s", ecosystem, name, version)
}

func finalizeSubgraph(g subgraph, include func(Node) bool) subgraph {
	if include == nil {
		include = func(Node) bool { return true }
	}

	adjacency := make(map[string][]Edge)
	for _, edge := range dedupeEdges(g.edges) {
		adjacency[edge.From] = append(adjacency[edge.From], edge)
	}

	depths := map[string]int{g.root: 0}
	queue := []string{g.root}
	keptEdges := make([]Edge, 0, len(g.edges))
	for len(queue) > 0 {
		from := queue[0]
		queue = queue[1:]
		for _, edge := range adjacency[from] {
			node, ok := g.nodes[edge.To]
			if !ok || (!node.Root && !include(node)) {
				continue
			}
			keptEdges = append(keptEdges, edge)
			candidateDepth := depths[from] + 1
			currentDepth, seen := depths[edge.To]
			if !seen || candidateDepth < currentDepth {
				depths[edge.To] = candidateDepth
				queue = append(queue, edge.To)
			}
		}
	}

	keptNodes := make(map[string]Node, len(depths))
	for id, depth := range depths {
		node, ok := g.nodes[id]
		if !ok {
			continue
		}
		node.Depth = depth
		keptNodes[id] = node
	}

	g.nodes = keptNodes
	g.edges = dedupeEdges(keptEdges)
	return g
}

func dedupeEdges(edges []Edge) []Edge {
	seen := make(map[string]struct{}, len(edges))
	out := make([]Edge, 0, len(edges))
	for _, edge := range edges {
		key := edge.From + "\x00" + edge.To + "\x00" + edge.Kind
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, edge)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].To != out[j].To {
			return out[i].To < out[j].To
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}
