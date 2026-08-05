package graph

import (
	"sort"
	"strings"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

type ExplainOptions struct {
	Query     string
	Version   string
	Ecosystem model.Ecosystem
	MaxPaths  int
}

type WhyPath struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type WhyMatch struct {
	Dependency Node      `json:"dependency"`
	Paths      []WhyPath `json:"paths"`
	Truncated  bool      `json:"truncated"`
}

type WhyResult struct {
	Path        string          `json:"path"`
	Query       string          `json:"query"`
	Version     string          `json:"version,omitempty"`
	Ecosystem   model.Ecosystem `json:"ecosystem,omitempty"`
	Matches     []WhyMatch      `json:"matches"`
	MatchCount  int             `json:"match_count"`
	Suggestions []string        `json:"suggestions"`
	Warnings    []model.Warning `json:"warnings"`
	Partial     bool            `json:"partial"`
	DurationMS  int64           `json:"duration_ms"`
}

// ExplanationEdges removes redundant root edges for dependencies that are
// already reachable through a direct dependency. The original Result remains
// unchanged and continues to expose the complete ecosystem-native graph.
func ExplanationEdges(result Result) []Edge {
	nodes := make(map[string]Node, len(result.Nodes))
	for _, node := range result.Nodes {
		nodes[node.ID] = node
	}

	adjacency := make(map[string][]Edge)
	for _, edge := range dedupeEdges(result.Edges) {
		if _, ok := nodes[edge.From]; !ok {
			continue
		}
		if _, ok := nodes[edge.To]; !ok {
			continue
		}
		adjacency[edge.From] = append(adjacency[edge.From], edge)
	}
	sortExplanationAdjacency(adjacency, nodes)

	removed := make(map[string][]Edge)
	for _, rootID := range result.Roots {
		edges := adjacency[rootID]
		kept := make([]Edge, 0, len(edges))
		for _, edge := range edges {
			if nodes[edge.To].Direct {
				kept = append(kept, edge)
			} else {
				removed[rootID] = append(removed[rootID], edge)
			}
		}
		adjacency[rootID] = kept
	}

	reachable := make(map[string]bool)
	visit := func(start string) {
		stack := []string{start}
		for len(stack) > 0 {
			id := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if reachable[id] {
				continue
			}
			reachable[id] = true
			for _, edge := range adjacency[id] {
				stack = append(stack, edge.To)
			}
		}
	}
	for _, rootID := range result.Roots {
		visit(rootID)
	}

	// Retain one root edge for each component that has no causal direct path.
	for _, rootID := range result.Roots {
		for _, edge := range removed[rootID] {
			if reachable[edge.To] {
				continue
			}
			adjacency[rootID] = append(adjacency[rootID], edge)
			visit(edge.To)
		}
	}

	edges := make([]Edge, 0, len(result.Edges))
	for _, outgoing := range adjacency {
		edges = append(edges, outgoing...)
	}
	return dedupeEdges(edges)
}

func Explain(result Result, opts ExplainOptions) WhyResult {
	maxPaths := opts.MaxPaths
	if maxPaths <= 0 {
		maxPaths = 10
	}
	query := strings.TrimSpace(opts.Query)
	version := strings.TrimSpace(opts.Version)
	explanation := WhyResult{
		Path:        result.Path,
		Query:       query,
		Version:     version,
		Ecosystem:   opts.Ecosystem,
		Matches:     make([]WhyMatch, 0),
		Suggestions: make([]string, 0),
		Warnings:    append(make([]model.Warning, 0, len(result.Warnings)), result.Warnings...),
		Partial:     result.Partial,
		DurationMS:  result.DurationMS,
	}

	nodes := make(map[string]Node, len(result.Nodes))
	for _, node := range result.Nodes {
		nodes[node.ID] = node
		if node.Root || !matchesDependency(node, query, version, opts.Ecosystem) {
			continue
		}
		explanation.Matches = append(explanation.Matches, WhyMatch{
			Dependency: node,
			Paths:      make([]WhyPath, 0),
		})
	}
	sort.Slice(explanation.Matches, func(i, j int) bool {
		return lessExplanationNode(explanation.Matches[i].Dependency, explanation.Matches[j].Dependency)
	})

	edges := ExplanationEdges(result)
	reverse := make(map[string][]Edge)
	for _, edge := range edges {
		reverse[edge.To] = append(reverse[edge.To], edge)
	}
	roots := make(map[string]bool, len(result.Roots))
	for _, rootID := range result.Roots {
		roots[rootID] = true
	}
	for target := range reverse {
		sort.Slice(reverse[target], func(i, j int) bool {
			leftRoot := roots[reverse[target][i].From]
			rightRoot := roots[reverse[target][j].From]
			if leftRoot != rightRoot {
				return leftRoot
			}
			left := nodes[reverse[target][i].From]
			right := nodes[reverse[target][j].From]
			return lessExplanationNode(left, right)
		})
	}

	for index := range explanation.Matches {
		paths, truncated := explainPaths(
			explanation.Matches[index].Dependency.ID,
			nodes,
			reverse,
			roots,
			maxPaths,
		)
		explanation.Matches[index].Paths = paths
		explanation.Matches[index].Truncated = truncated
	}
	explanation.MatchCount = len(explanation.Matches)
	if explanation.MatchCount == 0 {
		explanation.Suggestions = dependencySuggestions(result.Nodes, query, opts.Ecosystem)
	}
	return explanation
}

func explainPaths(target string, nodes map[string]Node, reverse map[string][]Edge, roots map[string]bool, maxPaths int) ([]WhyPath, bool) {
	paths := make([]WhyPath, 0)
	reversedNodes := []string{target}
	reversedEdges := make([]Edge, 0)
	active := map[string]bool{target: true}

	var walk func(string)
	walk = func(current string) {
		if len(paths) > maxPaths {
			return
		}
		if roots[current] {
			path := WhyPath{
				Nodes: make([]Node, len(reversedNodes)),
				Edges: make([]Edge, len(reversedEdges)),
			}
			for index, id := range reversedNodes {
				path.Nodes[len(reversedNodes)-1-index] = nodes[id]
			}
			for index, edge := range reversedEdges {
				path.Edges[len(reversedEdges)-1-index] = edge
			}
			paths = append(paths, path)
			return
		}

		for _, edge := range reverse[current] {
			if active[edge.From] {
				continue
			}
			active[edge.From] = true
			reversedNodes = append(reversedNodes, edge.From)
			reversedEdges = append(reversedEdges, edge)
			walk(edge.From)
			reversedNodes = reversedNodes[:len(reversedNodes)-1]
			reversedEdges = reversedEdges[:len(reversedEdges)-1]
			delete(active, edge.From)
			if len(paths) > maxPaths {
				return
			}
		}
	}
	walk(target)

	truncated := len(paths) > maxPaths
	if truncated {
		paths = paths[:maxPaths]
	}
	return paths, truncated
}

func matchesDependency(node Node, query, version string, ecosystem model.Ecosystem) bool {
	if !strings.EqualFold(node.Name, query) {
		return false
	}
	if version != "" && node.Version != version {
		return false
	}
	return ecosystem == "" || node.Ecosystem == ecosystem
}

func dependencySuggestions(nodes []Node, query string, ecosystem model.Ecosystem) []string {
	needle := strings.ToLower(query)
	seen := make(map[string]bool)
	suggestions := make([]string, 0, 5)
	for _, node := range nodes {
		if node.Root || (ecosystem != "" && node.Ecosystem != ecosystem) {
			continue
		}
		name := strings.ToLower(node.Name)
		if needle != "" && !strings.Contains(name, needle) && !strings.Contains(needle, name) {
			continue
		}
		key := strings.ToLower(node.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		suggestions = append(suggestions, node.Name)
	}
	sort.Slice(suggestions, func(i, j int) bool {
		if len(suggestions[i]) != len(suggestions[j]) {
			return len(suggestions[i]) < len(suggestions[j])
		}
		return suggestions[i] < suggestions[j]
	})
	if len(suggestions) > 5 {
		suggestions = suggestions[:5]
	}
	return suggestions
}

func sortExplanationAdjacency(adjacency map[string][]Edge, nodes map[string]Node) {
	for from := range adjacency {
		sort.Slice(adjacency[from], func(i, j int) bool {
			left := nodes[adjacency[from][i].To]
			right := nodes[adjacency[from][j].To]
			if left.Direct != right.Direct {
				return left.Direct
			}
			if lessExplanationNode(left, right) {
				return true
			}
			if lessExplanationNode(right, left) {
				return false
			}
			return adjacency[from][i].Kind < adjacency[from][j].Kind
		})
	}
}

func lessExplanationNode(left, right Node) bool {
	if left.Ecosystem != right.Ecosystem {
		return left.Ecosystem < right.Ecosystem
	}
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	if left.Version != right.Version {
		return left.Version < right.Version
	}
	if left.InstallPath != right.InstallPath {
		return left.InstallPath < right.InstallPath
	}
	return left.ID < right.ID
}
