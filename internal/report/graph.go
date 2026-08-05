package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Tmwakalasya/deadcheck/internal/graph"
)

type GraphOptions struct {
	Version  string
	MaxDepth int
	Colorize bool
}

func WriteGraphJSON(w io.Writer, result graph.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func WriteGraph(stdout, stderr io.Writer, result graph.Result, opts GraphOptions) error {
	brand := renderStyle(opts.Colorize, "DEADCHECK GRAPH", reportAccent, true)
	version := renderStyle(opts.Colorize, opts.Version, reportMuted, false)
	if _, err := fmt.Fprintf(stdout, "%s  %s\n%s\n", brand, version, result.Path); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "\n%d %s  /  %d direct  /  %d transitive  /  %d %s  /  %.1fs\n\n",
		result.DependencyCount,
		pluralize("dependency", result.DependencyCount),
		result.DirectCount,
		result.TransitiveCount,
		len(result.Ecosystems),
		pluralize("ecosystem", len(result.Ecosystems)),
		float64(result.DurationMS)/1000,
	); err != nil {
		return err
	}

	nodes := make(map[string]graph.Node, len(result.Nodes))
	identities := make(map[string]int)
	for _, node := range result.Nodes {
		nodes[node.ID] = node
		if !node.Root {
			identities[string(node.Ecosystem)+"\x00"+node.Name+"\x00"+node.Version]++
		}
	}
	adjacency := graphDisplayAdjacency(result, nodes)
	for index, rootID := range result.Roots {
		root, ok := nodes[rootID]
		if !ok {
			continue
		}
		heading := strings.ToUpper(string(root.Ecosystem))
		if _, err := fmt.Fprintf(stdout, "%s  %s\n", renderStyle(opts.Colorize, heading, reportAccent, true), graphNodeLabel(root, graph.Edge{}, identities, opts.Colorize)); err != nil {
			return err
		}
		if len(adjacency[rootID]) == 0 {
			if _, err := fmt.Fprintln(stdout, "  (no dependencies)"); err != nil {
				return err
			}
		} else {
			expanded := map[string]bool{rootID: true}
			active := map[string]bool{rootID: true}
			if err := writeGraphChildren(stdout, rootID, "", 0, adjacency, nodes, identities, expanded, active, opts); err != nil {
				return err
			}
		}
		if index < len(result.Roots)-1 {
			if _, err := fmt.Fprintln(stdout); err != nil {
				return err
			}
		}
	}

	if len(result.Warnings) > 0 {
		if _, err := fmt.Fprintln(stderr, "\nGRAPH WARNINGS"); err != nil {
			return err
		}
		for _, warning := range result.Warnings {
			line := warning.Message
			if warning.Dependency != "" {
				line = warning.Dependency + ": " + line
			}
			if warning.Source != "" {
				line += fmt.Sprintf(" [%s]", warning.Source)
			}
			if _, err := fmt.Fprintf(stderr, "  - %s\n", line); err != nil {
				return err
			}
		}
	}
	return nil
}

func graphAdjacency(edges []graph.Edge, nodes map[string]graph.Node) map[string][]graph.Edge {
	adjacency := make(map[string][]graph.Edge)
	for _, edge := range edges {
		if _, ok := nodes[edge.From]; !ok {
			continue
		}
		if _, ok := nodes[edge.To]; !ok {
			continue
		}
		adjacency[edge.From] = append(adjacency[edge.From], edge)
	}
	sortGraphAdjacency(adjacency, nodes)
	return adjacency
}

func graphDisplayAdjacency(result graph.Result, nodes map[string]graph.Node) map[string][]graph.Edge {
	adjacency := graphAdjacency(result.Edges, nodes)
	removed := make(map[string][]graph.Edge)
	for _, rootID := range result.Roots {
		edges := adjacency[rootID]
		kept := make([]graph.Edge, 0, len(edges))
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
	var visit func(string)
	visit = func(id string) {
		if reachable[id] {
			return
		}
		reachable[id] = true
		for _, edge := range adjacency[id] {
			visit(edge.To)
		}
	}
	for _, rootID := range result.Roots {
		visit(rootID)
	}

	// Keep one root edge for any requirement component that is not reachable
	// through a direct dependency. JSON still retains every original edge.
	for _, rootID := range result.Roots {
		for _, edge := range removed[rootID] {
			if reachable[edge.To] {
				continue
			}
			adjacency[rootID] = append(adjacency[rootID], edge)
			visit(edge.To)
		}
	}
	sortGraphAdjacency(adjacency, nodes)
	return adjacency
}

func sortGraphAdjacency(adjacency map[string][]graph.Edge, nodes map[string]graph.Node) {
	for from := range adjacency {
		sort.Slice(adjacency[from], func(i, j int) bool {
			left := nodes[adjacency[from][i].To]
			right := nodes[adjacency[from][j].To]
			if left.Direct != right.Direct {
				return left.Direct
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
			return adjacency[from][i].Kind < adjacency[from][j].Kind
		})
	}
}

func writeGraphChildren(
	w io.Writer,
	parentID string,
	prefix string,
	parentDepth int,
	adjacency map[string][]graph.Edge,
	nodes map[string]graph.Node,
	identities map[string]int,
	expanded map[string]bool,
	active map[string]bool,
	opts GraphOptions,
) error {
	edges := adjacency[parentID]
	for index, edge := range edges {
		last := index == len(edges)-1
		branch := "|- "
		continuation := "|  "
		if last {
			branch = "`- "
			continuation = "   "
		}
		node := nodes[edge.To]
		label := graphNodeLabel(node, edge, identities, opts.Colorize)
		nextDepth := parentDepth + 1
		cycle := active[edge.To]
		shared := expanded[edge.To] && !cycle
		rootReference := !nodes[parentID].Root && node.Direct && !cycle && !shared
		switch {
		case cycle:
			label += " " + renderStyle(opts.Colorize, "[cycle]", reportWarning, false)
		case shared:
			label += " " + renderStyle(opts.Colorize, "[shared]", reportMuted, false)
		case rootReference:
			label += " " + renderStyle(opts.Colorize, "[see root]", reportMuted, false)
		}
		if _, err := fmt.Fprintf(w, "%s%s%s\n", prefix, branch, label); err != nil {
			return err
		}
		if cycle || shared || rootReference {
			continue
		}
		expanded[edge.To] = true
		if len(adjacency[edge.To]) == 0 {
			continue
		}
		if opts.MaxDepth > 0 && nextDepth >= opts.MaxDepth {
			hidden := fmt.Sprintf("`- ... %d immediate %s", len(adjacency[edge.To]), pluralize("dependency", len(adjacency[edge.To])))
			if _, err := fmt.Fprintf(w, "%s%s%s\n", prefix, continuation, renderStyle(opts.Colorize, hidden, reportMuted, false)); err != nil {
				return err
			}
			continue
		}
		active[edge.To] = true
		if err := writeGraphChildren(w, edge.To, prefix+continuation, nextDepth, adjacency, nodes, identities, expanded, active, opts); err != nil {
			return err
		}
		delete(active, edge.To)
	}
	return nil
}

func graphNodeLabel(node graph.Node, edge graph.Edge, identities map[string]int, colorize bool) string {
	label := node.Name
	if node.Version != "" {
		label += " " + renderStyle(colorize, node.Version, reportMuted, false)
	}
	tags := make([]string, 0, 4)
	if node.Direct {
		tags = append(tags, "direct")
	}
	if node.Dev {
		tags = append(tags, "dev")
	}
	if edge.Kind == "optional" || edge.Kind == "peer" {
		tags = append(tags, edge.Kind)
	}
	identity := string(node.Ecosystem) + "\x00" + node.Name + "\x00" + node.Version
	if identities[identity] > 1 && node.InstallPath != "" {
		tags = append(tags, "at "+node.InstallPath)
	}
	if len(tags) > 0 {
		label += " " + renderStyle(colorize, "["+strings.Join(tags, ", ")+"]", reportInfo, false)
	}
	return label
}
