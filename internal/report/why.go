package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Tmwakalasya/deadcheck/internal/graph"
)

type WhyOptions struct {
	Version  string
	Colorize bool
}

func WriteWhyJSON(w io.Writer, result graph.WhyResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func WriteWhy(stdout, stderr io.Writer, result graph.WhyResult, opts WhyOptions) error {
	brand := renderStyle(opts.Colorize, "DEADCHECK WHY", reportAccent, true)
	version := renderStyle(opts.Colorize, opts.Version, reportMuted, false)
	if _, err := fmt.Fprintf(stdout, "%s  %s\n%s\n", brand, version, result.Path); err != nil {
		return err
	}

	query := result.Query
	if result.Version != "" {
		query += " " + result.Version
	}
	if result.Ecosystem != "" {
		query += " [" + string(result.Ecosystem) + "]"
	}
	if _, err := fmt.Fprintf(stdout, "\nQUERY  %s\n", renderStyle(opts.Colorize, query, reportInfo, true)); err != nil {
		return err
	}

	if result.MatchCount == 0 {
		if _, err := fmt.Fprintf(stdout, "\nNo dependency named %q was found.\n", result.Query); err != nil {
			return err
		}
		if len(result.Suggestions) > 0 {
			if _, err := fmt.Fprintf(stdout, "Did you mean: %s\n", strings.Join(result.Suggestions, ", ")); err != nil {
				return err
			}
		}
		return writeWhyWarnings(stderr, result)
	}

	totalPaths := 0
	for _, match := range result.Matches {
		totalPaths += len(match.Paths)
	}
	if _, err := fmt.Fprintf(stdout, "%d %s  /  %d %s  /  %.1fs\n\n",
		result.MatchCount,
		pluralize("match", result.MatchCount),
		totalPaths,
		pluralize("path", totalPaths),
		float64(result.DurationMS)/1000,
	); err != nil {
		return err
	}

	for matchIndex, match := range result.Matches {
		dependency := match.Dependency
		heading := strings.ToUpper(string(dependency.Ecosystem))
		if _, err := fmt.Fprintf(stdout, "%s  %s\n",
			renderStyle(opts.Colorize, heading, reportAccent, true),
			whyNodeLabel(dependency, graph.Edge{}, opts.Colorize),
		); err != nil {
			return err
		}
		if dependency.InstallPath != "" {
			if _, err := fmt.Fprintf(stdout, "Install: %s\n", dependency.InstallPath); err != nil {
				return err
			}
		}
		if len(match.Paths) == 0 {
			if _, err := fmt.Fprintln(stdout, "  (no path from a manifest root was found)"); err != nil {
				return err
			}
		}
		for pathIndex, path := range match.Paths {
			if _, err := fmt.Fprintf(stdout, "  PATH %d\n", pathIndex+1); err != nil {
				return err
			}
			for nodeIndex, node := range path.Nodes {
				prefix := "    "
				edge := graph.Edge{}
				if nodeIndex > 0 {
					prefix = "    -> "
					edge = path.Edges[nodeIndex-1]
				}
				if _, err := fmt.Fprintf(stdout, "%s%s\n", prefix, whyNodeLabel(node, edge, opts.Colorize)); err != nil {
					return err
				}
			}
		}
		if match.Truncated {
			if _, err := fmt.Fprintln(stdout, renderStyle(opts.Colorize, "  Additional paths for this match omitted; increase --max-paths to include them.", reportMuted, false)); err != nil {
				return err
			}
		}
		if matchIndex < len(result.Matches)-1 {
			if _, err := fmt.Fprintln(stdout); err != nil {
				return err
			}
		}
	}
	return writeWhyWarnings(stderr, result)
}

func whyNodeLabel(node graph.Node, edge graph.Edge, colorize bool) string {
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
	if len(tags) > 0 {
		label += " " + renderStyle(colorize, "["+strings.Join(tags, ", ")+"]", reportInfo, false)
	}
	return label
}

func writeWhyWarnings(stderr io.Writer, result graph.WhyResult) error {
	if len(result.Warnings) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(stderr, "\nWHY WARNINGS"); err != nil {
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
	return nil
}
