package graph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/Tmwakalasya/deadcheck/internal/model"
	"github.com/Tmwakalasya/deadcheck/internal/parser"
)

func (b *Builder) resolveGo(ctx context.Context, target string) (subgraph, error) {
	manifest := filepath.Join(target, "go.mod")
	data, err := os.ReadFile(manifest)
	if err != nil {
		return subgraph{}, fmt.Errorf("read go.mod for graph: %w", err)
	}
	file, err := modfile.Parse(manifest, data, nil)
	if err != nil {
		return subgraph{}, fmt.Errorf("parse go.mod for graph: %w", err)
	}
	if file.Module == nil || file.Module.Mod.Path == "" {
		return subgraph{}, fmt.Errorf("parse go.mod for graph: module directive is required")
	}

	moduleName := file.Module.Mod.Path
	root := rootID(model.EcosystemGo, moduleName)
	directTokens := directGoModuleTokens(file)
	env := envWithOverrides(os.Environ(), "GOFLAGS=-mod=readonly", "GOWORK=off")
	output, err := b.runner.Run(ctx, target, env, "go", "mod", "graph")
	if err != nil {
		return fallbackGoGraph(manifest, moduleName, root, err)
	}

	g := subgraph{
		root: root,
		nodes: map[string]Node{root: {
			ID:        root,
			Name:      moduleName,
			Ecosystem: model.EcosystemGo,
			Source:    manifest,
			Root:      true,
		}},
	}
	tokenIDs := map[string]string{moduleName: root}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		fromName, fromVersion := splitGoModule(fields[0])
		toName, toVersion := splitGoModule(fields[1])
		if syntheticGoModule(fromName) || syntheticGoModule(toName) {
			continue
		}

		fromID := ensureGoNode(g.nodes, tokenIDs, fields[0], fromName, fromVersion, manifest)
		toID := ensureGoNode(g.nodes, tokenIDs, fields[1], toName, toVersion, manifest)
		if fromID == root && directTokens[fields[1]] {
			node := g.nodes[toID]
			node.Direct = true
			g.nodes[toID] = node
		}
		g.edges = append(g.edges, Edge{
			From:       fromID,
			To:         toID,
			Kind:       "require",
			Constraint: toVersion,
		})
	}

	return finalizeSubgraph(g, nil), nil
}

func directGoModuleTokens(file *modfile.File) map[string]bool {
	direct := make(map[string]bool)
	for _, requirement := range file.Require {
		if requirement.Indirect {
			continue
		}
		direct[requirement.Mod.Path+"@"+requirement.Mod.Version] = true
		for _, replacement := range file.Replace {
			if replacement.Old.Path != requirement.Mod.Path {
				continue
			}
			if replacement.Old.Version != "" && replacement.Old.Version != requirement.Mod.Version {
				continue
			}
			if replacement.New.Version != "" {
				direct[replacement.New.Path+"@"+replacement.New.Version] = true
			}
		}
	}
	return direct
}

func fallbackGoGraph(manifest, moduleName, root string, graphErr error) (subgraph, error) {
	parsed, err := (parser.GoModParser{}).Parse(manifest)
	if err != nil {
		return subgraph{}, err
	}
	g := subgraph{
		root: root,
		nodes: map[string]Node{root: {
			ID:        root,
			Name:      moduleName,
			Ecosystem: model.EcosystemGo,
			Source:    manifest,
			Root:      true,
		}},
		warnings: append(parsed.Warnings, model.Warning{
			Kind:    "graph_fallback",
			Message: "go mod graph failed; showing direct dependencies only: " + graphErr.Error(),
			Source:  manifest,
		}),
	}
	for _, dependency := range parsed.Dependencies {
		id := dependencyID(model.EcosystemGo, dependency.Name, dependency.ResolvedVersion, "")
		g.nodes[id] = Node{
			ID:        id,
			Name:      dependency.Name,
			Version:   dependency.ResolvedVersion,
			Ecosystem: model.EcosystemGo,
			Source:    manifest,
			Direct:    true,
		}
		g.edges = append(g.edges, Edge{From: root, To: id, Kind: "require", Constraint: dependency.Constraint})
	}
	return finalizeSubgraph(g, nil), nil
}

func ensureGoNode(nodes map[string]Node, ids map[string]string, token, name, version, source string) string {
	if id, ok := ids[token]; ok {
		return id
	}
	id := dependencyID(model.EcosystemGo, name, version, "")
	ids[token] = id
	if _, ok := nodes[id]; !ok {
		nodes[id] = Node{
			ID:        id,
			Name:      name,
			Version:   version,
			Ecosystem: model.EcosystemGo,
			Source:    source,
		}
	}
	return id
}

func splitGoModule(token string) (string, string) {
	index := strings.LastIndex(token, "@")
	if index <= 0 {
		return token, ""
	}
	return token[:index], token[index+1:]
}

func syntheticGoModule(name string) bool {
	return name == "go" || name == "toolchain"
}
