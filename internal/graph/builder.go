package graph

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Tmwakalasya/deadcheck/internal/model"
)

type commandRunner interface {
	Run(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %v: %w: %s", name, args, err, output)
	}
	return output, nil
}

type Builder struct {
	runner commandRunner
}

func New() *Builder {
	return &Builder{runner: execCommandRunner{}}
}

func newWithRunner(runner commandRunner) *Builder {
	return &Builder{runner: runner}
}

func (b *Builder) Build(ctx context.Context, target string, opts Options) (Result, error) {
	started := time.Now().UTC()
	absPath, err := filepath.Abs(target)
	if err != nil {
		return Result{}, fmt.Errorf("resolve target path: %w", err)
	}

	hasGo := regularFile(filepath.Join(absPath, "go.mod"))
	hasNPM := regularFile(filepath.Join(absPath, "package.json"))
	hasPip := regularFile(filepath.Join(absPath, "requirements.txt"))
	if !hasGo && !hasNPM && !hasPip {
		return Result{}, ErrNoSupportedManifest
	}

	parts := make([]subgraph, 0, 3)
	if hasGo {
		part, err := b.resolveGo(ctx, absPath)
		if err != nil {
			return Result{}, err
		}
		parts = append(parts, part)
	}
	if hasNPM {
		part, err := b.resolveNPM(absPath, opts)
		if err != nil {
			return Result{}, err
		}
		parts = append(parts, part)
	}
	if hasPip {
		part, err := b.resolvePip(absPath)
		if err != nil {
			return Result{}, err
		}
		parts = append(parts, part)
	}

	result := Result{
		Path:       absPath,
		Roots:      make([]string, 0, len(parts)),
		Nodes:      make([]Node, 0),
		Edges:      make([]Edge, 0),
		Warnings:   make([]model.Warning, 0),
		Ecosystems: make([]model.Ecosystem, 0),
		StartedAt:  started,
	}
	for _, part := range parts {
		result.Roots = append(result.Roots, part.root)
		result.Edges = append(result.Edges, part.edges...)
		result.Warnings = append(result.Warnings, part.warnings...)
		for _, node := range part.nodes {
			result.Nodes = append(result.Nodes, node)
			if node.Root {
				continue
			}
			result.DependencyCount++
			if node.Direct {
				result.DirectCount++
			} else {
				result.TransitiveCount++
			}
		}
	}

	result.Edges = dedupeEdges(result.Edges)
	sort.Strings(result.Roots)
	sort.Slice(result.Nodes, func(i, j int) bool {
		if result.Nodes[i].Root != result.Nodes[j].Root {
			return result.Nodes[i].Root
		}
		if result.Nodes[i].Ecosystem != result.Nodes[j].Ecosystem {
			return result.Nodes[i].Ecosystem < result.Nodes[j].Ecosystem
		}
		if result.Nodes[i].Depth != result.Nodes[j].Depth {
			return result.Nodes[i].Depth < result.Nodes[j].Depth
		}
		if result.Nodes[i].Name != result.Nodes[j].Name {
			return result.Nodes[i].Name < result.Nodes[j].Name
		}
		if result.Nodes[i].Version != result.Nodes[j].Version {
			return result.Nodes[i].Version < result.Nodes[j].Version
		}
		return result.Nodes[i].InstallPath < result.Nodes[j].InstallPath
	})
	model.SortWarnings(result.Warnings)
	result.Ecosystems = graphEcosystems(result.Nodes)
	result.Partial = len(result.Warnings) > 0
	result.CompletedAt = time.Now().UTC()
	result.DurationMS = result.CompletedAt.Sub(started).Milliseconds()
	return result, nil
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func graphEcosystems(nodes []Node) []model.Ecosystem {
	seen := make(map[model.Ecosystem]struct{})
	for _, node := range nodes {
		seen[node.Ecosystem] = struct{}{}
	}
	out := make([]model.Ecosystem, 0, len(seen))
	for ecosystem := range seen {
		out = append(out, ecosystem)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func envWithOverrides(base []string, overrides ...string) []string {
	keys := make(map[string]struct{}, len(overrides))
	for _, override := range overrides {
		key, _, ok := strings.Cut(override, "=")
		if ok {
			keys[key] = struct{}{}
		}
	}

	out := make([]string, 0, len(base)+len(overrides))
	for _, item := range base {
		key, _, ok := strings.Cut(item, "=")
		if ok {
			if _, replaced := keys[key]; replaced {
				continue
			}
		}
		out = append(out, item)
	}
	return append(out, overrides...)
}
