package graph

import (
	"encoding/json"
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Tmwakalasya/deadcheck/internal/model"
	"github.com/Tmwakalasya/deadcheck/internal/parser"
)

type npmPackageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type npmLockfile struct {
	Name            string                         `json:"name"`
	Version         string                         `json:"version"`
	LockfileVersion int                            `json:"lockfileVersion"`
	Packages        map[string]npmLockPackage      `json:"packages"`
	Dependencies    map[string]npmLegacyDependency `json:"dependencies"`
}

type npmLockPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type npmLegacyDependency struct {
	Version      string                         `json:"version"`
	Dev          bool                           `json:"dev"`
	Optional     bool                           `json:"optional"`
	Peer         bool                           `json:"peer"`
	Requires     map[string]string              `json:"requires"`
	Dependencies map[string]npmLegacyDependency `json:"dependencies"`
}

type npmRequirement struct {
	constraint string
	kind       string
	dev        bool
}

func (b *Builder) resolveNPM(target string, opts Options) (subgraph, error) {
	manifest := filepath.Join(target, "package.json")
	data, err := os.ReadFile(manifest)
	if err != nil {
		return subgraph{}, fmt.Errorf("read package.json for graph: %w", err)
	}
	var pkg npmPackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return subgraph{}, fmt.Errorf("parse package.json for graph: %w", err)
	}
	if pkg.Name == "" {
		pkg.Name = filepath.Base(target)
	}

	lockPath := filepath.Join(target, "npm-shrinkwrap.json")
	if !regularFile(lockPath) {
		lockPath = filepath.Join(target, "package-lock.json")
	}
	if !regularFile(lockPath) {
		return fallbackNPMGraph(manifest, pkg, opts, model.Warning{
			Kind:    "lockfile_missing",
			Message: "npm graph is direct-only because package-lock.json or npm-shrinkwrap.json was not found",
			Source:  manifest,
		})
	}

	lockData, err := os.ReadFile(lockPath)
	if err != nil {
		return subgraph{}, fmt.Errorf("read npm lockfile: %w", err)
	}
	var lock npmLockfile
	if err := json.Unmarshal(lockData, &lock); err != nil {
		return fallbackNPMGraph(manifest, pkg, opts, model.Warning{
			Kind:    "lockfile_invalid",
			Message: "npm lockfile could not be parsed; showing direct dependencies only: " + err.Error(),
			Source:  lockPath,
		})
	}
	if len(lock.Packages) > 0 {
		return buildNPMModernGraph(manifest, lockPath, pkg, lock, opts), nil
	}
	if len(lock.Dependencies) > 0 || lock.LockfileVersion <= 1 {
		return buildNPMLegacyGraph(manifest, lockPath, pkg, lock, opts), nil
	}
	return fallbackNPMGraph(manifest, pkg, opts, model.Warning{
		Kind:    "lockfile_incomplete",
		Message: "npm lockfile contains no dependency tree; showing direct dependencies only",
		Source:  lockPath,
	})
}

func buildNPMModernGraph(manifest, lockPath string, pkg npmPackageJSON, lock npmLockfile, opts Options) subgraph {
	root := rootID(model.EcosystemNPM, pkg.Name)
	g := subgraph{
		root: root,
		nodes: map[string]Node{root: {
			ID:        root,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: model.EcosystemNPM,
			Source:    manifest,
			Root:      true,
		}},
	}

	pathIDs := make(map[string]string, len(lock.Packages))
	linkedNames := make(map[string]bool)
	locations := sortedKeys(lock.Packages)
	for _, location := range locations {
		if location == "" {
			continue
		}
		descriptor := lock.Packages[location]
		if descriptor.Link {
			name := descriptor.Name
			if name == "" {
				name = packageNameFromLockPath(location)
			}
			linkedNames[name] = true
			g.warnings = appendWarning(g.warnings, model.Warning{
				Kind:       "workspace_skipped",
				Message:    "skipping linked npm workspace or local package in dependency graph",
				Dependency: name,
				Source:     lockPath,
			})
			continue
		}
		name := descriptor.Name
		if name == "" {
			name = packageNameFromLockPath(location)
		}
		if name == "" {
			continue
		}
		id := dependencyID(model.EcosystemNPM, name, descriptor.Version, location)
		pathIDs[location] = id
		g.nodes[id] = Node{
			ID:          id,
			Name:        name,
			Version:     descriptor.Version,
			Ecosystem:   model.EcosystemNPM,
			Source:      lockPath,
			InstallPath: location,
			Dev:         descriptor.Dev,
		}
	}

	rootRequirements := npmRootRequirements(pkg, opts.ProductionOnly)
	for _, name := range sortedKeys(rootRequirements) {
		requirement := rootRequirements[name]
		location, ok := resolveNPMInstallPath("", name, pathIDs)
		if !ok {
			if !linkedNames[name] {
				g.warnings = appendUnresolvedNPMWarning(g.warnings, name, lockPath, requirement.kind)
			}
			continue
		}
		id := pathIDs[location]
		node := g.nodes[id]
		node.Direct = true
		if requirement.dev {
			node.Dev = true
		}
		g.nodes[id] = node
		g.edges = append(g.edges, Edge{From: root, To: id, Kind: requirement.kind, Constraint: requirement.constraint})
	}

	for _, location := range locations {
		fromID, ok := pathIDs[location]
		if !ok {
			continue
		}
		descriptor := lock.Packages[location]
		dependencies := npmPackageRequirements(descriptor)
		for _, name := range sortedKeys(dependencies) {
			requirement := dependencies[name]
			childLocation, ok := resolveNPMInstallPath(location, name, pathIDs)
			if !ok {
				if requirement.kind == "require" && !linkedNames[name] {
					g.warnings = appendUnresolvedNPMWarning(g.warnings, name, lockPath, requirement.kind)
				}
				continue
			}
			g.edges = append(g.edges, Edge{
				From:       fromID,
				To:         pathIDs[childLocation],
				Kind:       requirement.kind,
				Constraint: requirement.constraint,
			})
		}
	}

	include := func(node Node) bool {
		return !opts.ProductionOnly || !node.Dev
	}
	return finalizeSubgraph(g, include)
}

func buildNPMLegacyGraph(manifest, lockPath string, pkg npmPackageJSON, lock npmLockfile, opts Options) subgraph {
	root := rootID(model.EcosystemNPM, pkg.Name)
	g := subgraph{
		root: root,
		nodes: map[string]Node{root: {
			ID:        root,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: model.EcosystemNPM,
			Source:    manifest,
			Root:      true,
		}},
	}

	pathIDs := make(map[string]string)
	descriptors := make(map[string]npmLegacyDependency)
	var addDependencies func(string, map[string]npmLegacyDependency)
	addDependencies = func(parent string, dependencies map[string]npmLegacyDependency) {
		for _, name := range sortedKeys(dependencies) {
			descriptor := dependencies[name]
			location := pathpkg.Join(parent, "node_modules", name)
			id := dependencyID(model.EcosystemNPM, name, descriptor.Version, location)
			pathIDs[location] = id
			descriptors[location] = descriptor
			g.nodes[id] = Node{
				ID:          id,
				Name:        name,
				Version:     descriptor.Version,
				Ecosystem:   model.EcosystemNPM,
				Source:      lockPath,
				InstallPath: location,
				Dev:         descriptor.Dev,
			}
			addDependencies(location, descriptor.Dependencies)
		}
	}
	addDependencies("", lock.Dependencies)

	rootRequirements := npmRootRequirements(pkg, opts.ProductionOnly)
	for _, name := range sortedKeys(rootRequirements) {
		requirement := rootRequirements[name]
		location, ok := resolveNPMInstallPath("", name, pathIDs)
		if !ok {
			g.warnings = appendUnresolvedNPMWarning(g.warnings, name, lockPath, requirement.kind)
			continue
		}
		id := pathIDs[location]
		node := g.nodes[id]
		node.Direct = true
		if requirement.dev {
			node.Dev = true
		}
		g.nodes[id] = node
		g.edges = append(g.edges, Edge{From: root, To: id, Kind: requirement.kind, Constraint: requirement.constraint})
	}

	for _, location := range sortedKeys(descriptors) {
		descriptor := descriptors[location]
		for _, name := range sortedKeys(descriptor.Requires) {
			childLocation, ok := resolveNPMInstallPath(location, name, pathIDs)
			if !ok {
				g.warnings = appendUnresolvedNPMWarning(g.warnings, name, lockPath, "require")
				continue
			}
			kind := "require"
			if descriptors[childLocation].Optional {
				kind = "optional"
			} else if descriptors[childLocation].Peer {
				kind = "peer"
			}
			g.edges = append(g.edges, Edge{
				From:       pathIDs[location],
				To:         pathIDs[childLocation],
				Kind:       kind,
				Constraint: descriptor.Requires[name],
			})
		}
	}

	include := func(node Node) bool {
		return !opts.ProductionOnly || !node.Dev
	}
	return finalizeSubgraph(g, include)
}

func fallbackNPMGraph(manifest string, pkg npmPackageJSON, opts Options, warning model.Warning) (subgraph, error) {
	parsed, err := (parser.NPMParser{}).Parse(manifest)
	if err != nil {
		return subgraph{}, err
	}
	root := rootID(model.EcosystemNPM, pkg.Name)
	g := subgraph{
		root: root,
		nodes: map[string]Node{root: {
			ID:        root,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: model.EcosystemNPM,
			Source:    manifest,
			Root:      true,
		}},
		warnings: append(parsed.Warnings, warning),
	}
	requirements := npmRootRequirements(pkg, opts.ProductionOnly)
	for _, dependency := range parsed.Dependencies {
		if opts.ProductionOnly && dependency.Dev {
			continue
		}
		requirement, expected := requirements[dependency.Name]
		if !expected {
			continue
		}
		id := dependencyID(model.EcosystemNPM, dependency.Name, dependency.ResolvedVersion, "")
		g.nodes[id] = Node{
			ID:        id,
			Name:      dependency.Name,
			Version:   dependency.ResolvedVersion,
			Ecosystem: model.EcosystemNPM,
			Source:    manifest,
			Direct:    true,
			Dev:       dependency.Dev,
		}
		g.edges = append(g.edges, Edge{From: root, To: id, Kind: requirement.kind, Constraint: dependency.Constraint})
		delete(requirements, dependency.Name)
	}
	for _, name := range sortedKeys(requirements) {
		requirement := requirements[name]
		id := dependencyID(model.EcosystemNPM, name, "", "")
		g.nodes[id] = Node{
			ID:        id,
			Name:      name,
			Ecosystem: model.EcosystemNPM,
			Source:    manifest,
			Direct:    true,
			Dev:       requirement.dev,
		}
		g.edges = append(g.edges, Edge{From: root, To: id, Kind: requirement.kind, Constraint: requirement.constraint})
	}
	return finalizeSubgraph(g, nil), nil
}

func npmRootRequirements(pkg npmPackageJSON, productionOnly bool) map[string]npmRequirement {
	requirements := make(map[string]npmRequirement)
	for name, constraint := range pkg.Dependencies {
		requirements[name] = npmRequirement{constraint: constraint, kind: "require"}
	}
	for name, constraint := range pkg.OptionalDependencies {
		requirements[name] = npmRequirement{constraint: constraint, kind: "optional"}
	}
	if !productionOnly {
		for name, constraint := range pkg.DevDependencies {
			if _, exists := requirements[name]; exists {
				continue
			}
			requirements[name] = npmRequirement{constraint: constraint, kind: "dev", dev: true}
		}
	}
	return requirements
}

func npmPackageRequirements(descriptor npmLockPackage) map[string]npmRequirement {
	requirements := make(map[string]npmRequirement)
	for name, constraint := range descriptor.Dependencies {
		requirements[name] = npmRequirement{constraint: constraint, kind: "require"}
	}
	for name, constraint := range descriptor.OptionalDependencies {
		requirements[name] = npmRequirement{constraint: constraint, kind: "optional"}
	}
	for name, constraint := range descriptor.PeerDependencies {
		if _, exists := requirements[name]; exists {
			continue
		}
		requirements[name] = npmRequirement{constraint: constraint, kind: "peer"}
	}
	return requirements
}

func resolveNPMInstallPath(parent, name string, pathIDs map[string]string) (string, bool) {
	directory := strings.TrimSuffix(parent, "/")
	for {
		candidate := pathpkg.Join(directory, "node_modules", name)
		if _, ok := pathIDs[candidate]; ok {
			return candidate, true
		}
		if directory == "" {
			return "", false
		}
		index := strings.LastIndex(directory, "/node_modules/")
		if index < 0 {
			directory = ""
		} else {
			directory = directory[:index]
		}
	}
}

func packageNameFromLockPath(location string) string {
	const marker = "node_modules/"
	index := strings.LastIndex(location, marker)
	if index < 0 {
		return ""
	}
	name := location[index+len(marker):]
	parts := strings.Split(name, "/")
	if len(parts) == 0 {
		return ""
	}
	if strings.HasPrefix(parts[0], "@") && len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func appendUnresolvedNPMWarning(warnings []model.Warning, dependency, source, kind string) []model.Warning {
	if kind == "optional" || kind == "peer" {
		return warnings
	}
	return appendWarning(warnings, model.Warning{
		Kind:       "lockfile_incomplete",
		Message:    "dependency edge could not be resolved in npm lockfile",
		Dependency: dependency,
		Source:     source,
	})
}

func appendWarning(warnings []model.Warning, warning model.Warning) []model.Warning {
	for _, existing := range warnings {
		if existing.Kind == warning.Kind && existing.Dependency == warning.Dependency && existing.Source == warning.Source && existing.Message == warning.Message {
			return warnings
		}
	}
	return append(warnings, warning)
}

func sortedKeys[T any](items map[string]T) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
