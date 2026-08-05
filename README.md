# deadcheck
<img width="1400" height="496" alt="Deadcheck Logo-selection" src="https://github.com/user-attachments/assets/e0ad3e48-a72d-47be-a59c-38cf63d6a2ed" />


`deadcheck` is a single Go binary that answers a simple question fast: should you worry about your dependencies right now?

It scans top-level `go.mod`, `package.json`, and `requirements.txt` files in one directory, then reports:

- known vulnerabilities from OSV.dev
- deprecated packages
- stale or abandoned release activity
- a health score from `0-100`

## Install

```bash
go install github.com/Tmwakalasya/deadcheck@latest
```

## Usage

```bash
deadcheck
deadcheck /path/to/project
deadcheck --json
deadcheck --github-summary
deadcheck --no-tui
deadcheck --production-only
deadcheck --min-severity warning
deadcheck --fail-below 80
deadcheck graph
deadcheck graph --json
deadcheck why lodash
deadcheck why golang.org/x/sys --json
deadcheck init ci
```

### Flags

- `--json`: emit structured JSON to stdout
- `--github-summary`: write a Markdown report to `$GITHUB_STEP_SUMMARY`
- `--no-tui`: skip the interactive dashboard and print a static terminal report
- `--production-only`: exclude npm `devDependencies` from scanning and scoring
- `--verbose`: include `info` findings in terminal output
- `--min-severity info|warning|critical`: filter terminal output severity
- `--fail-below N`: exit with code `1` when score is below `N`
- `--workers N`: maximum concurrent dependency checks, default `10`
- `--timeout 30s`: overall scan timeout
- `--path DIR`: explicit target directory
- `--version`: print the binary version

### Dependency graph

Inspect why dependencies are present without changing the project:

```bash
deadcheck graph
deadcheck graph /path/to/project
deadcheck graph --depth 0
deadcheck graph --json
deadcheck graph --production-only
```

Terminal output is a deterministic tree with direct, transitive, dev, optional, shared, and duplicate-install context. It defaults to three levels; `--depth 0` prints the complete tree. JSON always contains the complete node and edge set, regardless of `--depth`.

Graph resolution is ecosystem-native:

- Go uses `go mod graph` in readonly mode. This is Go's module requirement graph, so it can include older minimum versions referenced by selected modules.
- npm reads `npm-shrinkwrap.json` or `package-lock.json` v1-v3, preserves physical install paths, resolves hoisted edges, and prunes unreachable lockfile entries.
- Python requirements are shown direct-only for now, with a graph warning explaining that transitive resolution needs a canonical lockfile format.

If Go graph resolution fails or an npm lockfile is missing or invalid, `deadcheck` returns a usable direct-only graph and marks the result partial. Graph warnings go to stderr; with `--json`, stdout remains valid JSON.

### Explain a dependency

Trace every causal path from a manifest root to a dependency:

```bash
deadcheck why lodash
deadcheck why golang.org/x/sys
deadcheck why shared --json
deadcheck why lodash --ecosystem npm
deadcheck why lodash --dependency-version 4.17.21
deadcheck why lodash --max-paths 25
deadcheck why lodash --path /path/to/project
```

`why` distinguishes duplicate physical npm installations, reports alternate parents, and safely handles graph cycles. Queries are exact but case-insensitive; a missing dependency returns suggestions when available and exits with code `1`. The default is at most 10 causal paths per graph match, configurable up to 100 with `--max-paths`.

Both `deadcheck why lodash --json` and `deadcheck why --json lodash` are accepted. JSON includes each matched node plus the complete ordered node and edge sequence for every returned path.

### Background scans

Generate a scheduled GitHub Actions workflow:

```bash
deadcheck init ci
```

This creates `.github/workflows/deadcheck.yml` with a weekly dependency scan, manual trigger, pull request scan, GitHub Actions job summary, JSON report artifact, and `--fail-below 80` threshold.

Useful options:

- `--path DIR`: repository directory to write the workflow into
- `--fail-below N`: score threshold for the workflow, default `80`
- `--production-only`: exclude npm `devDependencies` in the workflow scan
- `--schedule "0 14 * * 1"`: GitHub Actions cron schedule
- `--force`: overwrite an existing deadcheck workflow

## What v0.2 supports

| Ecosystem | Health scan | Graph and `why` |
| --- | --- | --- |
| Go | direct `require` entries | native module requirement graph |
| npm | `dependencies` and `devDependencies` | physical tree from shrinkwrap or package-lock v1-v3 |
| PyPI | top-level requirements | direct-only until lockfile support lands |

### v0.2 scope

- top-level manifests only
- direct dependencies for health scoring; graph and `why` add transitive visibility
- best-effort scans: lookup failures become warnings instead of aborting the scan

### Not yet included

- transitive vulnerability scoring; `deadcheck graph` is read-only analysis
- recursive monorepo scanning
- archived GitHub repository checks
- automatic fixes or config files

## Output

On a real terminal, `deadcheck` opens an interactive Bubble Tea dashboard after scanning. It includes a live scan state, health summary, severity views, clean dependencies, full finding details, and scan warnings.

Dashboard keys:

- `h` / `l` or left / right: switch views
- `j` / `k` or up / down: select a dependency or warning
- `1-6`: jump directly to a view
- `pgup` / `pgdn`: move through long lists
- `q`, `esc`, or `ctrl+c`: close the dashboard

Piped output, `NO_COLOR`, `TERM=dumb`, `--no-tui`, and CI environments automatically use the static plain-text report. Scan warnings remain on stderr in static mode. JSON output includes:

- `score`
- `grade`
- `partial`
- `dependency_count`
- `ecosystems`
- `duration_ms`
- `warnings`
- full dependency findings

In GitHub Actions, `--github-summary` writes a compact Markdown report to the job summary while preserving normal terminal or JSON output.

## Scoring

`deadcheck` starts at `100` and subtracts points per dependency:

- critical vulnerability: `-15`
- warning-severity vulnerability: `-8`
- info-severity vulnerability: `-3`
- deprecated package: `-10`
- stale `12-24` months: `-2`
- abandoned `24+` months: `-5`

Grades:

- `90-100`: excellent
- `70-89`: good
- `50-69`: needs attention
- `0-49`: critical

## Development

```bash
make build
make test
make lint
```

To install from a local checkout instead of GitHub:

```bash
go install .
```

## Notes

- npm and PyPI vulnerability checks need a safely normalized version. If a manifest range cannot be normalized, `deadcheck` still runs staleness and deprecation checks and records a scan warning.
- Go dependencies replaced with local filesystem paths are reported but skipped for remote checks.
- [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Tmwakalasya/deadcheck)
