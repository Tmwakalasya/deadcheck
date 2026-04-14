# deadcheck

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
deadcheck --production-only
deadcheck --min-severity warning
deadcheck --fail-below 80
```

### Flags

- `--json`: emit structured JSON to stdout
- `--production-only`: exclude npm `devDependencies` from scanning and scoring
- `--verbose`: include `info` findings in terminal output
- `--min-severity info|warning|critical`: filter terminal output severity
- `--fail-below N`: exit with code `1` when score is below `N`
- `--workers N`: maximum concurrent dependency checks, default `10`
- `--timeout 30s`: overall scan timeout
- `--path DIR`: explicit target directory
- `--version`: print the binary version

## What v0.1 supports

| Ecosystem | Manifest | Notes |
| --- | --- | --- |
| Go | `go.mod` | direct `require` entries only, indirect deps skipped |
| npm | `package.json` | scans `dependencies` and `devDependencies`, with optional `--production-only` filtering |
| PyPI | `requirements.txt` | top-level requirements only |

### v0.1 scope

- top-level manifests only
- direct dependencies only
- best-effort scans: lookup failures become warnings instead of aborting the scan

### Not in v0.1

- lockfiles or transitive dependency analysis
- recursive monorepo scanning
- archived GitHub repository checks
- automatic fixes or config files

## Output

Terminal output groups dependencies by severity and prints scan warnings separately on stderr. JSON output includes:

- `score`
- `grade`
- `partial`
- `dependency_count`
- `ecosystems`
- `duration_ms`
- `warnings`
- full dependency findings

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
