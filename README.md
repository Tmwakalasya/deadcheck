# deadcheck

<img width="1400" height="496" alt="Deadcheck" src="https://github.com/user-attachments/assets/e0ad3e48-a72d-47be-a59c-38cf63d6a2ed" />

**Know which dependencies need attention, why they are here, and what to investigate next.**

`deadcheck` is a Go CLI for checking dependency maintenance and known vulnerabilities. Run it before a release, when returning to an older project, or in CI. It reports findings with suggestions, explains dependency paths, and shows which checks actually completed.

- Check direct dependencies for OSV vulnerabilities, deprecation, and release inactivity.
- Explore dependency graphs and trace a package back to the dependencies that introduced it.
- Read results in a terminal dashboard, plain text, JSON, or a GitHub Actions summary.
- Keep incomplete scans visible: failed or skipped checks produce an **INCOMPLETE** result with no health score.

**Install**

Installing from source requires Go 1.26 or later:

```bash
go install github.com/Tmwakalasya/deadcheck@latest
```

Make sure your Go binary directory is on `PATH` (`go env GOBIN`, or `$(go env GOPATH)/bin` when `GOBIN` is unset).

To build and install the current checkout:

```bash
git clone https://github.com/Tmwakalasya/deadcheck.git
cd deadcheck
go install .
```

**Start here**

Run these commands in a project directory:

```bash
deadcheck                         # Scan with an interactive dashboard when supported
deadcheck --no-tui                 # Print a static report
deadcheck --json > report.json     # Save structured results
deadcheck graph                    # Inspect the dependency tree
deadcheck why lodash               # Explain how a package enters the project
```

To scan another directory or exclude npm development dependencies:

```bash
deadcheck /path/to/project
deadcheck --production-only /path/to/project
```

The health scan reads supported manifests at the top level of that directory. It does not recursively discover projects.

**What gets checked**

| Ecosystem | Health scan | `graph` and `why` |
| --- | --- | --- |
| Go | Direct `require` entries in `go.mod`; entries marked `// indirect` are excluded | Native module requirement graph from `go mod graph` |
| npm | `dependencies` and `devDependencies` in `package.json`, using resolved lockfile versions when available | Physical dependency tree from npm lockfiles, including transitive packages |
| Python / PyPI | Top-level entries in `requirements.txt` | Direct dependencies only |

Health checks cover known vulnerabilities from OSV, package deprecation or inactivity metadata, and time since the latest release. Findings can include advisory references and suggested versions to investigate.

For **npm**, the health scan shares the graph resolver and prefers `npm-shrinkwrap.json` over `package-lock.json`. Lockfile versions 1–3 are supported. Only direct manifest dependencies enter the health scan; transitive graph nodes are not vulnerability-scanned.

If no npm lockfile exists, an exact manifest version such as `1.2.3` can be checked. A range such as `^1.2.3`, `~1.2.3`, or `*` is not treated as an installed version. Without a resolved version, vulnerability and deprecation checks are skipped; package release activity can still be checked. Invalid lockfiles, missing direct entries, and linked packages leave the relevant checks incomplete.

For **Go**, remote version replacements are checked under the replacement identity. Local filesystem replacements are reported and skipped for remote checks.

For **Python**, supported constraints are normalized from the manifest. Some ranges are represented by their lower bound; this does not establish the installed version. Python lockfile resolution is not implemented. Unsupported requirement lines and constraints produce warnings.

Current limits also include recursive monorepo scanning, pnpm/Yarn lockfiles, archived-repository checks, automatic fixes, and project configuration files. `--production-only` applies to npm development dependencies.

**Reading a result**

A complete health scan reports a score and findings. An incomplete scan keeps available findings and makes missing coverage explicit. For example, a shortened report might show:

```text
HEALTH SCORE  unavailable  INCOMPLETE

CHECK COVERAGE  1 / 2 dependencies fully checked (direct dependencies only)

Scan incomplete; unchecked dependencies may have additional findings.
  checked  checked-lib
  incomplete  unknown-lib (vulnerability: failed)
```

“Fully checked” means the vulnerability, deprecation, and staleness checks all completed for that dependency. It does not mean the dependency has no findings. A dependency enters the dashboard's clean view only when all checks completed and no findings were reported.

Timeouts, registry failures, missing release dates, unresolved versions, and skipped dependency sources can make a scan incomplete. Warnings explain the missing checks. Coverage refers to the direct dependencies selected for the health scan, not every package displayed by `graph`.

On an interactive terminal, the dashboard provides severity views, dependency details, and scan warnings:

| Key | Action |
| --- | --- |
| `h` / `l`, left / right | Switch views |
| `j` / `k`, up / down | Select an item |
| `1`–`6` | Jump to a view |
| Page Up / Page Down | Move through long lists |
| `q`, Escape, Ctrl+C | Exit |

Piped output, CI environments, `NO_COLOR`, `TERM=dumb`, and `--no-tui` use a static report. In static mode, scan warnings go to stderr.

**JSON output**

```bash
deadcheck --json /path/to/project
```

The report includes `score`, `grade`, `partial`, `dependency_count`, `checked_dependency_count`, `ecosystems`, `duration_ms`, `warnings`, and dependency findings. Each dependency report has a `complete` boolean and a `checks` array. Check statuses are `complete`, `failed`, or `skipped`.

Selected fields from an incomplete report:

```json
{
  "score": null,
  "grade": "incomplete",
  "partial": true,
  "dependency_count": 2,
  "checked_dependency_count": 1
}
```

**Compatibility note:** `score` is nullable. JSON consumers must handle `null` when `partial` is `true`. Complete scans retain a numeric score from 0 to 100. npm dependencies include `version_source` when a version was resolved, identifying the lockfile or exact-version manifest used.

JSON scan warnings are included in the report. A threshold failure still produces one valid JSON document.

**Use in CI**

Generate a GitHub Actions workflow:

```bash
deadcheck init ci
```

This writes `.github/workflows/deadcheck.yml` with weekly, manual, and pull request triggers; a GitHub job summary; a JSON report artifact; and `--fail-below 80`.

Customize generation with:

```bash
deadcheck init ci --production-only --fail-below 90
deadcheck init ci --path /path/to/project --schedule "0 14 * * 1"
```

An existing workflow is preserved unless you pass `--force`.

For another CI system:

```bash
deadcheck --json --fail-below 80 > deadcheck-report.json
```

In GitHub Actions, add `--github-summary` to write to `GITHUB_STEP_SUMMARY` while keeping normal terminal or JSON output.

Health-scan exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Report produced; the threshold passed or the score gate was disabled |
| `1` | Complete scan scored below the configured threshold |
| `2` | Invalid command or options |
| `3` | Startup or execution failure, such as no supported manifest |
| `4` | Incomplete scan with `--fail-below N` enabled (`N > 0`) |

Without a score gate, best-effort scans can exit `0` while reporting incomplete coverage. `--fail-below 0` disables the gate. With a positive threshold, an incomplete scan exits `4` regardless of the findings collected. Reports and requested GitHub summaries are written before threshold-related exits.

**Graphs and dependency explanations**

```bash
deadcheck graph --depth 0                   # Print the full tree; default depth is 3
deadcheck graph --json                      # Export every node and edge
deadcheck graph --production-only

deadcheck why lodash --ecosystem npm
deadcheck why lodash --dependency-version 4.17.21
deadcheck why lodash --max-paths 25
deadcheck why golang.org/x/sys --json
```

Graph output distinguishes direct and transitive dependencies, development and optional dependencies, shared packages, and duplicate physical npm installations. JSON includes the full graph regardless of `--depth`.

`why` follows causal paths from a manifest root, reports alternate parents, and handles cycles. Names match exactly, ignoring case. It returns up to 10 paths per match by default; `--max-paths` accepts up to 100. No match exits `1` and includes suggestions when available. Both `why --json lodash` and `why lodash --json` work.

Go graph resolution runs `go mod graph` in readonly mode. Its output can include older minimum versions required by other modules; these are not necessarily the versions selected for the build. npm graph resolution preserves physical install locations and hoisted edges. Python graphs remain direct-only.

When Go resolution fails or an npm lockfile is unavailable or invalid, graph commands provide a partial, direct-only fallback with warnings. Fallback versions derived from ranges are estimates, not installed-version evidence. Graph analysis does not add transitive health checks or modify project files.

**Health-scan options**

| Option | Behavior |
| --- | --- |
| `--json` | Emit structured JSON |
| `--no-tui` | Print a static terminal report |
| `--github-summary` | Also write the GitHub Actions job summary |
| `--production-only` | Exclude npm `devDependencies` |
| `--min-severity info\|warning\|critical` | Filter terminal findings; default `warning` |
| `--verbose` | Include informational findings |
| `--fail-below N` | Enable the score gate; default `0` (disabled) |
| `--workers N` | Limit concurrent dependency checks; default `10` |
| `--timeout 30s` | Set the overall scan timeout |
| `--path DIR` | Set the target directory explicitly |
| `--version` | Print the binary version |

Place health-scan flags before the positional project directory. Use `deadcheck --help`, `deadcheck graph --help`, or `deadcheck why --help` for command-specific options.

**How scoring works**

Only complete scans receive a score. Start at 100, subtract penalties per dependency, and clamp the result at zero:

| Finding | Penalty |
| --- | ---: |
| Highest vulnerability severity is critical | 15 |
| Highest vulnerability severity is warning | 8 |
| Highest vulnerability severity is info | 3 |
| Deprecated package | 10 |
| Latest release is 365–729 days old (`STALE`) | 2 |
| Latest release is at least 730 days old (`ABANDONED`) | 5 |

The vulnerability penalty uses only the highest severity for each dependency. Releases 180–364 days old produce an informational `AGING` finding without a score penalty. The age labels are release-activity heuristics; an old release alone does not establish that maintainers have abandoned a package.

Grades are `excellent` (90–100), `good` (70–89), `needs_attention` (50–69), and `critical` (0–49). Incomplete scans use `grade: "incomplete"` and `score: null`.

A score threshold is an aggregate policy: one critical vulnerability alone yields 85, so a complete scan with that finding passes `--fail-below 80`. Read individual findings when deciding what to address.

**Data sources**

Health checks query OSV and the relevant package registries over the network. Requests contain package names and, for version-specific lookups, versions. The health scanner does not upload application source code.

The defaults can be overridden for testing or alternate endpoints:

| Environment variable | Default |
| --- | --- |
| `DEADCHECK_OSV_URL` | `https://api.osv.dev` |
| `DEADCHECK_GO_PROXY_URL` | `https://proxy.golang.org` |
| `DEADCHECK_NPM_REGISTRY_URL` | `https://registry.npmjs.org` |
| `DEADCHECK_PYPI_URL` | `https://pypi.org` |

Go graph resolution invokes the Go toolchain and follows its module-resolution configuration.

**Development**

```bash
make build     # Build ./deadcheck
make test      # Run the test suite
make lint      # Run go vet
```

The tests cover parsing, lockfile resolution, graph paths, registry responses, scan coverage, report output, and CLI exit behavior. When contributing a fix, include a small reproducer and a regression test where appropriate. Keep health-scan coverage and unsupported formats explicit in user-facing output.

See [performance benchmarks](PERFORMANCE.md) for measured scan and graph timings, allocation data, limitations, and commands to reproduce the results.
