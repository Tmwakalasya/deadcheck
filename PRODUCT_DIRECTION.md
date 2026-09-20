**Deadcheck product direction — September 19, 2026**

Recommendation: keep Deadcheck a focused open-source utility for dependency maintenance. Its promise should be: **“Know which dependencies need attention, why they are here, and what to do next.”**

The project direction is a focused open-source developer utility. The recommendations below prioritize correctness, understandable output, easy installation, and a sustainable maintenance scope. The proposed audience and workflow still need validation with actual users.

**Implementation update**

The first reliability patch implements explicit incomplete results, per-check coverage, unavailable scores for incomplete scans, exit code `4` when an incomplete scan is gated with `--fail-below`, and npm direct-dependency health checks using the existing lockfile resolver. The README now documents these behaviors and their limits. The findings and release sequence below describe the original review baseline; transitive health checks, revised abandonment labels, and configuration remain future work.

**What already works**

The repository at commit `1008c5d702140afb1acb9c61e663834e480966fb` has a substantial CLI foundation: Go, npm, and Python manifest scanning; OSV lookups; maintenance signals; terminal and JSON reports; a Bubble Tea interface; GitHub Actions summaries and workflow generation; dependency graphs; and causal dependency paths through `why`.

The graph and explanation code is especially useful for the proposed direction. It can connect a finding to the direct dependency a developer actually controls. The existing separation between parsing, registry access, checking, and reporting also supports incremental development.

Today, health scanning covers direct dependencies from top-level manifests. The graph adds transitive visibility separately. npm graph resolution understands package-lock/shrinkwrap files, while Python graph resolution remains direct-only. These limits are documented in [README.md](README.md).

**First users and recurring job**

Start with maintainers and small application teams who want a quick dependency check from their terminal or CI. The initial use case is a short review before a release or while returning to an older project, followed by checking whether a pull request introduces new maintenance problems.

Prioritize npm package-lock correctness because the repository already resolves its installed dependency structure and explains causal paths. Keep existing Go support dependable, and let users determine the next investment in pnpm, workspaces, or Python lockfiles. Preserve explicit support limits instead of widening the compatibility promise prematurely.

The desired first-session experience is: install a binary, run one command, understand coverage, inspect the few findings that need attention, follow a dependency path, and choose an upgrade, replacement investigation, or documented exception. A rerun should make new findings easy to distinguish from previously reviewed ones. Keep the plain terminal report useful on its own and preserve structured JSON for other tools.

**Competitive implication**

Basic detection is already well served. [GitHub dependency review](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/reviewing-dependency-changes-in-a-pull-request) shows dependency changes and vulnerabilities in pull requests. [Socket](https://docs.socket.dev/docs/maintenance) reports deprecation and possible lack of maintenance. OSV-Scanner offers [experimental deprecation reporting](https://google.github.io/osv-scanner/experimental/flag-deprecated-packages/) and [experimental guided remediation](https://google.github.io/osv-scanner/experimental/guided-remediation/) that can prioritize direct upgrades by the transitive vulnerabilities they address.

My inference: the useful niche to test is a small, convenient maintenance check combining evidence, causal paths, and practical next steps. A score or graph alone does not establish that value. Make it easy to use alongside existing vulnerability scanners and update tools. Keep any baseline and exception state local to the project.

**Trust problems to fix before promoting CI enforcement**

1. **Unknown results can look healthy.** I ran the built CLI against this repository with `--no-tui --timeout 1ns --fail-below 80`. All remote checks timed out, but stdout reported `100 / 100 EXCELLENT` and the process exited `0`. Warnings were printed separately. Display an explicit incomplete status, track coverage per check, and distinguish confirmed clean results from unchecked dependencies. CI needs a documented policy for insufficient coverage. See [scanner.go](internal/scanner/scanner.go), [table.go](internal/report/table.go), and [cli.go](internal/cli/cli.go).
2. **Manifest ranges are treated as resolved versions.** The npm parser can convert `^1.2.3` to `1.2.3` for vulnerability lookup even when the lockfile selects another version. Share resolved package identities between scanning, graph, and explanation. Without resolution, label the version as an estimate and avoid implying installed-version certainty. See [npm.go](internal/parser/npm.go) and [util.go](internal/parser/util.go).
3. **Release age is presented as abandonment.** The staleness checker labels a package `ABANDONED` after 730 days without a release. Age alone does not establish maintenance status. Show the observed fact, its source, and confidence; add maintainer deprecation notices and repository status as separate evidence. See [staleness.go](internal/checker/staleness.go).
4. **The aggregate score makes a weak gate.** With no other findings, one critical vulnerability produces a score of 85 and passes the generated workflow's threshold of 80. Meanwhile, maintenance penalties accumulate with project size. Use explicit policies for confirmed vulnerabilities and coverage; present maintenance concerns separately. See [scorer.go](internal/scorer/scorer.go) and [workflow.go](internal/ci/workflow.go).

**Build order**

Use three small releases as milestones. These are sequencing recommendations, not delivery estimates.

| Order | Work | Acceptance condition |
| --- | --- | --- |
| Next patch | Correct incomplete-result behavior; make scan scope visible; replace unsupported abandonment claims with evidence; document exit behavior | A timed-out scan cannot appear fully healthy, and users can explain what was checked |
| Next minor | Use npm lockfile versions for health checks; connect supported transitive findings to `why`; lead reports with actionable findings | Scan and graph agree on versions; each supported transitive finding identifies its parent path |
| Following minor | Add a small project configuration with exceptions, reasons, and expiry dates; add baseline comparison if users need it; improve the existing Actions workflow | Maintainers can distinguish new findings from reviewed ones and choose predictable CI policies |

Group findings by the direct dependency a maintainer can change. For each proposed action show: the evidence, affected versions, dependency path, whether the dependency is development-only, and the next step. Validate fixes against the installed version and applicable advisory ranges; a globally smallest fixed version is not necessarily appropriate for the installed release line. Do not imply that dependency presence proves exploitability or that an upgrade has been tested.

For Go, do not scan every raw `go mod graph` version as though it were selected for the build: the current graph includes older requirement versions. Establish the selected module versions before extending Go vulnerability coverage.

Retain the current score only as a secondary summary if users find it useful. Put actionable findings and scan coverage first. Keep the existing TUI, but prioritize the default text report and JSON contract. Defer automatic fixes, a hosted dashboard, new ecosystems, and AI features to protect the utility's scope.

Alongside the first releases, choose and add an open-source license (none was present in the reviewed checkout), publish versioned binaries with checksums, document the data sent to registries and OSV, and add a short contribution guide. A reproducible installation and a one-screen README example are adoption work worth doing early.

**Validation and project health**

Invite five to ten maintainers to run Deadcheck on a real repository. Ask about the last dependency problem they investigated, how they decided what to change, and what their existing tooling failed to explain. Compare Deadcheck with their current workflow on the same task. Publish reproducible examples of useful findings and document limitations beside them.

Useful early signals, chosen for this project rather than claimed as industry benchmarks:

- Several maintainers voluntarily run it again or keep it in CI after a month.
- At least three maintainers can point to a useful dependency decision enabled by the report.
- Track installation friction, time to a useful first decision, dismissed findings, and incomplete scans through opt-in feedback. Inspect every disputed high-priority finding.
- If users see no recurring advantage over their existing tools, improve the existing workflow before adding features.

Keep scanning, explanations, and CI integration freely usable. Maintain a short roadmap tied to reported use cases. Favor stable behavior and small contributions over feature breadth; contributor instructions and representative fixtures should make correctness improvements easy to review.

**Verification and limits**

The initial timeout behavior above was reproduced with the built binary. After the reliability patch, the same reproduction reports an unavailable score, zero fully checked dependencies, and exit code `4` when `--fail-below 80` is enabled. `go test ./...`, `go vet ./...`, a local build, and race checks for the scanner and registry packages passed. Regression fixtures cover timeouts, registry failures, incomplete reports, and npm lockfile resolution. Verification did not include a successful live registry scan, a visual terminal UI review, customer interviews, or a comprehensive security audit.
