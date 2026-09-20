**Performance baseline — September 19, 2026**

Benchmarked the production code at `2670c04` with the repeatable Go benchmarks included in this repository. All benchmark correctness checks passed. This is an initial baseline, not a comparison against an earlier release or a production service-level guarantee.

Environment: Apple M4 Pro, 12 logical CPUs, macOS 26.6.2, darwin/arm64, Go 1.26.0. Each case ran three samples with `-benchtime=500ms`; the tables show the median of those samples. For operations slower than 500 ms, each sample contained one operation. See the [raw results](benchmarks/2026-09-19.txt) for iteration counts and variation.

**Health scans**

Each scan starts with fresh metadata and vulnerability caches. Measurements include manifest and lockfile reads, npm graph resolution, response decoding, all three health checks, and scoring. Project fixture creation is excluded.

| Direct dependencies checked | Packages in lockfile | Workers | Simulated delay per lookup | Time per scan | Allocated per scan |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 50 | 500 | 10 | 0 ms | 1.888 ms | 1.85 MiB |
| 250 | 2,500 | 10 | 0 ms | 7.874 ms | 8.69 MiB |
| 1,000 | 10,000 | 10 | 0 ms | 29.412 ms | 35.30 MiB |
| 100 | 1,000 | 1 | 5 ms | 577.668 ms | 3.78 MiB |
| 100 | 1,000 | 10 | 5 ms | 64.274 ms | 3.79 MiB |
| 100 | 1,000 | 50 | 5 ms | 17.911 ms | 3.81 MiB |
| 1,000 | 10,000 | 10 | 5 ms | 611.084 ms | 35.78 MiB |

Registry responses come from an in-process HTTP transport. The delayed cases add a cancellable 5 ms timer to every lookup. Responses contain minimal, healthy package metadata and no vulnerabilities. There are no real sockets, DNS lookups, TLS handshakes, registry throttling, or large package histories in this test. Filesystem caches are not cleared between iterations. These times are not expected internet scan times.

The suite verifies two requests per direct dependency: one metadata request shared by staleness and deprecation checks, and one OSV request. It also verifies complete coverage and a score of 100 on every scan. Transitive lockfile packages are resolved but are not health-scanned.

**Graph resolution and explanations**

Fixtures have 50 direct dependencies, a branching dependency tree, and shared paths to a leaf. Graph resolution includes file reads and graph construction. Explanation timing starts with an already-built graph and returns the first 10 paths, verifying that further paths are marked truncated.

| Packages | Graph resolution | Graph allocations | Explanation only | Explanation allocations |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 0.230 ms | 0.33 MiB | 0.068 ms | 0.17 MiB |
| 1,000 | 1.971 ms | 3.41 MiB | 0.631 ms | 1.62 MiB |
| 10,000 | 22.416 ms | 31.45 MiB | 6.505 ms | 13.88 MiB |

Allocated bytes are total Go heap allocations per operation (`B/op`), not peak or retained process memory. Process startup and terminal/JSON rendering are excluded from all benchmarks. These fixtures do not cover every graph shape, cycles, many duplicate installations, failure-heavy scans, or Go/Python ecosystem performance.

**Interpretation**

- Local scan and graph processing stayed below 30 ms at the largest tested sizes on this machine with zero simulated lookup delay.
- With a 5 ms lookup delay and 100 direct dependencies, the default 10 workers were about 9 times faster than one worker. Fifty workers were faster again in this controlled test, but this does not establish an appropriate concurrency setting for a real registry.
- Large scans allocated about 35 MiB per run. Lockfile and graph construction are candidates for allocation profiling if larger projects become a priority; this run does not establish peak memory usage or a leak.
- Keep the default worker count unchanged. Use this baseline to evaluate future changes, and measure representative real registries separately before making end-to-end latency claims.

**Reproduce**

```bash
go test ./internal/scanner ./internal/graph \
  -run '^$' \
  -bench 'Benchmark(Scan|NPMGraph|Why)$' \
  -benchmem -benchtime=500ms -count=3
```

The benchmark suite uses synthetic local fixtures and requires no registry access once Go dependencies are available. For a more stable comparison, run on an otherwise idle machine with the same Go version and increase the sample duration and count, for example `-benchtime=2s -count=5`.
