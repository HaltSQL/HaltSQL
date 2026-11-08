# Performance

Every number on this page was measured by the benchmark harness in `bench/`,
in one run on one machine. The raw output is committed next to the harness:
`bench/results/m1max-2026-11-08.json` (machine-readable) and
`bench/results/m1max-2026-11-08.md` (the full tables). Read the numbers as one data point with the conditions
listed below, not as a guarantee. Run the harness on your own hardware before
you plan capacity.

## Summary

| Path | Typical latency (p50) | Throughput |
|---|---|---|
| Library, `Haltsql.verify` in process | 48 µs for a point lookup, 247 µs for a multi-CTE report query | 3.5k–18k verifies/s on one core |
| CLI, `haltsql verify --batch` | 160 µs per query at `--jobs 1` | 6.3k/s at `--jobs 1`, 22.5k/s at `--jobs 8` |
| `haltsql-server`, `POST /v1/verify` | 278 µs on one connection | about 4.5k requests/s (one core) |
| `haltsql-proxy`, added to a query | +246 µs on a point select | 6.1k queries/s at 32 connections (one core) |

The main conclusions:

- **Verification is cheap next to the query it guards.** The full verdict
  (parse with the real PostgreSQL 17 parser, then analyse it against the
  policy) is 50–250 µs for realistic agent queries. That is well below the
  round trip to a database, and orders of magnitude below an LLM call.
- **Cost grows with query complexity, not with policy size.** The time goes up
  steadily from point lookups (t1) to six-way-join reports (t5). The
  pathological inputs (10,000-element `IN` lists, 500 levels of nesting,
  50-way joins) stay in the low milliseconds and are denied by the policy's
  limits.
- **`haltsql-server` and `haltsql-proxy` each verify on one core.** Their
  throughput levels off at about 4.5k requests/s and 6k queries/s on this
  machine. Beyond that, adding connections only adds queueing latency. Scale
  them out by running more replicas: one sidecar per agent pod, or more
  instances behind the load balancer.

## Test machine and conditions

| | |
|---|---|
| Machine | Apple M1 Max (8 performance + 2 efficiency cores, 10 logical CPUs), 64 GiB RAM |
| OS | macOS 26.5.1 (Darwin 25.5.0), arm64 |
| Toolchain | OCaml 5.3.0, dune release profile (`scripts/bench.sh`) |
| HaltSQL | 0.1.0, branch `feat/enterprise-adoption`, 2026-11-08 |
| PostgreSQL | 17 (`haltlab-pg17-1`, `postgres:17-alpine`) in Docker Desktop, published on 127.0.0.1:5417 |
| Run | 2026-11-08T03:07Z, all suites, default sizes |

The machine was **not idle**. Other development work was running at the same
time, including Docker containers and other builds. The 1/5/15-minute load
averages were `67.89 171.08 167.20` at the start of the run and
`63.22 122.71 147.30` at the end. An earlier run under much heavier load (a
1-minute load average above 150) measured p50 latencies up to 2x higher and
tail latencies up to 10x higher. Expect better and more stable numbers, above
all at p99 and p99.9, on a dedicated host. The harness records the load
average in its JSON output so that you can tell runs apart.

PostgreSQL runs inside Docker Desktop's Linux VM, and the benchmark client and
`haltsql-proxy` run natively on macOS. Every database round trip therefore
crosses Docker Desktop's port forwarding. This inflates the absolute PostgreSQL
latencies, for both the direct path and the proxied path, compared with a
database on the same host or network.

## Library: `Haltsql.verify`

These are in-process calls, one at a time on one domain, cycling through each
workload's queries. Each workload gets 20,000 timed calls after a warm-up; the
pathological workload gets 1,000. The policy is
`test/fixtures/policies/saas.yaml` (bound tenancy, catalog, function presets).
All latencies are in microseconds.

| Workload | Queries | What it is | p50 | p90 | p99 | p99.9 | verifies/s |
|---|---:|---|---:|---:|---:|---:|---:|
| `t1_point` | 4 | point lookups by id, ~80–100 bytes | 47.9 | 73.9 | 114 | 356 | 17,926 |
| `t2_filter_aggregate` | 4 | filters, `GROUP BY`, aggregates, `HAVING` | 78.0 | 109 | 170 | 600 | 11,435 |
| `t3_joins` | 4 | 2–3 joins, each table tenant-scoped | 112 | 152 | 239 | 437 | 8,492 |
| `t4_cte_window` | 4 | CTEs, window functions, correlated `EXISTS` | 130 | 189 | 365 | 1,069 | 6,835 |
| `t5_report` | 4 | 3 CTEs + 5 joins + `FILTER` + `CASE`; 5-way `UNION ALL`; cohort retention | 247 | 433 | 703 | 1,620 | 3,508 |
| `corpus_benign` | 170 | `test/corpus/benign_analytics.suite.yaml` (all allowed) | 64.1 | 108 | 211 | 523 | 13,516 |
| `corpus_attack` | 1,038 | every other `test/corpus` suite against its own policy (mostly denials) | 43.2 | 82.0 | 248 | 1,085 | 18,171 |
| `pathological` | 10 | 10k-element `IN`, 500-deep nesting, 50 joins, 15 KB query, 100-way `UNION` | 869 | 5,524 | 6,294 | 7,969 | 507 |

The tiers t1–t5 (`bench/corpus/complexity.jsonl`) are queries of the kind an
analytics agent writes against the haltlab-style SaaS schema. Before timing
anything, the harness checks that each one is **allowed**, so that a fast
denial cannot pass for a fast verify. Denials (`corpus_attack`) are a little
cheaper than allowed queries, because the analysis stops at the first
violation.

## CLI: `haltsql verify --batch`

The CLI runs end to end as a separate process: it loads the policy, reads
24,000 JSONL lines on stdin (the t1–t5 queries round-robin), and writes
24,000 verdicts. Each figure is the median of 3 runs. Every verdict is checked
to be `"allowed":true`.

| `--jobs` | Wall time (median) | Verdicts/s | Per query |
|---:|---:|---:|---:|
| 1 | 3.83 s | 6,268 | 160 µs |
| 2 | 1.91 s | 12,557 | 79.6 µs |
| 4 | 1.14 s | 21,072 | 47.5 µs |
| 8 | 1.07 s | 22,514 | 44.4 µs |

`--jobs` scales almost linearly up to 4 domains. At 8 domains the run is
bound by I/O and by the sequential read and write of each 4096×jobs-line
block. One `haltsql verify --sql ...` invocation (process start, policy and
catalog load, one verify) takes **9.8 ms** at the median and 11.0 ms at p99,
over 30 runs. For more than a handful of queries, use `--batch`.

## `haltsql-server`: `POST /v1/verify`

The load generator is closed-loop and built into the harness. It opens C
persistent HTTP/1.1 keep-alive connections, spread over up to 4 forked client
processes, and each connection sends its next request as soon as the previous
response arrives. Every response must be `200` with `"allowed":true`; there
were 0 errors. The server runs with `--policy saas.yaml
--allow-unauthenticated`, the default `info` logging to a file, and a file
audit sink (hash-chained, one record per request) unless noted. Each run lasts
10 s after a 2 s warm-up. Latencies are in microseconds and measured by the
client.

| Connections | Audit sink | p50 | p90 | p99 | p99.9 | requests/s |
|---:|---|---:|---:|---:|---:|---:|
| 1 | file | 278 | 460 | 752 | 2,159 | 3,192 |
| 8 | file | 1,735 | 2,184 | 3,320 | 8,601 | 4,466 |
| 32 | file | 6,847 | 10,288 | 18,741 | 38,148 | 4,187 |
| 128 | file | 26,908 | 37,301 | 58,559 | 79,690 | 4,488 |
| 32 | none | 6,410 | 8,599 | 16,378 | 34,690 | 4,655 |

The server verifies on a single Lwt event loop, so throughput saturates at
about **4.5k requests/s** on this machine. From there, latency rises in
proportion to the queue depth (Little's law: 32 connections / 4.2k/s ≈ 7.6 ms).
On one connection, the HTTP, JSON, logging and audit work adds roughly 150 µs
to the bare verify. The file audit sink costs about 10% of throughput at 32
connections.

To size a deployment, plan for one core per ~4k verifies/s of t1–t5-like
traffic, keep each instance well below saturation if you care about p99, and
scale out horizontally.

## `haltsql-proxy`: latency added to a query

Both paths use the same client: the harness's simple-query client, which
reuses the proxy's own `Upstream` module and authenticates with
SCRAM-SHA-256. The direct path connects to PostgreSQL. The proxied path
connects to `haltsql-proxy`, which verifies the statement against
`bench/fixtures/proxy-policy.yaml` (literal tenancy), writes one audit record
to a file, and relays the query over its own upstream connection. The table
is `app.orders`, with 20,000 rows over two tenants and an index on
`(tenant_id, created_at)`. For each query, 10 rounds of 500 direct and 500
proxied executions are interleaved on one connection each, so that drift on
the machine hits both paths equally. Before timing, the harness checks that
the proxy denies a cross-tenant query with SQLSTATE 42501. Latencies are in
microseconds.

| Query | Rows | Direct p50 | Proxied p50 | **Added p50** | Direct p99 | Proxied p99 |
|---|---:|---:|---:|---:|---:|---:|
| point select by primary key | 1 | 441 | 687 | **+246** | 1,961 | 3,556 |
| `GROUP BY status` aggregate | 2 | 2,448 | 2,748 | **+300** | 7,974 | 8,701 |
| range scan, `ORDER BY ... LIMIT 100` | 100 | 525 | 1,280 | **+755** | 3,037 | 3,331 |

The proxy adds about **0.25–0.3 ms** per statement at the median. That time
goes to the extra loopback hop, the verify, and the audit write. Large result
sets add more, because the proxy relays each row message: about 5 µs per
row for the 100-row query. At the tail, the difference between paths is
smaller than the run-to-run noise on this machine.

Throughput with 32 concurrent connections running the point select, closed
loop for 8 s:

| Path | p50 | p99 | queries/s |
|---|---:|---:|---:|
| direct | 1,149 | 5,022 | 23,394 |
| via `haltsql-proxy` | 4,564 | 12,545 | 6,070 |

Like the server, the proxy runs on a single event loop. It saturates at about
6k statements/s on one core, while PostgreSQL itself serves 23k/s for this
query. If a workload needs more than that through one proxy, run several
proxy replicas.

## How to reproduce

```sh
make -C lab up                  # Postgres 17 on localhost:5417 (proxy suite only)
scripts/bench.sh                # release build + all suites (~4 min)
# results: _build/bench-results/bench.json and bench.md
```

`scripts/bench.sh` builds `bench/bench.exe` and the three binaries with
`--profile release` and runs the harness. It passes any extra arguments
through to the harness:

| Option | Meaning |
|---|---|
| `--suite library,cli,http,proxy` | Suites to run (default: all). The proxy suite is skipped with a message if Postgres is unreachable. |
| `--small` | The short CI-sized run (~1 min). |
| `--iters N`, `--lines N` | Library calls per workload (default 20,000), CLI batch size (default 24,000). |
| `--pg-host`, `--pg-port`, `--pg-user` | Postgres for the proxy suite (default 127.0.0.1:5417, `postgres`; password from `HALTSQL_PGPASSWORD`, default `haltlab`). |
| `--json FILE`, `--markdown FILE` | Output files (`scripts/bench.sh` sets both under `$OUT_DIR`). |
| `--baseline FILE`, `--max-regress X` | The regression gate, described below. |

The proxy suite creates a scratch database, `release_bench_<pid>`, and always
drops it. The HTTP and proxy suites start their own server and proxy on free
loopback ports and stop them afterwards. `make bench` (or `dune build @bench`)
runs only the small library suite.

### Output format

The JSON output (`"schema": "haltsql-bench/1"`) records the host (OS, arch,
CPU, logical CPUs, memory, OCaml version, load average at the end), the
configuration (suites, sizes, load average at the start), and one object per
workload. Each object has `suite`, `name`, `unit`, `samples`, `p50`, `p90`,
`p99`, `p99_9`, `max`, `mean`, `throughput_per_s`, `errors`, `gate` and
workload-specific fields (`queries`, `concurrency`, `audit`, `jobs`,
`calibration_ms`, ...). Percentiles use the nearest-rank method. Timing uses
`Unix.gettimeofday`, whose resolution is 1 µs. A run exits 1 if any request
failed or any verdict was wrong.

## Regression gate (CI)

The `bench` job of `.github/workflows/build-images.yml` runs on pull requests
that touch `bin/`, `lib/`, `vendor/`, `bench/` or the build files:

```sh
scripts/bench.sh --small --suite library,cli,http \
  --baseline bench/baseline/ci-small.json --max-regress 1.5
```

The job compares the **gated** workloads with the committed baseline
`bench/baseline/ci-small.json`:

- the library tiers t1–t5;
- `corpus_benign`;
- `cli/batch_jobs_1`;
- `http/verify_c1_audit_file`.

It compares p50, the most stable statistic on a shared runner. The baseline
was recorded on the machine above, but CI runs on a GitHub-hosted x86-64
Linux runner, so absolute numbers are not comparable. Each p50 is therefore
divided by a **calibration time** first: a fixed CPU workload that does not
touch HaltSQL (SHA-256 over 64 KiB, sorting pseudo-random integers, hashing
short strings). The calibration runs interleaved with each library workload,
and before and after the CLI and HTTP suites, so that a busy or throttled
machine slows both sides of the ratio:

```
ratio = (p50_now / calibration_now) / (p50_baseline / calibration_baseline)
```

**The job fails when any gated ratio exceeds 2.5** (`--max-regress 1.5`), that
is, when a workload got more than 2.5x slower relative to the machine's
speed. p50 values below 5 µs are raised to 5 µs on both sides to absorb timer
noise. This threshold is deliberately loose, for three reasons:

- On a quiet machine, two consecutive runs against the baseline gave ratios
  of 0.94–1.07.
- The same small run in a Linux container on the same Mac shifted the
  normalized library numbers by up to about 1.3x compared with macOS.
- Under heavy machine load (a load average above 150), ratios spread from 0.1
  to over 2.

So the gate catches algorithmic regressions (an accidental quadratic pass, a
cache that stops working, recompiling the policy on every call) without
failing on noise. Smaller regressions need a look at the uploaded
`bench-results` artifact, or a local before/after run of `scripts/bench.sh`.

To update the baseline after an intended change, run this on a quiet machine
and commit the result:

```sh
OUT_DIR=/tmp/b scripts/bench.sh --small --suite library,cli,http
cp /tmp/b/bench.json bench/baseline/ci-small.json
```
