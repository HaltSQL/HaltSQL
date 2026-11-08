# Testing

A security tool is only as good as the evidence that it works. HaltSQL's test
strategy aims to show three things continuously:

1. **No escapes:** nothing HaltSQL allows can read another tenant's data, read a
   denied column, or change anything in the database.
2. **Few false alarms:** realistic queries that should be allowed are allowed.
3. **It survives real deployments:** messy schemas, many policies, connection
   poolers, reloads, outages, upgrades, and load.

This page covers testing your own policies, then the project's own test
layers. Some layers described here are targets for 1.0 and are being built
during the 0.x series; the table marks which ones run in CI today.

## Policy test suites

Write allow/deny cases next to each policy and run them in CI with
`haltsql test`. A suite is a `kind: TestSuite` document:

```yaml
apiVersion: haltsql.dev/v1
kind: TestSuite
metadata:
  name: tenancy-basic
  description: Tenant filters for the analytics agent.
policy: ../policies/analytics-agent.yaml    # relative to this file
defaults:
  context: { tenant_id: acme }
cases:
  - name: filtered select is allowed
    sql: SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10
    expect: allow
    bind: [{ param: 1, value: acme }]
  - name: missing tenant filter
    sql: SELECT id FROM orders LIMIT 10
    context: { tenant_id: globex }          # replaces defaults.context
    expect: deny
    codes: [E_TENANT_MISSING]
    tags: [tenancy]
```

| Field | Required | Meaning |
|---|---|---|
| `policy` | yes | Path to the policy, relative to the suite file. |
| `defaults.context` | no | Context used by cases that do not set their own. |
| `cases[].name` | yes | Descriptive name, printed on failure. |
| `cases[].sql` | yes | The exact SQL string. |
| `cases[].expect` | yes | `allow` or `deny`. |
| `cases[].codes` | no | For `deny`: each listed code must appear in the reasons (others may too). |
| `cases[].bind` | no | For `allow`: the expected `bind_params`, compared exactly. |
| `cases[].context` | no | Replaces `defaults.context` for this case. |
| `cases[].tags` | no | Free-form labels. |

For shadow-mode policies, cases are checked against `shadow_reasons`, so the
same suite works before and after switching to `enforce`.

```sh
haltsql test policies/*.test.yaml
```

Good suites include, for every tenant-scoped table, at least one allowed query
and the common bypass shapes (missing filter, `OR`, outer-only filter, `UNION`
branch, `LEFT JOIN` preserved side), plus a denied-column case for each
sensitive column you left out.

## Test layers

| Layer | What it checks | Tooling | Status in 0.1.0 |
|---|---|---|---|
| Unit | Each module and rule in isolation, with positive and negative cases | Alcotest | Runs on every PR |
| Golden | Verdict JSON, `explain` output, and error messages stay stable | Snapshot files reviewed in PRs | Runs on every PR |
| Attack corpus | Known bypass techniques with the verdict HaltSQL must return | `test/corpus/` TestSuite files | Runs on every PR; must be 100% |
| Conformance | Same verdicts as the sql-guardrail test cases (MIT, attributed) | `test/conformance/` | Runs on every PR |
| Property-based | Evasion transforms applied to allowed queries must flip the verdict to deny when they break isolation | QCheck with shrinking (`test/property/`) | Runs on every PR |
| Differential | Allowed queries run against real Postgres; the database is the judge | `haltlab` | Nightly (lab) |
| Fuzzing | Parser bridge and YAML/JSON loader (HTTP input planned): no crashes, every input gets a verdict | Deterministic generator (`test/fuzz/`); AFL++ planned | Runs on every PR |
| Mutation | Tests catch injected bugs in rule code | Mutation testing | Planned |
| Contract | HTTP API matches `docs/openapi.yaml` | Schemathesis | Planned |
| Coverage | Untested code | bisect_ppx (`make coverage`) | Report uploaded by CI |

Targets for 1.0 include at least 2,000 attack-corpus cases, at least 95% line
coverage in the analyzer, resolver, policy, and loader modules, and at least
85% of mutants caught. These are goals, not current measurements.

### The attack corpus

`test/corpus/` holds bypass techniques: statement smuggling, data-modifying
CTEs, side-effect functions, catalog access, identifier tricks (quoting, case,
`U&` escapes), tenant bypass shapes, resource exhaustion, and more. It grows
with every bug fix, every report, and every published technique. Every fixed
bypass gets a case so it cannot come back. See
[CONTRIBUTING.md](../CONTRIBUTING.md#adding-an-attack-corpus-case) for how to add
one.

### Evasion transforms

Property tests take allowed queries and apply transforms, alone and combined:
wrap in a CTE, subquery, or `LATERAL`; add a `UNION`/`INTERSECT`/`EXCEPT`
branch; move the tenant filter to an outer query; add `OR` or `NOT`; `LEFT
JOIN` to a tenant table; alias and CTE-name shadowing; quoting, case, and
Unicode-escape variants; casts and `reg*` casts; set-returning functions in
`FROM`; whole-row references; `EXPLAIN ANALYZE` wrappers; comments and dollar
quoting in odd places. A transform that breaks isolation must turn the verdict
into a denial. Failures are shrunk to a minimal query and added to the corpus.

## The enterprise lab (haltlab)

`haltlab` builds a realistic company environment, runs traffic through
HaltSQL, and checks the results against a real Postgres. It lives in `lab/`
and runs locally with Docker Compose:

```sh
make lab-up      # start Postgres and the lab services
make lab-run     # run scenarios; reports go to lab/out/
make lab-down    # stop and clean up
```

The nightly `Lab` workflow runs the same targets and uploads the report.

### Scenarios

Scenarios are `kind: Scenario` documents, loaded with the same YAML/JSON rules
as policies. A scenario names a schema fixture, a data generator
configuration, policies, workloads (benign, adversarial, replayed), and the
expected outcome, for example zero escapes and a maximum false-positive rate.
See the files in `lab/` for the exact format supported by the current lab.

Schema fixtures are synthetic and modeled on common enterprise shapes:
multi-tenant SaaS with `tenant_id` columns, composite tenant keys,
hierarchical tenants (sets of allowed values), mixed-case and Unicode names,
sensitive columns, and legacy naming with ambiguous column names.

### Oracles

A lab run decides pass or fail with oracles that do not depend on HaltSQL's own
logic:

| Oracle | How it works | Catches |
|---|---|---|
| RLS differential | Each allowed query also runs as a role restricted by Postgres row-level security to the current tenant. Any difference in results is an escape. | Tenant leaks |
| Honeytokens | Every tenant and sensitive column gets unique marker values; any result containing another tenant's marker or a denied column's marker fails the run. | Tenant and column leaks |
| Column privileges | Allowed queries run as a role granted `SELECT` only on the policy's columns; a permission error means HaltSQL allowed a column it should not have. | Column leaks |
| Side effects | Queries run in a read-only transaction; table checksums, sequences, locks, and settings are compared before and after. | Hidden writes and state changes |
| Verdict stability | The same query, policy, and context are checked across processes and across YAML and JSON policy files. | Nondeterminism |

Any escape found by the lab is minimized and added to the attack corpus.

## When each tier runs

| Tier | When | Contents |
|---|---|---|
| PR | Every pull request | Formatting, build, unit, golden, attack corpus, coverage report |
| Nightly | Every night | Lab scenarios with the oracles above |
| Weekly | Every week | Trivy image and configuration scans |
| Release | Every tag | Full build matrix, signed artifacts, SBOM |

The plan for 1.0 adds nightly fuzzing, chaos and mutation testing, multiple
Postgres versions, and a signed test report attached to each release.
