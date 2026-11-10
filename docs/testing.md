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

| Layer | What it checks | Tooling | Status in 0.0.1 |
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

## End-to-end suite

`test/e2e/` runs the real `haltsql`, `haltsql-server` and `haltsql-proxy`
binaries against the real services HaltSQL integrates with. Nothing is mocked
or emulated: if something cannot be tested against the real software, it is
not in the suite.

```sh
make e2e                 # build, start the stack, run every scenario, stop the stack
make e2e KEEP=1          # ... and leave the stack running afterwards
make e2e E2E_ARGS="-k policy_distribution -x"   # extra pytest arguments
```

The stack is the Docker Compose project `haltsql-e2e`
(`test/e2e/compose.yaml`). Every port is bound to 127.0.0.1:

| Service | Image | Host port |
|---|---|---|
| Postgres | `postgres:17` | 17000 |
| Keycloak (realm `haltsql-e2e`, imported from `fixtures/keycloak/`) | `quay.io/keycloak/keycloak:26.4.2` | 17001 |
| Kafka (KRaft, PLAINTEXT, no topic auto-creation) | `apache/kafka:3.9.1` | 17002 |
| OpenSearch (security plugin off) | `opensearchproject/opensearch:2.17.1` | 17003 |
| OPA (rego from `fixtures/opa/`, decision logs on the console) | `openpolicyagent/opa:1.10.1` | 17004 |
| registry:2 (plain HTTP on loopback) | `registry:2` | 17005 |
| MinIO | `pgsty/minio:latest` | 17006 |

Ports 17050-17099 are for the haltsql processes the tests start; each test
file owns a sub-range (listed in its docstring). Passwords and the Keycloak
client secret are random: `test/e2e/stack.sh env` writes them to
`test/e2e/.env` (mode 0600, gitignored), which Compose and the tests read.
Signing keys are generated in each test's temporary directory. Never commit a
key or secret under `test/e2e/fixtures`.

### Working against a running stack

```sh
test/e2e/stack.sh up                      # start (or check) the stack; waits until healthy
test/e2e/stack.sh venv                    # test/e2e/.venv with the pinned driver (requirements.txt + constraints.txt)
                                          # and test/e2e/.venv-agents/<framework> for test_agents.py
test/e2e/stack.sh test test_policy_distribution.py        # one file
test/e2e/stack.sh test test_policy_distribution.py::test_policy_distribution_over_oci -x
test/e2e/stack.sh logs opa                # service logs
test/e2e/stack.sh down                    # stop and delete the volumes
```

The agent frameworks' dependency pins conflict, so `test_agents.py` runs each
one in its own virtualenv, `test/e2e/.venv-agents/{openai_agents,langgraph,google_adk}`
(Python 3.11-3.13, `PYTHON_AGENTS` to choose; installed from `integrations/<framework>`
with its `constraints.txt` and only releases uploaded before `AGENTS_CUTOFF`).

The binaries come from `_build/default` (run `dune build` first); set
`HALTSQL_BIN`, `HALTSQL_SERVER_BIN` or `HALTSQL_PROXY_BIN` to use others.
`HALTSQL_SKIP_DOCKER=1` skips every test. A test whose service is unreachable
is skipped with the reason, unless `HALTSQL_E2E_REQUIRE=1` (set by `make e2e`
and in CI), which makes it a failure.

### Writing a scenario

Each scenario is one `test_*.py` file with its own tests. The fixtures in
`test/e2e/conftest.py`:

| Fixture or helper | What it does |
|---|---|
| `cli` | The `haltsql` CLI: `run`, `json`, `keygen`, `build_bundle`, `sign`, `push_oci`. |
| `processes` | `server(config_yaml, port)` writes the config, starts `haltsql-server` and waits for `/readyz`; `proxy(args, port)` starts `haltsql-proxy`. All are stopped after the test. A process has `verify`, `admin_status`, `get` and `log()`. |
| `registry`, `registry_manifest(ref)` | registry:2, and the manifest it stores for a reference. |
| `keycloak` | `client_token()` (service account, group `support`), `user_token("alice" or "bob")`, `claims(token)`. |
| `kafka` | `create_topic`, `consume(topic, min_messages=...)`, `delete_topic`. |
| `opensearch_client` | `search(index)`, `wait_for(index, count)`, `delete_index`. |
| `opa`, `opa_put_policy`, `opa_decision_logs()` | OPA, uploading a test's own rego module, and the inputs OPA received. |
| `minio` | `mc(...)` in the MinIO container, `make_bucket`, `credentials_env()`. |
| `postgres`, `pg_database` | psycopg connections, and a fresh database dropped after the test. |
| `pg_exec_exact(conn, sql, bind_params)` | Runs exactly the verified SQL in Postgres with a verdict's `bind_params` as server-side parameters. |
| `keycloak_admin` | Keycloak's admin API: a test's own realm (`create_realm`, with unmanaged user attributes enabled so attribute mappers work), groups, a client with mappers, users with attributes, `password_token`, `delete_realm`. |
| `read_jsonl(path)` | The records of a file audit sink. |
| `unique_name(prefix)`, `wait_until(...)` | Per-test names for topics, indexes, buckets, repositories and databases; polling with a timeout. |

Rules: use unique names on the shared services, so tests are independent and
can run in any order; start and stop your own haltsql processes on your own
ports; and assert on what the real services saw (the registry's manifest, the
Kafka records, the OpenSearch documents, OPA's decision log, the database), not
only on HaltSQL's own answers.

`test_stack.py` checks each helper against its service, so a scenario failure
points at HaltSQL rather than at the harness.

| Scenario | File | What it shows |
|---|---|---|
| Policy distribution | `test_policy_distribution.py` | A signed bundle pushed with `haltsql bundle push --oci` is pulled by the server; a newer version is hot-swapped (seen in `/v1/admin/status` and in verdicts); a bundle signed by an untrusted key is refused with `bundle_source_signature` while the last good version keeps serving, also after a restart from the cache. |
| Identity | `test_identity.py` | A per-test Keycloak realm issues real tokens: group `support` gets policy `support-bot`, group `finance` gets `finance-analyst`, an unknown group, a token without groups and one without the tenant claim get `401`. The tenant comes from the nested claim `haltsql.tenant`: a literal for another tenant is `E_TENANT_MISMATCH`, a body context for another tenant is `403 CONTEXT_NOT_ALLOWED`, and allowed queries run in Postgres with the bound tenant return only that tenant's rows. Audit records carry the token's `sub`, never the token. |
| OPA | `test_opa.py` | A query HaltSQL allows and OPA denies gets `E_EXTERNAL_POLICY` with OPA's reason; OPA's decision log shows the exact input (no SQL, no context values) and no request for queries HaltSQL denied; an allow-everything OPA policy cannot allow a HaltSQL denial; for `on_error: deny` and `allow_haltsql_verdict`: a closed port, a private OPA container paused (timeout) and stopped, an undefined decision, and recovery after unpause and restart. |
| Shadow rollout | `test_shadow.py` | A shadow-mode workload; `GET /v1/admin/report` and `haltsql report --suggest` on the server's audit file list the would-be denials and the same suggestions; `--apply-to` adds the benign column, function, LIMIT and (tenant-scoped) table but never the sensitive column, and the tenant escapes stay denied; the patched policy in `mode: enforce` allows the benign queries (run in Postgres, only the caller's tenant's rows) and denies the escapes. |
| Audit pipeline | `test_audit_pipeline.py` | One server writes to a file, Kafka and OpenSearch at once. Each sink holds one record per request (same request ids and verdicts, no SQL), each with its own chain. `haltsql audit verify` passes on the file (with `--expect-head`), on the Kafka values read back in offset order and on the OpenSearch `event.original` lines (also checked with `test/siem/verify_chain.py`). A modified and a deleted record are detected in every copy, and so are tampering on the services themselves: a forged record appended to the topic, records removed with Kafka's DeleteRecords (`mid_chain_start`), and an OpenSearch document rewritten and another deleted. |
| Proxy | `test_proxy.py` | `haltsql-proxy` (TLS verify-full against a CA made for the test, SCRAM) in front of Postgres. psycopg gets the session tenant's rows even when it binds another tenant; a denied column, a cross-tenant literal and a `DELETE` get SQLSTATE 42501 with their reason codes, and the connection stays usable. The upstream role logs every statement, and the Postgres log shows the allowed statements (with `$1 = 'acme'`) and never the denied ones, which reach Postgres only as the proxy's unparsable placeholder; the rows are all still there. After SIGHUP with a new policy, new sessions may read `total_cents` and a session from before keeps the old policy. `haltsql audit verify` passes on the proxy's audit file, whose records match every statement, catches an edited record, and passes with `--strict` after a restart continues the chain. |
| Agent frameworks | `test_agents.py` | The HaltSQL tool of the OpenAI Agents SDK, LangGraph and Google ADK, each called through the framework's own tool-call machinery (no LLM) in its own virtualenv (`agents/drive_tool.py`), against a real server with a token and the stack's Postgres. Allowed queries return the rows of the tenant in the application state; cross-tenant queries are denied (`E_TENANT_MISMATCH`; `E_TENANT_MISSING` + `E_PARAM_UNBOUND`) and never executed; a call without a trusted context is refused. The Postgres log shows the two allowed executions with the bound tenants and none of the others; the server's audit file matches the verdicts and verifies. |

The `E2E` job of the Integration workflow runs `make e2e` on every pull request
that touches the OCaml tree (`.github/scripts/changes.sh` decides), and on every
push to `main`.

## When each tier runs

| Tier | When | Contents |
|---|---|---|
| PR | Every pull request | Formatting, build, unit, golden, attack corpus, coverage report; Docker integration suites and the end-to-end suite (Integration workflow) |
| Nightly | Every night | Lab scenarios with the oracles above |
| Weekly | Every week | Trivy image and configuration scans |
| Release | Every tag | Full build matrix, signed artifacts, SBOM |

The plan for 1.0 adds nightly fuzzing, chaos and mutation testing, multiple
Postgres versions, and a signed test report attached to each release.
