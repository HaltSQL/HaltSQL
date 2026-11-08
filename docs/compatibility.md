# Database compatibility

HaltSQL never connects to the database: it parses SQL with the PostgreSQL 17
grammar and checks it against your policy. The question for a Postgres flavour
is therefore whether what HaltSQL proves about a query (tenant filter, allowed
columns, no side effects) still holds when that flavour executes it, and
whether `haltsql-proxy` works in front of it.

This page lists what has actually been run. A row says "not yet run" until
someone runs it; nothing here is extrapolated.

## Method

Every engine runs the same haltlab scenario as `pr-smoke` (the `saas_shared`
fixture, 8 tenants, seed 42, 200 benign and 400 adversarial generated queries;
see [testing.md](testing.md) and `lab/README.md`). A run has three parts, all
against the same engine:

1. **Oracle self-test.** The workload runs with an allow-everything stand-in
   verifier. The database oracles (RLS differential, honeytokens,
   column-privilege role, side-effect checks) must catch tenant escapes, column
   leaks and side effects on that engine. Without this, a clean HaltSQL result
   on an engine could just mean that the oracles do not work there.
2. **HaltSQL.** `haltsql verify --batch` decides. Every allowed query is
   executed under the oracles inside a read-only, repeatable-read transaction
   that is always rolled back. The run passes only with zero escapes, zero
   side effects and zero column leaks.
3. **Proxy parity.** The workload goes through a live `haltsql-proxy` whose
   upstream is the engine (extended protocol, psycopg/libpq). The client sends
   another tenant's id for every tenancy parameter. The proxy must make the
   same decision as the CLI for every query, and must return exactly the rows
   of direct execution, with no foreign honeytokens.

Run it yourself:

```bash
cd lab && make venv
compat/run.sh up && compat/run.sh local all && compat/run.sh down
```

See `lab/compat/README.md` for details.

## Results

Local engines in Docker (compose profile `compat`). Run on 2026-11-07 on an
arm64 Mac with HaltSQL built from branch `feat/enterprise-adoption`.

| Engine | Version | Scenario | Executed | Escapes | Side effects | Proxy parity | Notes |
|---|---|---|---|---|---|---|---|
| PostgreSQL 18 (`postgres:18.4-alpine`) | 18.4 | `compat-pg18` | 268 of 600 | 0 | 0 | 600/600 same decisions, 261 executed through the proxy, 0 escapes | Oracle self-test caught 167 escapes, 37 column leaks and 34 side effects. |
| Supabase Postgres (`supabase/postgres:17.11.0.018`) | 17.11 | `compat-supabase` | 268 of 600 | 0 | 0 | 600/600, 261 executed, 0 escapes | The lab connects as Supabase's `postgres` role, which is not a superuser (it has CREATEROLE, CREATEDB and BYPASSRLS), as on hosted Supabase. Self-test: 167 / 37 / 34. |
| AlloyDB Omni (`google/alloydbomni:17.10.0`) | 17.10 | `compat-alloydb-omni` | 268 of 600 | 0 | 0 | 600/600, 261 executed, 0 escapes | Self-test: 167 / 37 / 34. |
| Citus 14.2 (`citusdata/citus:14.2.0-alpine`) | 18.4 | `compat-citus` | 268 of 600 | 0 | 0 | 600/600, 261 executed, 0 escapes | Single node. Tenant tables are co-located single-shard distributed tables and `currencies` is a reference table. Self-test: 167 / 37 / 34. amd64 image, emulated. See [Citus](#citus). |
| TimescaleDB 2.31.0 (`timescale/timescaledb:2.31.0-pg17`) | 17.11 | `compat-timescaledb` | 268 of 600 | 0 | 0 | 600/600, 261 executed, 0 escapes | `app.audit_events` (27 chunks) and `app.orgs` (12 chunks) are hypertables. Self-test: 167 / 37 / 34. |
| Amazon Aurora PostgreSQL | - | `compat-aurora-postgresql` | not yet run (workflow provided) | | | | |
| Neon | - | `compat-neon` | not yet run (workflow provided) | | | | |
| Supabase (hosted) | - | `compat-supabase-cloud` | not yet run (workflow provided) | | | | |
| Google AlloyDB | - | `compat-alloydb` | not yet run (workflow provided) | | | | |
| Amazon Redshift | - | grammar suite only | not applicable | | | | Not supported. See [Amazon Redshift](#amazon-redshift). |

How to read the table:

- **Executed**: queries HaltSQL allowed, all of which were run under the
  oracles. The other 332 were denied. The false-positive rate on benign
  queries was 0.030 on every engine.
- **7 execution errors on every engine**: an allowed query failed in the
  database with SQLSTATE 42P18 ("could not determine data type of parameter
  $1"). These come from the query generator (an untyped parameter) and happen
  identically on the PostgreSQL 17 baseline: `pr-smoke` on 17.11 also executed
  268 queries with the same 7 errors, 0 escapes and 0 side effects. They are
  not counted as executed through the proxy, which is why that count is 261.
- The proxy column counts all 600 queries: the proxy allowed exactly the 268
  the CLI allowed and denied the other 332 with SQLSTATE 42501.

### Engine-specific setup

The fixture is installed exactly as on stock Postgres. Some engines then
convert it to their native storage, after the data is loaded so the query
generators see the same catalog everywhere (`lab/compat/engines.py`).
Row-level security, ownership and column grants are kept, so the oracles judge
the converted tables.

- **PostgreSQL 18, Supabase, AlloyDB Omni**: no changes.
- **TimescaleDB**: `CREATE EXTENSION timescaledb`. Each tenant table with a
  `NOT NULL created_at timestamptz`, a single-column primary key and no
  incoming foreign keys becomes a hypertable with 30-day chunks and its data
  migrated. Its primary key is widened to `(id, created_at)`, as TimescaleDB
  requires. RLS on the hypertable applies to queries through it.
- **Citus**: see below.

### Citus

The Citus run uses one node: the coordinator holds all shards. Tenant tables
become co-located single-shard distributed tables (`create_distributed_table(t,
NULL)`, the building block of Citus schema-based sharding). Global tables
become reference tables. Foreign keys are dropped for the conversion and then
restored.

Hash-distributed tables were not used, for two reasons:

- The fixture keeps NULL tenant ids on purpose, and Citus rejects NULL
  distribution keys.
- Multi-shard queries and repartition joins run over extra connections. Those
  connections do not carry the transaction's `SET LOCAL ROLE` and `app.*`
  settings, so the RLS and column oracles cannot judge those queries.

What the Citus result shows: HaltSQL's verdicts hold for queries that the
Citus router planner runs in the session's own backend. It does **not** cover
multi-node clusters or multi-shard execution.

Citus itself changes two settings inside the transaction:
`enable_self_join_elimination` while planning any distributed query, and
`citus.enable_local_execution` while running `EXPLAIN`. The side-effect oracle
ignores those two settings on Citus only. Every other setting is still
compared, and HaltSQL denies `SET` and `set_config` anyway.

## Managed services

Aurora PostgreSQL, Neon, hosted Supabase and AlloyDB could not be reached from
the environment where this page was produced. `.github/workflows/compat-cloud.yml`
(manual `workflow_dispatch`) runs the same three parts against each service.
It reads the DSN from an optional repository secret and skips a service whose
secret is unset:

| Service | Secret |
|---|---|
| Amazon Aurora PostgreSQL | `HALTLAB_DSN_AURORA_POSTGRESQL` |
| Neon | `HALTLAB_DSN_NEON` |
| Supabase (hosted) | `HALTLAB_DSN_SUPABASE_CLOUD` |
| Google AlloyDB | `HALTLAB_DSN_ALLOYDB` |

To run one by hand:

```bash
HALTLAB_DSN='postgresql://admin:PASSWORD@HOST:5432/postgres?sslmode=require' \
  lab/compat/run.sh cloud neon
```

Requirements and effects:

- Use a disposable server, never production.
- The DSN's role must be able to `CREATE DATABASE` and `CREATE ROLE`.
- Each run creates and drops `haltlab_compat_<engine>_pg17` and
  `haltlab_compat_<engine>_proxy_pg17`.
- It creates the `NOLOGIN` roles `haltlab_owner`, `haltlab_rls` and
  `haltlab_cols`, and grants them to the DSN's role.
- A cloud scenario without `HALTLAB_DSN` refuses to run. It does not fall back
  to the local lab server.
- The proxy's upstream TLS follows `sslmode`:
  - `require` stays `require`.
  - `verify-full` needs `sslrootcert=FILE`.
  - `verify-ca` is upgraded to `verify-full`.
  - `prefer` and `allow` are refused.

Reports never contain the DSN. Add results to the table above only from such a
run.

## Amazon Redshift

Redshift is not supported. It speaks the Postgres wire protocol, but its SQL
forked from PostgreSQL 8.0.2. It also differs in ways that matter here:

| Area | Redshift | What HaltSQL does |
|---|---|---|
| Grammar | `TOP n`, `QUALIFY`, `MINUS`, `APPROXIMATE COUNT(DISTINCT ...)`, `PIVOT`/`UNPIVOT`, `GROUP BY ALL` | Not in the PG17 grammar: denied with `E_PARSE`. |
| DDL and data movement | `DISTKEY`, `SORTKEY`, `DISTSTYLE`, `ENCODE`, `IDENTITY(seed, step)`, `WITH NO SCHEMA BINDING`, `UNLOAD`, `COPY ... IAM_ROLE` | `E_PARSE`. |
| Grouping | `ROLLUP`, `CUBE`, `GROUPING SETS` (valid in both) | `E_UNSUPPORTED`: the analyzer does not model them. |
| Names | three-part `database.schema.table` | `E_UNSUPPORTED`. |
| Functions and pseudo-columns | `GETDATE`, `SYSDATE`, `NVL`, `NVL2`, `DECODE`, `LEN`, `LISTAGG`, `MEDIAN`, `RATIO_TO_REPORT`, `DATEADD`/`DATEDIFF`/`DATE_PART` with a bare date part, `CONVERT_TIMEZONE`, `MONTHS_BETWEEN`, `REGEXP_SUBSTR`, `STRTOL`, `JSON_PARSE`, `IS_VALID_JSON`, `PG_LAST_QUERY_ID`, `CURRENT_USER_ID` | Unknown to the policy: `E_FUNCTION_DENIED`, `E_COLUMN_UNRESOLVED` or `E_COLUMN_DENIED` (a bare date part such as `day` reads as a column). |
| SUPER / PartiQL | `c.payload.key`, `FROM t, t.items i` | Read as PostgreSQL names, which do not resolve: `E_COLUMN_UNRESOLVED`, `E_TABLE_DENIED`. |
| System catalog | `STV_*`, `SVV_*`, `SVL_*` | `E_TABLE_DENIED`. |
| Row-level security | `CREATE RLS POLICY ... WITH (...) USING (...)`, `ATTACH RLS POLICY ... TO ROLE` | Not PostgreSQL RLS: `E_PARSE`. `haltsql rls` output does not apply. |
| Transactions and roles | no `SET ROLE`, serializable isolation only | The lab oracles cannot run, so there is no lab scenario for Redshift. |

`test/corpus/compat-redshift.suite.yaml` pins this behavior. It has 71 cases:

- 45 Redshift-only statements, all denied (fail closed) with the codes above.
- 26 common analytics queries written in SQL that is valid on both PostgreSQL 17
  and Redshift. They are allowed with the usual tenant proof and
  `bind_params`.

`lab/compat/run.sh redshift` runs the suite, and so does the workflow's
`redshift` job.

What this does **not** show:

- That HaltSQL's semantics match Redshift's. The portable cases were checked
  against the PG17 grammar and the policy, not run on a Redshift cluster.
- That `haltsql-proxy` works in front of Redshift. Its authentication methods
  and protocol details were not tested.

Do not rely on HaltSQL as a security control for Redshift.
