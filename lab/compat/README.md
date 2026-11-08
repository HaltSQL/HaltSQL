# haltlab: Postgres flavour compatibility

Runs the `pr-smoke` workload against Postgres flavours and managed services.
Results and the method are in [docs/compatibility.md](../../docs/compatibility.md).

```bash
cd lab && make venv
compat/run.sh up                 # PostgreSQL 18, Supabase, AlloyDB Omni, Citus, TimescaleDB
compat/run.sh local all          # or: compat/run.sh local citus timescaledb
compat/run.sh table              # Markdown table from out/compat/*.json
compat/run.sh down

HALTLAB_DSN='postgresql://admin:...@host:5432/postgres?sslmode=require' \
  compat/run.sh cloud neon       # aurora-postgresql | neon | supabase-cloud | alloydb
compat/run.sh redshift           # offline grammar suite, no cluster

.venv/bin/python -m pytest compat/test_compat.py                  # unit tests
.venv/bin/python -m pytest -m integration compat/test_compat.py   # needs `compat/run.sh up`
```

Each engine run (`python -m compat run scenarios/compat-<engine>.yaml`) has
three parts:

1. **Oracle self-test**: the workload with the allow-everything stand-in
   verifier. The oracles must catch tenant escapes, column leaks and side
   effects on that engine, otherwise a clean HaltSQL result there proves nothing.
2. **HaltSQL**: the same workload with `haltsql verify --batch`; every allowed
   query is executed under the oracles (zero escapes, side effects and column
   leaks required).
3. **Proxy parity**: the workload through a live `haltsql-proxy`
   ([../proxy](../proxy/README.md)), upstream = the engine.

| Engine | Compose service | Port | Install hook (`engines.py`) |
|---|---|---|---|
| PostgreSQL 18 | `compat-pg18` (`postgres:18.4-alpine`) | 55418 | none |
| Supabase Postgres | `compat-supabase` (`supabase/postgres:17.11.0.018`) | 55419 | none; the lab connects as Supabase's non-superuser `postgres` role |
| AlloyDB Omni | `compat-alloydb-omni` (`google/alloydbomni:17.10.0`) | 55420 | none |
| Citus | `compat-citus` (`citusdata/citus:14.2.0-alpine`, amd64 only) | 55421 | tenant tables become co-located single-shard distributed tables, `currencies` a reference table; FKs restored |
| TimescaleDB | `compat-timescaledb` (`timescale/timescaledb:2.31.0-pg17`) | 55422 | `audit_events` and `orgs` become hypertables (data migrated) |

Hooks run after the data is loaded, so the generators see the same catalog as
on stock Postgres. RLS, ownership and column grants are kept, and the oracles
judge the converted tables. Engine-owned settings the side-effect oracle
ignores are listed per engine (`ignored_settings`; only Citus has any).

Cloud scenarios carry no DSN: `HALTLAB_DSN` must be set, and a cloud engine
refuses to run without it instead of falling back to the local lab server. The
proxy's upstream TLS follows the DSN's `sslmode` (`require`, or `verify-full`
with `sslrootcert=FILE`; `verify-ca` is upgraded to `verify-full`; `prefer` and
`allow` are refused).
