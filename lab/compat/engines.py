"""Per-engine install hooks for Postgres flavours (docs/compatibility.md).

A scenario selects an engine with ``environment.engine``. The harness installs
the fixture exactly as on stock Postgres and then calls the engine's hooks:

* ``prepare(conn)`` runs in the fresh lab database before the fixture schema
  (for example ``CREATE EXTENSION``).
* ``after_load(conn, schemas)`` runs after the data is loaded and analyzed, so
  the generators have already seen the unchanged catalog (foreign keys, primary
  keys). Engines use it to convert the fixture into their native storage:
  Citus distributes the tenant tables, TimescaleDB turns time-keyed tables into
  hypertables. Row-level security, ownership and column grants are kept, so
  the oracles judge the converted tables.

Engines without hooks (stock Postgres 18, Supabase, AlloyDB Omni and every
managed cloud service) run the fixture unchanged: the point there is that the
same SQL, roles and RLS policies behave identically.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Sequence

Hook = Callable[[Any, Sequence[str]], list[str]]  # returns a list of notes for the report


def _ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _qualified(schema: str, table: str) -> str:
    return f"{_ident(schema)}.{_ident(table)}"


def _tables(conn: Any, schemas: Sequence[str]) -> list[tuple[str, str, bool]]:
    """(schema, table, rls_enabled) for ordinary tables in the fixture schemas."""
    rows = conn.execute(
        "SELECT n.nspname, c.relname, c.relrowsecurity FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE c.relkind = 'r' AND n.nspname = ANY(%s) ORDER BY 1, 2", (list(schemas),)).fetchall()
    return [(r[0], r[1], bool(r[2])) for r in rows]


def _single_pk(conn: Any, schema: str, table: str) -> str | None:
    rows = conn.execute(
        "SELECT a.attname FROM pg_index i JOIN pg_attribute a "
        "ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
        "WHERE i.indrelid = %s::regclass AND i.indisprimary", (_qualified(schema, table),)).fetchall()
    return rows[0][0] if len(rows) == 1 else None


# ------------------------------------------------------------------ citus ---

def citus_prepare(conn: Any, _schemas: Sequence[str]) -> list[str]:
    conn.execute("CREATE EXTENSION IF NOT EXISTS citus")
    v = conn.execute("SELECT extversion FROM pg_extension WHERE extname = 'citus'").fetchone()[0]
    return [f"citus {v}, single node (shards on the coordinator)"]


def _foreign_keys(conn: Any, schemas: Sequence[str]) -> list[tuple[str, str, str]]:
    """(table, constraint name, definition) for every foreign key in the fixture schemas."""
    rows = conn.execute(
        "SELECT k.conrelid::regclass::text, k.conname, pg_get_constraintdef(k.oid) FROM pg_constraint k "
        "JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE k.contype = 'f' AND n.nspname = ANY(%s) ORDER BY 1, 2", (list(schemas),)).fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


def citus_after_load(conn: Any, schemas: Sequence[str]) -> list[str]:
    """Tenant tables (RLS enabled) become co-located single-shard distributed
    tables (``create_distributed_table(t, NULL)``, the building block of Citus
    schema-based sharding); global tables become reference tables. Foreign
    keys, primary keys, RLS, ownership and column grants are kept.

    Why not hash distribution: the fixtures allow NULL tenant ids on purpose
    (Citus refuses NULL distribution keys), and multi-shard queries and
    repartition joins run over extra connections that do not carry the
    harness's ``SET LOCAL ROLE`` and ``app.*`` settings, so the RLS and column
    oracles could not judge them. Single-shard co-located tables are planned by
    the Citus router planner and executed in the harness's own backend.
    """
    # Citus cannot distribute a table while plain tables reference it, so the
    # foreign keys are dropped, every table converted, and the keys restored.
    fks = _foreign_keys(conn, schemas)
    for table, name, _ in fks:
        conn.execute(f"ALTER TABLE {table} DROP CONSTRAINT {_ident(name)}")
    distributed, reference, first = [], [], None
    for schema, table, rls in _tables(conn, schemas):
        q = _qualified(schema, table)
        if rls:
            conn.execute("SELECT create_distributed_table(%s, NULL, colocate_with => %s)", (q, first or "none"))
            first = first or q
            distributed.append(f"{schema}.{table}")
        else:
            conn.execute("SELECT create_reference_table(%s)", (q,))
            reference.append(f"{schema}.{table}")
        # The shell table keeps the copy of the data that was moved into the shard; drop it.
        conn.execute("SELECT truncate_local_data_after_distributing_table(%s)", (q,))
    for table, name, definition in fks:
        conn.execute(f"ALTER TABLE {table} ADD CONSTRAINT {_ident(name)} {definition}")
    return [f"single-shard distributed (co-located): {', '.join(distributed)}",
            f"reference: {', '.join(reference) or '-'}",
            f"{len(fks)} foreign keys restored"]


# ------------------------------------------------------------ timescaledb ---

def timescale_prepare(conn: Any, _schemas: Sequence[str]) -> list[str]:
    conn.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")
    v = conn.execute("SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'").fetchone()[0]
    return [f"timescaledb {v}"]


def timescale_after_load(conn: Any, schemas: Sequence[str]) -> list[str]:
    """Tenant tables with a NOT NULL ``created_at timestamptz``, a single-column
    primary key and no incoming foreign keys become hypertables (data
    migrated). The primary key is widened to include the time column, which
    TimescaleDB requires; nothing else changes (RLS, owner, grants)."""
    converted = []
    for schema, table, rls in _tables(conn, schemas):
        if not rls:
            continue
        q = _qualified(schema, table)
        col = conn.execute(
            "SELECT 1 FROM pg_attribute WHERE attrelid = %s::regclass AND attname = 'created_at' "
            "AND atttypid = 'timestamptz'::regtype AND attnotnull AND NOT attisdropped", (q,)).fetchone()
        incoming = conn.execute(
            "SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND confrelid = %s::regclass",
            (q,)).fetchone()[0]
        pk = _single_pk(conn, schema, table)
        if col is None or incoming or pk is None:
            continue
        pkname = conn.execute(
            "SELECT conname FROM pg_constraint WHERE conrelid = %s::regclass AND contype = 'p'",
            (q,)).fetchone()[0]
        conn.execute(f"ALTER TABLE {q} DROP CONSTRAINT {_ident(pkname)}")
        conn.execute(f"ALTER TABLE {q} ADD PRIMARY KEY ({_ident(pk)}, created_at)")
        conn.execute("SELECT create_hypertable(%s::regclass, by_range('created_at', INTERVAL '30 days'), "
                     "migrate_data => true)", (q,))
        chunks = conn.execute("SELECT count(*) FROM show_chunks(%s::regclass)", (q,)).fetchone()[0]
        converted.append(f"{schema}.{table} ({chunks} chunks)")
    if not converted:
        raise RuntimeError("timescaledb: no table qualified as a hypertable")
    return [f"hypertables: {', '.join(converted)}"]


# --------------------------------------------------------------- registry ---

@dataclass(frozen=True)
class Engine:
    name: str
    description: str
    prepare: Hook | None = None
    after_load: Hook | None = None
    cloud: bool = False  # reachable only through an explicit DSN (HALTLAB_DSN)
    # Settings the engine itself changes while planning; the side-effect oracle
    # does not attribute them to the query.
    ignored_settings: tuple[str, ...] = ()

    def check_dsn(self, dsn: str | None) -> None:
        """A cloud engine without a DSN would silently fall back to the local lab
        server and report results for the wrong engine; refuse instead."""
        if self.cloud and not dsn:
            raise ValueError(f"engine {self.name} is a managed service: set HALTLAB_DSN to its admin DSN")


ENGINES: dict[str, Engine] = {e.name: e for e in [
    Engine("postgres", "stock PostgreSQL"),
    Engine("supabase", "Supabase Postgres (connects as the non-superuser `postgres` role)"),
    Engine("alloydb-omni", "AlloyDB Omni"),
    Engine("citus", "Citus (single node): tenant tables as co-located single-shard distributed tables, "
           "global tables as reference tables",
           citus_prepare, citus_after_load,
           # Citus changes these itself (source: session) inside the transaction:
           # enable_self_join_elimination while planning any distributed query,
           # citus.enable_local_execution while running EXPLAIN. ROLLBACK TO
           # SAVEPOINT restores both. Queries cannot reach either through
           # HaltSQL (SET and set_config are denied), and every other setting
           # is still compared.
           ignored_settings=("enable_self_join_elimination", "citus.enable_local_execution")),
    Engine("timescaledb", "TimescaleDB: time-keyed tenant tables as hypertables",
           timescale_prepare, timescale_after_load),
    # Managed services: the fixture runs unchanged.
    Engine("aurora-postgresql", "Amazon Aurora PostgreSQL", cloud=True),
    Engine("neon", "Neon", cloud=True),
    Engine("supabase-cloud", "Supabase (hosted)", cloud=True),
    Engine("alloydb", "Google AlloyDB for PostgreSQL", cloud=True),
]}


def get_engine(name: str | None) -> Engine:
    if name is None:
        return ENGINES["postgres"]
    try:
        return ENGINES[name]
    except KeyError:
        raise ValueError(f"unknown engine {name!r}; known: {sorted(ENGINES)}") from None
