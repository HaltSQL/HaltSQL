"""Disposable lab databases: create, install a fixture schema, load data."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psycopg

from common.fixtures import Fixture
from common.ident import qi, qname
from compat.engines import get_engine
from common.policy import LabPolicy
from common.tenancy import Universe, build_universe
from datagen.catalog import TableInfo, introspect, topo_sort
from datagen.generate import DataConfig, Dataset, generate, load

# docker-compose.yml publishes Postgres N on port 54NN (e.g. 17 -> 5417).
DEFAULT_ADMIN_DSN = "postgresql://postgres:haltlab@localhost:{port}/postgres"


def admin_dsn(version: int, override: str | None) -> str:
    if override:
        return override.replace("{version}", str(version)).replace("{port}", str(5400 + version))
    return DEFAULT_ADMIN_DSN.format(port=5400 + version)


def with_dbname(dsn: str, dbname: str) -> str:
    info = psycopg.conninfo.conninfo_to_dict(dsn)
    info["dbname"] = dbname
    return psycopg.conninfo.make_conninfo(**info)


def db_name(scenario: str, version: int, run_id: str | None = None) -> str:
    """``run_id`` makes the name unique when several runs share one server."""
    base = f"haltlab_{scenario.lower()}" + (f"_{run_id.lower()}" if run_id else "")
    suffix = f"_pg{version}"
    return re.sub(r"[^a-z0-9_]", "_", base[:63 - len(suffix)] + suffix)


@dataclass
class LabDatabase:
    dsn: str
    catalog: list[TableInfo]
    universe: Universe
    dataset: Dataset
    server_version: str
    engine_notes: list[str] = field(default_factory=list)  # what an engine hook changed (lab/compat)


def create_database(admin: str, name: str) -> str:
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        conn.execute(f'CREATE DATABASE "{name}"')
    return with_dbname(admin, name)


def drop_database(admin: str, name: str) -> None:
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def install(dsn: str, fixture: Fixture, policy: LabPolicy, data: dict[str, Any],
            engine: str | None = None) -> LabDatabase:
    """``engine`` names a Postgres flavour with install hooks (lab/compat/engines.py)."""
    if fixture.schema_sql is None:
        raise ValueError(f"fixture {fixture.name} has no schema SQL (generated fixtures must be materialized)")
    cfg = DataConfig.from_scenario(data)
    eng = get_engine(engine)
    notes: list[str] = []
    with psycopg.connect(dsn, autocommit=True) as conn:
        if eng.prepare is not None:
            notes += eng.prepare(conn, policy.schemas)
        conn.execute(Path(fixture.schema_sql).read_text(encoding="utf-8"))  # simple protocol: multi-statement OK
        server_version = conn.execute("SHOW server_version").fetchone()[0]
    with psycopg.connect(dsn) as conn:
        catalog = topo_sort(introspect(conn, policy.schemas))
        universe = build_universe(fixture.model, policy.keys, cfg.tenants, cfg.skew, cfg.edge_cases)
        dataset = generate(catalog, policy, universe, cfg, fixture.unit_tables, fixture.column_roles)
        load(conn, dataset)
        conn.execute("ANALYZE")
        conn.commit()
    if eng.after_load is not None:
        with psycopg.connect(dsn, autocommit=True) as conn:
            notes += eng.after_load(conn, policy.schemas)
            conn.execute("ANALYZE")
    return LabDatabase(dsn, catalog, universe, dataset, server_version, notes)


COLS_ROLE = "haltlab_cols"


def column_grant_statements(policy: LabPolicy, catalog: list[TableInfo]) -> list[str]:
    """SQL that gives ``haltlab_cols`` SELECT on exactly ``policy``'s allowed columns.

    Fixture SQL grants the fixture's own policy statically. A run judged
    against another policy (``--oracle-policy``/``--policy``, e.g. one drafted
    from a data catalog) re-applies the grants from that policy, so the
    column-privilege oracle uses the same ground truth as the honeytokens.
    Relations the policy omits get no grant at all; policy columns that do not
    exist in the database are skipped.
    """
    stmts: list[str] = []
    for schema in policy.schemas:
        stmts.append(f"REVOKE ALL ON ALL TABLES IN SCHEMA {qi(schema)} FROM {COLS_ROLE}")
        stmts.append(f"GRANT USAGE ON SCHEMA {qi(schema)} TO {COLS_ROLE}")
    for t in catalog:
        pt = policy.table(t.schema, t.name)
        if pt is None:
            continue
        rel = qname(t.schema, t.name)
        if pt.columns is None:
            stmts.append(f"GRANT SELECT ON {rel} TO {COLS_ROLE}")
            continue
        cols = [c.name for c in t.columns if c.name in pt.columns]
        if cols:
            stmts.append(f"GRANT SELECT ({', '.join(qi(c) for c in cols)}) ON {rel} TO {COLS_ROLE}")
    return stmts


def apply_column_grants(dsn: str, policy: LabPolicy, catalog: list[TableInfo]) -> int:
    """Apply :func:`column_grant_statements`; returns the number of relations granted."""
    stmts = column_grant_statements(policy, catalog)
    with psycopg.connect(dsn, autocommit=True) as conn:
        for s in stmts:
            conn.execute(s)  # type: ignore[arg-type]
    return sum(1 for s in stmts if s.startswith("GRANT SELECT"))
