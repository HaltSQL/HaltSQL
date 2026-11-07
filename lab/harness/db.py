"""Disposable lab databases: create, install a fixture schema, load data."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg

from common.fixtures import Fixture
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


def db_name(scenario: str, version: int) -> str:
    return re.sub(r"[^a-z0-9_]", "_", f"haltlab_{scenario.lower()}_pg{version}")[:63]


@dataclass
class LabDatabase:
    dsn: str
    catalog: list[TableInfo]
    universe: Universe
    dataset: Dataset
    server_version: str


def create_database(admin: str, name: str) -> str:
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        conn.execute(f'CREATE DATABASE "{name}"')
    return with_dbname(admin, name)


def drop_database(admin: str, name: str) -> None:
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def install(dsn: str, fixture: Fixture, policy: LabPolicy, data: dict[str, Any]) -> LabDatabase:
    if fixture.schema_sql is None:
        raise ValueError(f"fixture {fixture.name} has no schema SQL (generated fixtures must be materialized)")
    cfg = DataConfig.from_scenario(data)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(Path(fixture.schema_sql).read_text(encoding="utf-8"))  # simple protocol: multi-statement OK
        server_version = conn.execute("SHOW server_version").fetchone()[0]
    with psycopg.connect(dsn) as conn:
        catalog = topo_sort(introspect(conn, policy.schemas))
        universe = build_universe(fixture.model, policy.keys, cfg.tenants, cfg.skew, cfg.edge_cases)
        dataset = generate(catalog, policy, universe, cfg, fixture.unit_tables, fixture.column_roles)
        load(conn, dataset)
        conn.execute("ANALYZE")
        conn.commit()
    return LabDatabase(dsn, catalog, universe, dataset, server_version)
