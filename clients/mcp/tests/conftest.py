"""Fixtures for haltsql-mcp tests: fake sidecar, lab Postgres, repo paths."""

from __future__ import annotations

import os
import uuid
from typing import Iterator

import pytest

from haltsql.testing import FakeSidecar, make_verdict_dict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SAAS_POLICY = os.path.join(ROOT, "test", "fixtures", "policies", "saas.yaml")
PG_ADMIN = os.environ.get(
    "HALTSQL_TEST_PG_ADMIN", "host=127.0.0.1 port=5417 user=postgres password="
    + os.environ.get("HALTSQL_PGPASSWORD", "haltlab") + " dbname=postgres"
)


def haltsql_bin():
    p = os.environ.get("HALTSQL_BIN") or os.path.join(
        ROOT, "_build", "default", "bin", "haltsql", "main.exe")
    return p if os.path.isfile(p) else None


def decide(sql, ctx, _policy):
    """Allows SQL containing 'tenant_id = $1' (binding ctx.tenant_id); denies the rest."""
    if "tenant_id = $1" in sql:
        return make_verdict_dict(sql, allowed=True, bind=[ctx.get("tenant_id", "")], policy="saas")
    return make_verdict_dict(sql, allowed=False, codes=["E_TENANT_MISSING"], policy="saas")


@pytest.fixture
def fake_sidecar() -> Iterator[FakeSidecar]:
    with FakeSidecar(decide, token="sidecar-token",
                     policies=[{"name": "saas", "version": "sha256:" + "a" * 64, "mode": "enforce"}]) as f:
        yield f


@pytest.fixture(scope="session")
def pg_dsn() -> Iterator[str]:
    psycopg = pytest.importorskip("psycopg", exc_type=ImportError)
    try:
        admin = psycopg.connect(PG_ADMIN, autocommit=True, connect_timeout=2)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"lab Postgres not reachable (make -C lab up): {type(e).__name__}")
    name = f"haltsql_python_mcp_{uuid.uuid4().hex[:10]}"
    admin.execute(f'CREATE DATABASE "{name}"')
    dsn = PG_ADMIN.replace("dbname=postgres", f"dbname={name}")
    try:
        with psycopg.connect(dsn, autocommit=True) as c:
            c.execute(
                """
                CREATE SCHEMA app;
                CREATE TABLE app.orders (id int8 PRIMARY KEY, tenant_id text NOT NULL,
                  customer_id int8, status text, total_cents numeric(12,2), currency text,
                  created_at timestamptz DEFAULT '2026-01-02T03:04:05Z', updated_at timestamptz);
                INSERT INTO app.orders (id, tenant_id, customer_id, status, total_cents, currency)
                  SELECT g, CASE WHEN g <= 6 THEN 'acme' ELSE 'globex' END, g, 'open', g * 1.5, 'USD'
                  FROM generate_series(1, 10) g;
                """
            )
            c.execute(f'ALTER DATABASE "{name}" SET search_path = app, public')
        yield dsn
    finally:
        admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        admin.close()
