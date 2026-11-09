"""Shared fixtures: repo paths, the real haltsql binaries, the lab Postgres."""

from __future__ import annotations

import glob
import json
import os
import socket
import subprocess
import time
import uuid
from typing import Any, Dict, Iterator, List, Optional

import httpx
import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
VECTORS_DIR = os.path.join(ROOT, "clients", "testvectors", "cases")
POLICIES_DIR = os.path.join(ROOT, "test", "fixtures", "policies")


def _bin(env: str, *rel: str) -> Optional[str]:
    path = os.environ.get(env) or os.path.join(ROOT, *rel)
    return path if os.path.isfile(path) and os.access(path, os.X_OK) else None


def haltsql_bin() -> Optional[str]:
    return _bin("HALTSQL_BIN", "_build", "default", "bin", "haltsql", "main.exe")


def server_bin() -> Optional[str]:
    return _bin("HALTSQL_SERVER_BIN", "_build", "default", "bin", "server", "main.exe")


def native_lib() -> Optional[str]:
    """libhaltsql for the native tests: $HALTSQL_LIB or the dune build output."""
    path = os.environ.get("HALTSQL_LIB") or os.path.join(
        ROOT, "_build", "default", "native", "libhaltsql.so"
    )
    return path if os.path.isfile(path) else None


def require_native() -> bool:
    """CI sets HALTSQL_REQUIRE_NATIVE=1: a missing engine then fails instead of skipping."""
    return os.environ.get("HALTSQL_REQUIRE_NATIVE", "") not in ("", "0")


def skip_or_fail(reason: str) -> None:
    if require_native():
        pytest.fail(f"{reason} (HALTSQL_REQUIRE_NATIVE=1)")
    pytest.skip(reason)


@pytest.fixture(scope="session")
def native_lib_path() -> str:
    p = native_lib()
    if p is None:
        skip_or_fail("libhaltsql not built (dune build native/libhaltsql.so) and HALTSQL_LIB not set")
    return p  # type: ignore[return-value]


@pytest.fixture(scope="session")
def native_bin_path() -> str:
    b = haltsql_bin()
    if b is None:
        skip_or_fail("haltsql CLI not built (dune build ./bin/haltsql/main.exe) and HALTSQL_BIN not set")
    return b  # type: ignore[return-value]


@pytest.fixture
def native_env(monkeypatch, native_lib_path, native_bin_path):
    """Point NativeVerifier at the built engine; clear HALTSQL_NATIVE."""
    monkeypatch.setenv("HALTSQL_LIB", native_lib_path)
    monkeypatch.setenv("HALTSQL_BIN", native_bin_path)
    monkeypatch.delenv("HALTSQL_NATIVE", raising=False)
    return {"lib": native_lib_path, "bin": native_bin_path}


def load_vectors() -> List[Dict[str, Any]]:
    out = []
    for path in sorted(glob.glob(os.path.join(VECTORS_DIR, "*.json"))):
        with open(path, encoding="utf-8") as f:
            out.append(json.load(f))
    return out


@pytest.fixture(scope="session")
def haltsql_cli() -> str:
    b = haltsql_bin()
    if b is None:
        pytest.skip("haltsql CLI not built (dune build ./bin/haltsql/main.exe) "
                    "and HALTSQL_BIN not set")
    return b


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def real_server() -> Iterator[str]:
    """A real haltsql-server with every fixture policy used by the vectors."""
    b = server_bin()
    if b is None:
        pytest.skip("haltsql-server not built and HALTSQL_SERVER_BIN not set")
    files = sorted({v["policy_file"] for v in load_vectors()})
    port = free_port()
    argv = [b, "--listen", f"127.0.0.1:{port}", "--allow-unauthenticated",
            "--audit", "none", "--no-watch", "--log-level", "error"]
    for f in files:
        argv += ["--policy", os.path.join(ROOT, f)]
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 15
        while True:
            if proc.poll() is not None:
                err = proc.stderr.read().decode() if proc.stderr else ""
                pytest.fail(f"haltsql-server exited early ({proc.returncode}): {err[:500]}")
            try:
                if httpx.get(url + "/readyz", timeout=0.5).status_code == 200:
                    break
            except httpx.TransportError:
                pass
            if time.time() > deadline:
                pytest.fail("haltsql-server did not become ready")
            time.sleep(0.05)
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()


PG_DSN_ADMIN = os.environ.get(
    "HALTSQL_TEST_PG_ADMIN", "host=127.0.0.1 port=5417 user=postgres password="
    + os.environ.get("HALTSQL_PGPASSWORD", "haltlab") + " dbname=postgres"
)


@pytest.fixture(scope="session")
def pg_dsn() -> Iterator[str]:
    """A fresh database haltsql_python_<random> on the lab Postgres (dropped afterwards)."""
    psycopg = pytest.importorskip("psycopg", exc_type=ImportError)
    try:
        admin = psycopg.connect(PG_DSN_ADMIN, autocommit=True, connect_timeout=2)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"lab Postgres not reachable (make -C lab up): {type(e).__name__}")
    name = f"haltsql_python_{uuid.uuid4().hex[:10]}"
    admin.execute(f'CREATE DATABASE "{name}"')
    dsn = PG_DSN_ADMIN.replace("dbname=postgres", f"dbname={name}")
    try:
        with psycopg.connect(dsn, autocommit=True) as c:
            c.execute(
                """
                CREATE SCHEMA app;
                CREATE TABLE app.orders (id int8 PRIMARY KEY, tenant_id text NOT NULL,
                  customer_id int8, status text, total_cents int8, currency text,
                  created_at timestamptz DEFAULT now(), updated_at timestamptz);
                CREATE TABLE app.accounts (id int8 PRIMARY KEY, tenant_id text NOT NULL,
                  name text, balance_cents int8, opened_at timestamptz);
                INSERT INTO app.orders (id, tenant_id, customer_id, status, total_cents, currency)
                  SELECT g, CASE WHEN g % 2 = 0 THEN 'acme' ELSE 'globex' END, g, 'open', g * 100, 'USD'
                  FROM generate_series(1, 20) g;
                INSERT INTO app.accounts (id, tenant_id, name, balance_cents)
                  VALUES (1, 'acme', 'a', 1), (2, 'acme-eu', 'b', 2), (3, 'globex', 'c', 3);
                ALTER DATABASE "{db}" SET search_path = app, public;
                """.replace("{db}", name)
            )
        yield dsn
    finally:
        admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        admin.close()
