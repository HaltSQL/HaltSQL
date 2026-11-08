"""Scenario: the HaltSQL query tool of three agent frameworks (OpenAI Agents
SDK, LangGraph, Google ADK), called through each framework's own tool-call
machinery, verifying with a real haltsql-server and running on the stack's
Postgres 17. No LLM: each call is handed to the framework the way a model
turn carries it (agents/drive_tool.py, run in the framework's own virtualenv,
because the frameworks' dependency pins conflict).

For each framework:

* an allowed query returns the rows of the tenant in the trusted application
  state (acme, then globex: the tenant never comes from the model);
* cross-tenant queries (a literal tenant, an OR that escapes the tenant
  filter) are denied with the HaltSQL reason codes and `executed: false`;
* a call without a trusted context is refused before verification;
* Postgres saw exactly the allowed statements, with the tenant bound as a
  parameter, and never the denied ones (log_statement = all for the tool's
  role only, read back from the Postgres container);
* the server's audit file has one record per verification with the verdict
  the tool got, and `haltsql audit verify` passes on it.

Ports: 17072-17074. Resources: database haltsql_e2e_*, role audit_proxy_agents_*.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import pytest

from conftest import (
    E2E_DIR,
    REPO,
    Cli,
    Postgres,
    Processes,
    container,
    docker,
    new_token,
    sha256_hex,
    unavailable,
    wait_until,
)

PORTS = {"openai_agents": 17072, "langgraph": 17073, "google_adk": 17074}
POLICY = REPO / "test" / "fixtures" / "policies" / "saas.yaml"
DRIVER = E2E_DIR / "agents" / "drive_tool.py"
GENESIS = "0" * 64

SETUP = """
CREATE SCHEMA app;
CREATE TABLE app.orders (id int8 PRIMARY KEY, tenant_id text NOT NULL, customer_id int8,
  status text, total_cents int8, currency text, created_at timestamptz DEFAULT now(),
  updated_at timestamptz);
INSERT INTO app.orders (id, tenant_id, customer_id, status, total_cents, currency) VALUES
  (1, 'acme', 10, 'open', 1250, 'USD'), (2, 'globex', 11, 'open', 990, 'EUR'),
  (3, 'acme', 12, 'paid', 4200, 'USD'), (4, 'globex', 13, 'paid', 100, 'EUR');
"""


def framework_python(framework: str) -> Path:
    py = E2E_DIR / ".venv-agents" / framework / "bin" / "python"
    if not py.is_file():
        unavailable(f"{py} is missing: create the agent-framework virtualenvs with "
                    f"`test/e2e/stack.sh venv`")
    return py


@pytest.fixture
def agent_role(postgres: Postgres, pg_database: str) -> Iterator[tuple[str, str]]:
    """A read-only login role for the tool's connections (unique name,
    dropped afterwards). Postgres logs every statement of this role."""
    from psycopg import sql

    role = f"audit_proxy_agents_{secrets.token_hex(5)}"
    password = secrets.token_hex(16)
    with postgres.connect(pg_database) as c:
        c.execute(SETUP)
        c.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
            sql.Identifier(role), sql.Literal(password)))
        c.execute(sql.SQL("GRANT USAGE ON SCHEMA app TO {}").format(sql.Identifier(role)))
        c.execute(sql.SQL("GRANT SELECT ON app.orders TO {}").format(sql.Identifier(role)))
        c.execute(sql.SQL("ALTER ROLE {} SET log_statement = 'all'").format(sql.Identifier(role)))
    try:
        yield role, password
    finally:
        with postgres.connect("postgres") as c:
            c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(
                sql.Identifier(pg_database)))
            c.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


def server_config(port: int, token: str, audit: Path) -> str:
    return f"""apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:{port}
  auth:
    tokens:
      - {{ name: agents, token_sha256: {sha256_hex(token)}, policy: saas }}
policies:
  - path: {POLICY}
audit:
  sinks:
    - {{ type: file, path: {audit} }}
"""


@pytest.mark.parametrize("framework", list(PORTS))
def test_agent_tool_through_framework(framework: str, cli: Cli, processes: Processes,
                                      postgres: Postgres, pg_database: str,
                                      agent_role: tuple[str, str], tmp_path: Path) -> None:
    py = framework_python(framework)
    role, password = agent_role
    port = PORTS[framework]
    token = new_token()
    audit = tmp_path / "audit.jsonl"
    server = processes.server(server_config(port, token, audit), port)
    since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    m = 5_000_000 + secrets.randbelow(1_000_000)

    acme, globex = {"tenant_id": "acme"}, {"tenant_id": "globex"}
    q_ok = f"SELECT id, status FROM orders WHERE tenant_id = $1 AND id > -{m} ORDER BY id LIMIT 10"
    q_literal = f"SELECT id, status FROM orders WHERE tenant_id = 'globex' AND id > -{m + 1} LIMIT 10"
    q_or = (f"SELECT id, status FROM orders WHERE tenant_id = $1 OR tenant_id = 'globex' "
            f"AND id > -{m + 2} LIMIT 10")
    q_noctx = f"SELECT id, status FROM orders WHERE tenant_id = $1 AND id > -{m + 3} LIMIT 10"
    calls = [
        {"query": q_ok, "context": acme},
        {"query": q_ok, "context": globex},
        {"query": q_literal, "context": acme},
        {"query": q_or, "context": acme},
        {"query": q_noctx, "context": None},
    ]
    job = {"server_url": server.base, "token": token,
           "dsn": (f"host=127.0.0.1 port={postgres.port} dbname={pg_database} user={role} "
                   f"password={password} options=-csearch_path=app"),
           "calls": calls}
    env = {k: v for k, v in os.environ.items() if not k.startswith("HALTSQL_E2E")}
    p = subprocess.run([str(py), "-I", str(DRIVER), framework], input=json.dumps(job),
                       capture_output=True, text=True, timeout=300, env=env)
    assert p.returncode == 0, f"drive_tool.py {framework} exited {p.returncode}:\n{p.stderr[-4000:]}"
    out = json.loads(p.stdout)
    assert out["framework"] == framework
    ok_acme, ok_globex, literal, escape, noctx = out["results"]

    # Allowed: rows of the tenant from the trusted application state.
    assert ok_acme["status"] == "ok" and ok_acme["executed"] is True, ok_acme
    assert ok_acme["rows"] == [[1, "open"], [3, "paid"]], ok_acme
    assert ok_globex["status"] == "ok" and ok_globex["rows"] == [[2, "open"], [4, "paid"]], ok_globex

    # Cross-tenant: denied, with reason codes, never executed.
    for res in (literal, escape):
        assert res["status"] == "denied" and res["executed"] is False, res
        assert "rows" not in res
    assert [r["code"] for r in literal["reasons"]] == ["E_TENANT_MISMATCH"], literal
    assert [r["code"] for r in escape["reasons"]] == ["E_TENANT_MISSING", "E_PARAM_UNBOUND"], escape

    # No trusted context: refused before anything was verified or run.
    assert noctx["status"] == "error" and noctx["executed"] is False, noctx
    assert "No trusted HaltSQL context" in noctx["message"], noctx

    # ---- what Postgres saw ----
    log = wait_until("the allowed statements in the Postgres log",
                     lambda: (t := pg_log(since)) and t.count(f"> -{m} ORDER BY") >= 2 and t,
                     timeout=20)
    lines = log.splitlines()
    executes = [i for i, line in enumerate(lines) if f"> -{m} ORDER BY" in line and "execute" in line]
    assert len(executes) == 2, [lines[i] for i in executes]
    assert [lines[i + 1].split("DETAIL:  ", 1)[-1] for i in executes] == [
        "Parameters: $1 = 'acme'", "Parameters: $1 = 'globex'"]
    for denied in (m + 1, m + 2, m + 3):
        assert f"-{denied}" not in log, f"denied statement {denied} reached Postgres"
    with postgres.connect(pg_database) as c:
        assert c.execute("SELECT count(*) FROM app.orders").fetchone() == (4,)

    # ---- what the server audited ----
    server.stop()
    recs = [json.loads(line) for line in audit.read_text().splitlines()]
    assert [(r["sql_sha256"], r["allowed"]) for r in recs] == [
        (sha256_hex(q_ok), True), (sha256_hex(q_ok), True),
        (sha256_hex(q_literal), False), (sha256_hex(q_or), False)]
    assert all(r["caller"] == "agents" and r["policy"] == "saas" for r in recs)
    assert recs[2]["codes"] == ["E_TENANT_MISMATCH"]
    assert recs[3]["codes"] == ["E_TENANT_MISSING", "E_PARAM_UNBOUND"]
    assert recs[0]["prev_hash"] == GENESIS
    c = cli.run("audit", "verify", "--json", "--expect-head", recs[-1]["hash"], audit, check=False)
    rep = json.loads(c.stdout)
    assert c.returncode == 0 and rep["ok"] is True and rep["records"] == 4, rep


def pg_log(since: str) -> str:
    p = docker("logs", "--since", since, container("postgres"))
    return p.stdout + p.stderr


