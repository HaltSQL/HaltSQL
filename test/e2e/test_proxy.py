"""Scenario: haltsql-proxy in front of the stack's Postgres 17, with a
hash-chained audit file.

A psycopg client connects to the proxy over TLS (verify-full against a CA
generated for this test) with SCRAM, and:

* allowed statements run on Postgres and return the client's tenant rows; the
  tenant bind parameter is overwritten by the proxy with the session's tenant,
  whatever the client sent;
* denied statements (a column outside the policy, a cross-tenant literal, a
  DELETE) come back as SQLSTATE 42501 with the HaltSQL reason codes, the
  connection stays usable, and Postgres never sees their text: the upstream
  role logs every statement (log_statement = all, set for that role only) and
  the server log is read back from the Postgres container;
* rewriting the policy and sending SIGHUP changes what new sessions may do,
  and a session opened before the reload is ended rather than left on the old
  policy;
* `haltsql audit verify` passes on the proxy's audit file, whose records
  match every statement the client sent, and fails once a record is edited.

Ports: 17071. Resources: database haltsql_e2e_*, role audit_proxy_agents_*.
"""

from __future__ import annotations

import json
import secrets
import signal
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import psycopg
import pytest

from conftest import (
    Cli,
    Postgres,
    Processes,
    Process,
    container,
    docker,
    sha256_hex,
    wait_until,
)

PROXY_PORT = 17071
GENESIS = "0" * 64

POLICY = """apiVersion: haltsql.dev/v1
kind: Policy
metadata: {{ name: proxy-shop }}
search_path: [app]
statements: {{ allow: [select] }}
tenancy:
  mode: bound
  keys: {{ tenant: "${{ctx.tenant_id}}" }}
tables:
  app.orders: {{ columns: [{columns}], tenant_column: tenant_id }}
mode: enforce
"""

SETUP = """
CREATE SCHEMA app;
CREATE TABLE app.orders (id int8 PRIMARY KEY, tenant_id text NOT NULL, status text,
                         total_cents int8);
INSERT INTO app.orders VALUES (1, 'acme', 'open', 1250), (2, 'globex', 'open', 990),
                              (3, 'acme', 'paid', 4200), (4, 'globex', 'paid', 100);
"""


def openssl(*args: str, cwd: Path) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True, timeout=60)


def make_tls(d: Path) -> tuple[Path, Path, Path]:
    """A throwaway CA and a server certificate for DNS:localhost (SAN only:
    hostname checks read DNS SubjectAltName entries)."""
    d.mkdir()
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", "ca.key", "-out", "ca.crt", "-days", "2", "-subj", "/CN=haltsql-e2e-ca",
            cwd=d)
    openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", "server.key", "-out", "server.csr", "-subj", "/O=haltsql-e2e", cwd=d)
    (d / "ext.cnf").write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
            "-CAcreateserial", "-out", "server.crt", "-days", "2", "-extfile", "ext.cnf", cwd=d)
    return d / "ca.crt", d / "server.crt", d / "server.key"


def proxy_config(*, upstream_db: str, upstream_user: str, policy: Path, verifier: str,
                 tls: tuple[Path, Path, Path], audit: Path) -> str:
    _, crt, key = tls
    return f"""apiVersion: haltsql.dev/v1
kind: ProxyConfig
listen: 127.0.0.1:{PROXY_PORT}
tls: {{ cert: {crt}, key: {key}, required: true }}
upstream:
  host: 127.0.0.1
  port: 17000
  database: {upstream_db}
  user: {upstream_user}
  password: ${{env:UPSTREAM_PASSWORD}}
policies:
  - path: {policy}
auth:
  method: scram
  users:
    - name: analyst
      scram_verifier: "{verifier}"
      policy: proxy-shop
      context: {{ tenant_id: acme }}
audit:
  sinks:
    - {{ type: file, path: {audit} }}
logging: {{ level: info }}
"""


@pytest.fixture
def upstream_role(postgres: Postgres, pg_database: str) -> Iterator[tuple[str, str]]:
    """A login role for the proxy (unique name, dropped afterwards) that may
    read AND delete app.orders: only the proxy stands between the client and
    a DELETE. Every statement of this role is written to the server log."""
    from psycopg import sql

    role = f"audit_proxy_agents_{secrets.token_hex(5)}"
    password = secrets.token_hex(16)
    with postgres.connect(pg_database) as c:
        c.execute(SETUP)
        c.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
            sql.Identifier(role), sql.Literal(password)))
        c.execute(sql.SQL("GRANT USAGE ON SCHEMA app TO {}").format(sql.Identifier(role)))
        c.execute(sql.SQL("GRANT SELECT, DELETE ON app.orders TO {}").format(sql.Identifier(role)))
        c.execute(sql.SQL("ALTER ROLE {} SET log_statement = 'all'").format(sql.Identifier(role)))
    try:
        yield role, password
    finally:
        with postgres.connect("postgres") as c:
            c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(
                sql.Identifier(pg_database)))
            c.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


def pg_server_log(since: str) -> str:
    p = docker("logs", "--since", since, container("postgres"))
    return p.stdout + p.stderr


def client_dsn(db: str, password: str, ca: Path) -> str:
    return (f"host=localhost hostaddr=127.0.0.1 port={PROXY_PORT} dbname={db} user=analyst "
            f"password={password} sslmode=verify-full sslrootcert={ca} connect_timeout=10")


def connect(dsn: str) -> Any:
    import psycopg

    return psycopg.connect(dsn, autocommit=True)


def expect_denied(conn: Any, sql: str, params: Any = None) -> Any:
    import psycopg

    with pytest.raises(psycopg.errors.InsufficientPrivilege) as ei:
        conn.execute(sql, params)
    diag = ei.value.diag
    assert diag.sqlstate == "42501"
    assert diag.message_primary.startswith('haltsql: query denied by policy "proxy-shop"'), diag.message_primary
    assert diag.message_detail.startswith("HaltSQL reasons: "), diag.message_detail
    # The connection stays usable after a denial.
    assert conn.execute("SELECT 1 AS one FROM app.orders WHERE tenant_id = %s LIMIT 1",
                        ["x"]).fetchone() == (1,)
    return diag.message_detail.removeprefix("HaltSQL reasons: ").split(", ")


def wait_listening(p: Process, timeout: float = 30.0) -> None:
    import socket

    def up() -> bool:
        assert p.alive(), f"haltsql-proxy exited {p.proc.returncode}:\n{p.log()}"
        with socket.socket() as s:
            s.settimeout(0.5)
            return s.connect_ex(("127.0.0.1", p.port)) == 0

    wait_until("haltsql-proxy listening", up, timeout=timeout, interval=0.2)


def log_events(p: Process, msg: str) -> list[dict[str, Any]]:
    out = []
    for line in p.log().splitlines():
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        if j.get("msg") == msg:
            out.append(j)
    return out


def test_proxy_enforces_policy_reloads_and_audits(cli: Cli, proxy_bin: Path, processes: Processes,
                                                  postgres: Postgres, pg_database: str, upstream_role: tuple[str, str],
                                                  tmp_path: Path) -> None:
    role, upstream_password = upstream_role
    since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    marker = 7_000_000 + secrets.randbelow(1_000_000)  # makes this run's statements unique
    tls = make_tls(tmp_path / "tls")
    client_password = secrets.token_hex(12)
    verifier = subprocess.run([str(proxy_bin), "scram-verifier"], input=client_password + "\n",
                              capture_output=True, text=True, check=True, timeout=30).stdout.strip()
    assert verifier.startswith("SCRAM-SHA-256$4096:")

    policy = tmp_path / "proxy-shop.yaml"
    policy.write_text(POLICY.format(columns="id, tenant_id, status"))
    audit = tmp_path / "proxy-audit.jsonl"
    cfg_text = proxy_config(upstream_db=pg_database, upstream_user=role, policy=policy,
                            verifier=verifier, tls=tls, audit=audit)
    cfg = tmp_path / "proxy.yaml"
    cfg.write_text(cfg_text)
    v = subprocess.run([str(proxy_bin), "validate", "--config", str(cfg), "--json"],
                       capture_output=True, text=True, timeout=30,
                       env={"UPSTREAM_PASSWORD": upstream_password, "PATH": "/usr/bin:/bin"})
    assert v.returncode == 0, v.stdout + v.stderr
    assert upstream_password not in v.stdout and client_password not in v.stdout

    proxy = processes.proxy(["run", "--config", str(cfg)], PROXY_PORT,
                            env={"UPSTREAM_PASSWORD": upstream_password})
    wait_listening(proxy)
    dsn = client_dsn(pg_database, client_password, tls[0])

    # (sql as Postgres receives it after psycopg's %s -> $n, allowed)
    sent: list[tuple[str, bool]] = []

    def pg_text(sql: str) -> str:
        n = 0
        while "%s" in sql:
            n += 1
            sql = sql.replace("%s", f"${n}", 1)
        return sql

    q_ok = f"SELECT id, status FROM app.orders WHERE tenant_id = %s AND id > -{marker} ORDER BY id"
    q_total = f"SELECT id, total_cents FROM app.orders WHERE tenant_id = %s AND id > -{marker + 1} ORDER BY id"
    q_cross = f"SELECT id, status FROM app.orders WHERE tenant_id = 'globex' AND id > -{marker + 2}"
    q_delete = f"DELETE FROM app.orders WHERE id > -{marker + 3}"
    q_probe = "SELECT 1 AS one FROM app.orders WHERE tenant_id = %s LIMIT 1"

    old_session = connect(dsn)
    with connect(dsn) as conn:
        # Allowed: the client asks for globex; the proxy binds the session's tenant.
        rows = conn.execute(q_ok, ["globex"]).fetchall()
        assert rows == [(1, "open"), (3, "paid")]
        sent.append((pg_text(q_ok), True))

        codes = expect_denied(conn, q_total, ["acme"])
        assert codes == ["E_COLUMN_DENIED"], codes
        sent += [(pg_text(q_total), False), (pg_text(q_probe), True)]

        codes = expect_denied(conn, q_cross)
        assert codes == ["E_TENANT_MISMATCH"], codes
        sent += [(q_cross, False), (pg_text(q_probe), True)]

        codes = expect_denied(conn, q_delete)
        assert codes[0] == "E_STATEMENT_KIND" and "E_WRITE_DENIED" in codes, codes
        sent += [(q_delete, False), (pg_text(q_probe), True)]

    # ---- SIGHUP: the policy now allows total_cents for new sessions ----
    policy.write_text(POLICY.format(columns="id, tenant_id, status, total_cents"))
    proxy.proc.send_signal(signal.SIGHUP)
    reloaded = wait_until("config reloaded", lambda: log_events(proxy, "config reloaded"), timeout=30)
    assert reloaded[0]["trigger"] == "sighup" and reloaded[0]["generation"] == 2

    with connect(dsn) as conn:
        assert conn.execute(q_total, ["globex"]).fetchall() == [(1, 1250), (3, 4200)]
        sent.append((pg_text(q_total), True))
    # A session accepted before the reload is not left on the old policy: the proxy
    # ends it (FATAL 57P01, as for an administrator shutdown) so the pool reconnects
    # under the new one. It never runs another statement.
    with pytest.raises(psycopg.OperationalError) as ended:
        old_session.execute(q_total, ["acme"]).fetchall()
    assert ended.value.sqlstate in (None, "57P01"), ended.value.sqlstate
    old_session.close()

    # ---- What Postgres saw ----
    with postgres.connect(pg_database) as c:
        assert c.execute("SELECT count(*) FROM app.orders").fetchone() == (4,)  # DELETE never ran
    executed = wait_until(
        "the allowed statements in the Postgres log",
        lambda: (log := pg_server_log(since)) and f"-{marker + 1}" in log and log, timeout=20)
    stmt_lines = [line for line in executed.splitlines() if f"-{marker}" in line or
                  any(f"-{marker + k}" in line for k in (1, 2, 3))]
    assert any(f"> -{marker} ORDER BY" in line for line in stmt_lines), stmt_lines
    # The client bound 'globex'; Postgres received the session's tenant.
    all_lines = executed.splitlines()
    for i, line in enumerate(all_lines):
        if f"> -{marker} ORDER BY" in line and "execute" in line:
            assert "Parameters: $1 = 'acme'" in all_lines[i + 1], all_lines[i:i + 2]
            break
    else:
        raise AssertionError("no execute line for the first allowed statement")
    # total_cents ran exactly once: after the reload, in the new session.
    assert sum(f"> -{marker + 1} ORDER BY" in line and "execute" in line for line in stmt_lines) == 1, stmt_lines
    for denied in (marker + 2, marker + 3):
        assert not any(f"-{denied}" in line for line in stmt_lines), stmt_lines
    # The denied statements reached Postgres only as the proxy's unparsable placeholder.
    assert "haltsql_deny_" in executed

    # ---- The proxy's audit file ----
    proxy.stop()
    stopped = log_events(proxy, "stopped")
    assert stopped, proxy.log()
    lines = audit.read_text().splitlines()
    recs = [json.loads(line) for line in lines]
    stmts = [r for r in recs if r.get("event") == "statement"]
    execs = [r for r in recs if r.get("event") == "execute"]
    assert len(stmts) + len(execs) == len(recs), [r.get("event") for r in recs]
    assert [(r["sql_sha256"], r["allowed"]) for r in stmts] == [
        (sha256_hex(sql), allowed) for sql, allowed in sent]
    # Every forwarded Execute has its own record, and only allowed statements run.
    allowed_hashes = {sha256_hex(sql) for sql, allowed in sent if allowed}
    assert execs and {r["sql_sha256"] for r in execs} <= allowed_hashes, execs
    assert sha256_hex(pg_text(q_total)) in {r["sql_sha256"] for r in execs}
    assert all(r["user"] == "analyst" and r["policy"] == "proxy-shop" for r in recs)
    assert recs[0]["prev_hash"] == GENESIS
    assert not any("app.orders WHERE" in line for line in lines)  # log_raw_sql is off
    assert upstream_password not in proxy.log() and client_password not in proxy.log()
    assert f"-{marker}" not in proxy.log()  # no SQL text in the operational log either
    assert len(log_events(proxy, "statement denied")) == 4
    # The two policy generations are both in the audit trail.
    assert len({r["policy_version"] for r in recs}) == 2

    p = cli.run("audit", "verify", "--json", "--expect-head", recs[-1]["hash"], audit, check=False)
    rep = json.loads(p.stdout)
    assert p.returncode == 0 and rep["ok"] is True and rep["records"] == len(recs), rep

    tampered = list(lines)
    victim = next(i for i, line in enumerate(lines) if '"allowed":false' in line)
    tampered[victim] = tampered[victim].replace('"allowed":false', '"allowed":true', 1)
    assert tampered[victim] != lines[victim]
    bad = tmp_path / "tampered.jsonl"
    bad.write_text("\n".join(tampered) + "\n")
    p = cli.run("audit", "verify", "--json", bad, check=False)
    rep = json.loads(p.stdout)
    assert p.returncode == 1 and rep["first_broken"]["kind"] == "bad_hash", rep
    assert rep["first_broken"]["line"] == victim + 1

    # A restarted proxy continues the file's chain.
    proxy2 = processes.proxy(["run", "--config", str(cfg)], PROXY_PORT, name="haltsql-proxy-2",
                             env={"UPSTREAM_PASSWORD": upstream_password})
    wait_listening(proxy2)
    with connect(dsn) as conn:
        assert conn.execute(q_ok, ["acme"]).fetchall() == [(1, "open"), (3, "paid")]
    proxy2.stop()
    p = cli.run("audit", "verify", "--json", "--strict", audit, check=False)
    rep = json.loads(p.stdout)
    after_restart = len(audit.read_text().splitlines())
    assert after_restart > len(recs), "the restarted proxy wrote no audit record"
    assert p.returncode == 0 and rep["records"] == after_restart and rep["inputs"][0]["chains"] == 1, rep

