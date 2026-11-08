"""haltlab through haltsql-proxy.

Runs a normal lab Scenario, but sends every generated query through a live
``haltsql-proxy`` (extended protocol, real libpq driver) instead of only asking
``haltsql verify --batch``. The CLI verdicts stay the reference; the proxy is
judged against them and against the database:

* parity      - the proxy allows exactly the queries the CLI allows, and denies
                with SQLSTATE 42501 + "HaltSQL reasons: ..." otherwise;
* divergence  - an allowed query returns, through the proxy, exactly the rows
                the same SQL returns directly (same role) with the CLI's
                bind_params. The client always sends ANOTHER tenant's value for
                every tenancy parameter, so any divergence means the proxy failed
                to overwrite it;
* honeytokens - proxy output never contains another tenant's or a denied
                column's marker.

Every proxied query runs inside BEGIN READ ONLY ... ROLLBACK (allowed by the
proxy's transaction-control allowlist), so the lab database never changes.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psycopg
import yaml
from psycopg import pq

from common.fixtures import LAB, get_fixture
from common.policy import load_policy
from datagen.honeytokens import classify, extract_markers
from generators.sqlspec import SchemaModel
from harness import db as labdb
from harness.oracles import encode_param
from harness.runner import build_items, log
from harness.scenario import Scenario
from harness.verifier import resolve_binary, verify_batch

REPO = LAB.parent
DENY_SQLSTATE = "42501"
PARAM_RE = re.compile(r"\$(\d+)")


# ---------------------------------------------------------------- helpers

def resolve_proxy_binary() -> list[str]:
    """``HALTSQL_PROXY_BIN``, else a dune build output, else ``haltsql-proxy`` on PATH."""
    env = os.environ.get("HALTSQL_PROXY_BIN")
    if env:
        return [env]
    for d in sorted(REPO.glob("_build*/default/bin/proxy/main.exe")) + [
            REPO / "_build/install/default/bin/haltsql-proxy"]:
        if d.exists():
            return [str(d)]
    found = shutil.which("haltsql-proxy")
    if found:
        return [found]
    raise FileNotFoundError("haltsql-proxy not found: build bin/proxy or set HALTSQL_PROXY_BIN")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def param_count(sql: str) -> int:
    return max((int(m) for m in PARAM_RE.findall(sql)), default=0)


def context_key(ctx: dict[str, Any]) -> str:
    return json.dumps(ctx, sort_keys=True, ensure_ascii=False)


def decoy_params(sql: str, verdict: dict[str, Any], decoy_ctx: dict[str, Any]) -> list[bytes | None]:
    """Client-side parameters: every tenancy parameter gets ANOTHER tenant's value."""
    n = param_count(sql)
    binds = {int(b["param"]): b["value"] for b in verdict.get("bind_params") or []}
    decoy_value = next(iter(decoy_ctx.values()), "decoy") if decoy_ctx else "decoy"
    out: list[bytes | None] = []
    for i in range(1, n + 1):
        if i in binds:
            v = binds[i]
            out.append(encode_param(decoy_value if not isinstance(v, list) else
                                    (decoy_value if isinstance(decoy_value, list) else [decoy_value])))
        else:
            out.append(b"0")
    return out


@dataclass
class Outcome:
    allowed: bool
    rows: list[tuple[str | None, ...]] = field(default_factory=list)
    sqlstate: str | None = None
    detail: str | None = None
    message: str | None = None


def classify_result(res: Any) -> Outcome:
    """Map a PGresult to proxy allowed/denied. Only a HaltSQL denial counts as denied."""
    status = pq.ExecStatus(res.status)
    if status in (pq.ExecStatus.TUPLES_OK, pq.ExecStatus.COMMAND_OK, pq.ExecStatus.EMPTY_QUERY):
        rows = [tuple(None if res.get_value(i, j) is None else res.get_value(i, j).decode("utf-8", "replace")
                      for j in range(res.nfields)) for i in range(res.ntuples)]
        return Outcome(True, rows)

    def f(code: Any) -> str | None:
        v = res.error_field(code)
        return v.decode("utf-8", "replace") if v is not None else None

    sqlstate = f(pq.DiagnosticField.SQLSTATE)
    detail = f(pq.DiagnosticField.MESSAGE_DETAIL)
    msg = f(pq.DiagnosticField.MESSAGE_PRIMARY)
    denied = sqlstate == DENY_SQLSTATE and (detail or "").startswith("HaltSQL reasons:")
    return Outcome(not denied, [], sqlstate, detail, msg)


# ---------------------------------------------------------------- proxy

@dataclass
class Proxy:
    proc: subprocess.Popen
    port: int
    log_path: Path
    users: dict[str, tuple[str, str]]  # context key -> (user, password)

    def stop(self) -> int:
        self.proc.send_signal(signal.SIGTERM)
        try:
            return self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return self.proc.wait()


def scram_verifier(bin_cmd: list[str], password: str) -> str:
    p = subprocess.run([*bin_cmd, "scram-verifier"], input=password + "\n", capture_output=True,
                       text=True, check=True)
    return p.stdout.strip()


def start_proxy(bin_cmd: list[str], out_dir: Path, policy_path: Path, dbname: str,
                contexts: list[dict[str, Any]], admin_dsn: str) -> Proxy:
    info = psycopg.conninfo.conninfo_to_dict(admin_dsn)
    policy_doc = yaml.safe_load(policy_path.read_text(encoding="utf-8")) \
        if policy_path.suffix in (".yaml", ".yml") else json.loads(policy_path.read_text(encoding="utf-8"))
    policy_name = policy_doc["metadata"]["name"]
    users: dict[str, tuple[str, str]] = {}
    cfg_users = []
    for i, ctx in enumerate(contexts):
        name, pw = f"lab{i:04d}", secrets.token_urlsafe(18)
        users[context_key(ctx)] = (name, pw)
        cfg_users.append({"name": name, "scram_verifier": scram_verifier(bin_cmd, pw),
                          "policy": policy_name, "context": ctx})
    port = free_port()
    cfg = {
        "apiVersion": "haltsql.dev/v1", "kind": "ProxyConfig",
        "listen": f"127.0.0.1:{port}",
        "upstream": {"host": info.get("host", "localhost"), "port": int(info.get("port", 5432)),
                     "database": dbname, "user": info.get("user", "postgres"),
                     "password": "${env:HALTLAB_PROXY_UPSTREAM_PASSWORD}"},
        "policies": [{"path": str(policy_path.resolve())}],
        "auth": {"method": "scram", "users": cfg_users},
        "limits": {"max_connections": 64},
        "audit": {"type": "file", "path": str((out_dir / "proxy-audit.jsonl").resolve())},
        "logging": {"level": "warn"},
        "shutdown_grace_seconds": 2,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = out_dir / "proxy.json"
    cfg_path.write_text(json.dumps(cfg, indent=1, ensure_ascii=False), encoding="utf-8")
    os.chmod(cfg_path, 0o600)
    log_path = out_dir / "proxy.log"
    env = dict(os.environ, HALTLAB_PROXY_UPSTREAM_PASSWORD=info.get("password", ""))
    proc = subprocess.Popen([*bin_cmd, "run", "-c", str(cfg_path)], stdout=subprocess.DEVNULL,
                            stderr=open(log_path, "wb"), env=env)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"haltsql-proxy exited {proc.returncode}: {log_path.read_text()[-2000:]}")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return Proxy(proc, port, log_path, users)
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("haltsql-proxy did not start listening")


# ---------------------------------------------------------------- run

@dataclass
class Metrics:
    items: int = 0
    cli_allowed: int = 0
    proxy_allowed: int = 0
    executed: int = 0
    parity_mismatches: int = 0
    divergences: int = 0
    honeytoken_leaks: int = 0
    execution_errors: int = 0
    examples: list[dict[str, Any]] = field(default_factory=list)

    @property
    def escapes(self) -> int:
        return self.divergences + self.honeytoken_leaks

    def to_json(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if k != "examples"}
        d["escapes"] = self.escapes
        return d


def _direct(conn: psycopg.Connection, sql: str, verdict: dict[str, Any]) -> Outcome:
    from harness.oracles import bind_values
    pg = conn.pgconn
    pg.exec_(b"BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
    try:
        params = bind_values(verdict)
        n = param_count(sql)
        params = params + [b"0"] * (n - len(params))
        return classify_result(pg.exec_params(sql.encode(), params))
    finally:
        pg.exec_(b"ROLLBACK")


def _proxied(conn: psycopg.Connection, sql: str, params: list[bytes | None]) -> Outcome:
    pg = conn.pgconn
    pg.exec_(b"BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
    try:
        return classify_result(pg.exec_params(sql.encode(), params))
    finally:
        pg.exec_(b"ROLLBACK")


def run(scn: Scenario, out_dir: Path, keep_db: bool = False) -> tuple[bool, Metrics]:
    fixture = get_fixture(scn.fixture)
    if fixture.generated:
        raise ValueError("generated fixtures (erp_large) are not supported by the proxy lab yet")
    policy_path = Path(scn.policy_override or fixture.policy)
    policy = load_policy(policy_path)
    seed = int(scn.data.get("seed", 42))
    version = scn.postgres[0]
    admin = labdb.admin_dsn(version, scn.dsn)
    name = labdb.db_name(f"{scn.name}_proxy", version)
    cli = resolve_binary()
    proxy_bin = resolve_proxy_binary()
    log(f"Postgres {version}: creating database {name}")
    dsn = labdb.create_database(admin, name)
    metrics = Metrics()
    proxy: Proxy | None = None
    try:
        lab = labdb.install(dsn, fixture, policy, scn.data)
        with psycopg.connect(dsn, autocommit=True) as c:
            c.execute(f'ALTER DATABASE "{name}" SET statement_timeout = {int(scn.statement_timeout_ms)}')
        model = SchemaModel.build(policy, fixture.model, lab.catalog)
        items = build_items(scn, model, lab.universe, fixture.name, seed)
        verdicts = verify_batch(cli, policy_path, items)
        contexts = list({context_key(it.get("context") or {}): it.get("context") or {} for it in items}.values())
        log(f"{len(items)} queries, {len(contexts)} distinct contexts; starting haltsql-proxy")
        proxy = start_proxy(proxy_bin, out_dir, policy_path, name, contexts, admin)
        conns: dict[str, psycopg.Connection] = {}
        direct = psycopg.connect(dsn, autocommit=True)
        try:
            for idx, it in enumerate(items):
                ctx = it.get("context") or {}
                key = context_key(ctx)
                verdict = verdicts[str(it["id"])]
                metrics.items += 1
                cli_ok = bool(verdict.get("allowed"))
                metrics.cli_allowed += cli_ok
                if key not in conns:
                    user, pw = proxy.users[key]
                    conns[key] = psycopg.connect(host="127.0.0.1", port=proxy.port, dbname=name,
                                                 user=user, password=pw, sslmode="disable",
                                                 autocommit=True)
                other = contexts[(contexts.index(ctx) + 1) % len(contexts)] if len(contexts) > 1 else {}
                params = decoy_params(it["sql"], verdict, other)
                got = _proxied(conns[key], it["sql"], params)
                metrics.proxy_allowed += got.allowed
                example = {"id": it["id"], "sql": it["sql"][:300], "context": ctx}
                if got.allowed != cli_ok:
                    metrics.parity_mismatches += 1
                    metrics.examples.append({**example, "finding": "parity",
                                             "cli_allowed": cli_ok, "proxy": got.__dict__ | {"rows": len(got.rows)}})
                    continue
                if not got.allowed:
                    continue
                if got.sqlstate is not None:  # allowed by HaltSQL, failed in the database
                    metrics.execution_errors += 1
                    if metrics.execution_errors <= 5:
                        metrics.examples.append({**example, "finding": "execution_error",
                                                 "sqlstate": got.sqlstate, "message": got.message})
                    continue
                metrics.executed += 1
                ref = _direct(direct, it["sql"], verdict)
                if ref.sqlstate is None and Counter(ref.rows) != Counter(got.rows):
                    metrics.divergences += 1
                    metrics.examples.append({**example, "finding": "divergence",
                                             "proxy_rows": len(got.rows), "direct_rows": len(ref.rows)})
                leaks = classify(extract_markers(got.rows), lab.dataset.registry, lab.universe.allowed(ctx))
                if leaks:
                    metrics.honeytoken_leaks += 1
                    metrics.examples.append({**example, "finding": "honeytoken",
                                             "markers": [lk.marker for lk in leaks][:5]})
        finally:
            for c in conns.values():
                c.close()
            direct.close()
        rc = proxy.stop()
        proxy = None
        if rc != 0:
            metrics.examples.append({"finding": "proxy_exit", "code": rc})
    finally:
        if proxy is not None:
            proxy.stop()
        if not keep_db:
            labdb.drop_database(admin, name)

    failures = []
    if metrics.parity_mismatches:
        failures.append(f"parity_mismatches={metrics.parity_mismatches}")
    if metrics.escapes > (scn.expect.escapes or 0):
        failures.append(f"escapes={metrics.escapes}")
    if scn.expect.min_executed is not None and metrics.executed < scn.expect.min_executed:
        failures.append(f"executed={metrics.executed} < min_executed={scn.expect.min_executed}")
    if any(e.get("finding") == "proxy_exit" for e in metrics.examples):
        failures.append("proxy did not shut down cleanly")
    write_report(out_dir, scn, metrics, failures)
    return (not failures, metrics)


def write_report(out_dir: Path, scn: Scenario, m: Metrics, failures: list[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(
        {"scenario": scn.name, "mode": "proxy", "metrics": m.to_json(), "failures": failures,
         "examples": m.examples[:50]}, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    lines = [f"# haltlab proxy run: {scn.name}", "",
             f"Result: **{'PASS' if not failures else 'FAIL'}**", "",
             "| metric | value |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in m.to_json().items()]
    if failures:
        lines += ["", "## Failures", ""] + [f"- {f}" for f in failures]
    if m.examples:
        lines += ["", "## Examples", ""] + [f"- `{json.dumps(e, ensure_ascii=False, default=str)[:400]}`"
                                            for e in m.examples[:20]]
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
