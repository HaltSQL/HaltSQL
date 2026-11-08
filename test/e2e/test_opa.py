"""Scenario: Open Policy Agent as a second opinion that can only further deny.

Real OPA (openpolicyagent/opa:1.10.1) decides on what HaltSQL allowed:

* the stack's OPA with the fixture policy haltsql/e2e/decision (it blocks
  app.payroll): a query HaltSQL allows but OPA denies gets E_EXTERNAL_POLICY
  with OPA's reason; OPA's own decision log shows exactly the input it got
  (no SQL text, no context values) and that it was never asked about queries
  HaltSQL denied;
* an allow-everything OPA policy (uploaded under a unique package) cannot turn
  any HaltSQL denial into an allow;
* OPA unavailable, for each on_error mode (deny, allow_haltsql_verdict): a
  closed port (connection refused), a private OPA container that is paused
  (no answer: timeout) and then stopped, and recovery after unpause / start.

Ports: 17061-17065, private OPA containers on 17068-17069.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
import requests

from conftest import (
    FIXTURES,
    OPA_URL,
    Processes,
    docker,
    new_token,
    opa_decision_logs,
    opa_delete_policy,
    opa_put_policy,
    read_jsonl,
    reason_codes,
    sha256_hex,
    unique_name,
    wait_until,
)

SHARED_PORT = 17061
ALLOW_ALL_PORT = 17062
CLOSED_PORT = 17065  # nothing ever listens here
OPA_IMAGE = "openpolicyagent/opa:1.10.1"

POLICIES = """apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: shop-opa }
search_path: [app]
statements: { allow: [select] }
tables:
  app.orders: { columns: [id, total_cents, status] }
  app.payroll: { columns: [id, amount_cents] }
mode: enforce
"""

SHADOW_POLICY = POLICIES.replace("shop-opa", "shop-opa-shadow").replace(
    "mode: enforce", "mode: shadow")

ALLOW_SQL = "SELECT id, total_cents FROM app.orders LIMIT 5"
PAYROLL_SQL = "SELECT id, amount_cents FROM app.payroll LIMIT 5"
# Queries HaltSQL itself denies.
HALT_DENIED = {
    "SELECT id, ssn FROM app.payroll LIMIT 5": "E_COLUMN_DENIED",
    "SELECT id FROM app.customers LIMIT 5": "E_TABLE_DENIED",
    "DELETE FROM app.orders WHERE id = 1": "E_STATEMENT_KIND",
    "SELECT 1; SELECT 2": "E_MULTI_STATEMENT",
}
OPA_REASON = "table app.payroll is blocked by the e2e OPA policy"


def config(port: int, *, opa_url: str, decision_path: str, on_error: str, tokens: dict[str, str],
           work: Path, audit: Path, timeout_ms: int = 500, header_secret: str | None = None) -> str:
    (work / "shop.yaml").write_text(POLICIES)
    (work / "shop-shadow.yaml").write_text(SHADOW_POLICY)
    headers = f"\n  headers: {{ Authorization: \"Bearer {header_secret}\" }}" if header_secret else ""
    return f"""apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:{port}
  auth:
    tokens:
      - {{ name: agent, token_sha256: {sha256_hex(tokens["agent"])}, policy: shop-opa }}
      - {{ name: shadow-agent, token_sha256: {sha256_hex(tokens["shadow"])}, policy: shop-opa-shadow }}
policies:
  - path: {work / "shop.yaml"}
  - path: {work / "shop-shadow.yaml"}
opa:
  url: {opa_url}
  decision_path: {decision_path}
  timeout_ms: {timeout_ms}
  on_error: {on_error}{headers}
audit:
  sinks:
    - {{ type: file, path: {audit} }}
"""


def opa_metric(server, outcome: str) -> float:
    for line in server.get("/metrics").text.splitlines():
        if line.startswith(f'haltsql_opa_decisions_total{{outcome="{outcome}"}} '):
            return float(line.rsplit(" ", 1)[1])
    return 0.0


def decisions_for(sql: str, since: str) -> list[dict]:
    h = sha256_hex(sql)
    return [d for d in opa_decision_logs(since) if d.get("input", {}).get("sql_sha256") == h]


def wait_decision(sql: str, since: str) -> dict:
    return wait_until(f"OPA decision log entry for {sql!r}",
                      lambda: (ds := decisions_for(sql, since)) and ds[-1], timeout=20)


@pytest.fixture
def tokens() -> dict[str, str]:
    return {"agent": new_token(), "shadow": new_token()}


def workdir(tmp_path: Path, name: str) -> Path:
    w = tmp_path / name
    w.mkdir()
    return w


def test_opa_denies_what_haltsql_allows(opa: str, processes: Processes, tokens: dict[str, str],
                                        tmp_path: Path) -> None:
    since = str(int(time.time()) - 1)
    audit = tmp_path / "audit.jsonl"
    server = processes.server(
        config(SHARED_PORT, opa_url=OPA_URL, decision_path="haltsql/e2e/decision",
               on_error="deny", tokens=tokens, work=workdir(tmp_path, "cfg"), audit=audit),
        SHARED_PORT)
    secret_ctx = "u-" + new_token()

    # ---- HaltSQL allows, OPA allows ----
    v = server.verify(ALLOW_SQL, tokens["agent"], context={"user_id": secret_ctx})
    assert v["allowed"] is True and v["reasons"] == [], v
    d = wait_decision(ALLOW_SQL, since)
    assert d["path"] == "haltsql/e2e/decision"
    assert d["result"] == {"allow": True, "reasons": []}
    assert d["input"] == {
        "caller": {"name": "agent", "type": "token"},
        "policy": "shop-opa",
        "policy_version": v["policy"]["version"],
        "statement_kind": "select",
        "tables": ["app.orders"],
        "columns": ["app.orders.id", "app.orders.total_cents"],
        "reasons": [],
        "shadow_reasons": [],
        "allowed": True,
        "sql_sha256": sha256_hex(ALLOW_SQL),
        "fingerprint": v["fingerprint"],
        "context_keys": ["user_id"],
    }

    # ---- HaltSQL allows, OPA denies: E_EXTERNAL_POLICY with OPA's reason ----
    v = server.verify(PAYROLL_SQL, tokens["agent"], context={"user_id": secret_ctx})
    assert v["allowed"] is False, v
    assert v["reasons"] == [{
        "code": "E_EXTERNAL_POLICY", "rule": "opa.decision",
        "message": f"denied by the external policy haltsql/e2e/decision (OPA): {OPA_REASON}",
    }], v
    assert v["bind_params"] == []
    d = wait_decision(PAYROLL_SQL, since)
    assert d["result"] == {"allow": False, "reasons": [OPA_REASON]}
    assert d["input"]["allowed"] is True and d["input"]["tables"] == ["app.payroll"]

    # ---- shadow policy: OPA's denial is reported, the query stays allowed ----
    v = server.verify(PAYROLL_SQL, tokens["shadow"])
    assert v["allowed"] is True and v["reasons"] == [], v
    assert reason_codes({"reasons": v["shadow_reasons"]}) == ["E_EXTERNAL_POLICY"], v

    # ---- HaltSQL denies: OPA is never asked ----
    for sql, code in HALT_DENIED.items():
        v = server.verify(sql, tokens["agent"])
        assert v["allowed"] is False and code in reason_codes(v), (sql, v)
        assert "E_EXTERNAL_POLICY" not in reason_codes(v), (sql, v)
    marker = "SELECT id, status FROM app.orders LIMIT 7"
    assert server.verify(marker, tokens["agent"])["allowed"] is True
    wait_decision(marker, since)  # the log is ordered: later entries are in
    for sql in HALT_DENIED:
        assert decisions_for(sql, since) == [], f"OPA was asked about a HaltSQL denial: {sql}"

    # OPA never received the SQL text or context values.
    logs = docker("logs", "--since", since, "haltsql-e2e-opa-1")
    text = logs.stdout + logs.stderr
    assert secret_ctx not in text
    for sql in [ALLOW_SQL, PAYROLL_SQL, marker, *HALT_DENIED]:
        assert sql not in text

    assert opa_metric(server, "allowed") == 2
    assert opa_metric(server, "denied") == 2  # enforce + shadow
    assert opa_metric(server, "skipped") == len(HALT_DENIED)
    recs = read_jsonl(audit)
    assert [r["codes"] for r in recs[:3]] == [[], ["E_EXTERNAL_POLICY"], ["E_EXTERNAL_POLICY"]]
    assert [(r["allowed"], r["shadow"]) for r in recs[:3]] == [(True, False), (False, False),
                                                                 (True, True)]


def test_opa_cannot_turn_a_haltsql_deny_into_an_allow(opa: str, processes: Processes,
                                                      tokens: dict[str, str], tmp_path: Path) -> None:
    pkg = unique_name("identity_opa_shadow").replace("-", "_")
    opa_put_policy(pkg, f"package {pkg}\n\nimport rego.v1\n\n"
                        "# Allows everything, even what HaltSQL denied.\n"
                        "decision := {\"allow\": true, \"reasons\": []}\n")
    since = str(int(time.time()) - 1)
    try:
        r = requests.post(f"{OPA_URL}/v1/data/{pkg}/decision", json={"input": {"allowed": False}},
                          timeout=5)
        assert r.json()["result"] == {"allow": True, "reasons": []}, r.text
        server = processes.server(
            config(ALLOW_ALL_PORT, opa_url=OPA_URL, decision_path=f"{pkg}/decision",
                   on_error="deny", tokens=tokens, work=workdir(tmp_path, "cfg"),
                   audit=tmp_path / "audit.jsonl"),
            ALLOW_ALL_PORT)
        for sql, code in HALT_DENIED.items():
            for tok in ("agent", "shadow"):
                v = server.verify(sql, tokens[tok])
                if tok == "agent":
                    assert v["allowed"] is False, (sql, v)
                    assert code in reason_codes(v) and "E_EXTERNAL_POLICY" not in reason_codes(v)
                else:  # shadow: allowed by HaltSQL's own mode, the would-be denial kept
                    assert code in reason_codes({"reasons": v["shadow_reasons"]}), (sql, v)
        v = server.verify(PAYROLL_SQL, tokens["agent"])
        assert v["allowed"] is True, v  # this OPA policy allows payroll
        wait_decision(PAYROLL_SQL, since)
        for sql in HALT_DENIED:
            assert all(d["input"]["allowed"] is True for d in decisions_for(sql, since)), sql
            # enforce denials are never sent; shadow ones are sent with their
            # shadow_reasons (allowed=true) and OPA's allow adds nothing.
        assert opa_metric(server, "skipped") == len(HALT_DENIED)
    finally:
        opa_delete_policy(pkg)


@pytest.mark.parametrize("on_error,server_port,opa_port", [
    ("deny", 17063, 17068),
    ("allow_haltsql_verdict", 17064, 17069),
])
def test_opa_unavailable(on_error: str, server_port: int, opa_port: int, docker_available: None,
                         processes: Processes, tokens: dict[str, str], tmp_path: Path) -> None:
    header_secret = new_token()
    fails_closed = on_error == "deny"

    def check_down(server, what: str) -> None:
        t0 = time.monotonic()
        v = server.verify(ALLOW_SQL, tokens["agent"])
        elapsed = time.monotonic() - t0
        if fails_closed:
            assert v["allowed"] is False, (what, v)
            assert reason_codes(v) == ["E_EXTERNAL_POLICY"], (what, v)
            msg = v["reasons"][0]["message"]
            assert "failed and on_error is deny" in msg, (what, msg)
        else:
            assert v["allowed"] is True and v["reasons"] == [], (what, v)
        # With OPA down, a query OPA would deny keeps HaltSQL's verdict only
        # under allow_haltsql_verdict.
        v = server.verify(PAYROLL_SQL, tokens["agent"])
        assert v["allowed"] is (not fails_closed), (what, v)
        # HaltSQL's own denials stay denials either way.
        for sql, code in HALT_DENIED.items():
            v = server.verify(sql, tokens["agent"])
            assert v["allowed"] is False and reason_codes(v)[0] == code, (what, sql, v)
            assert "E_EXTERNAL_POLICY" not in reason_codes(v)
        assert elapsed < 5, f"{what}: verify took {elapsed:.1f}s with timeout_ms 300"

    def check_up(server, what: str) -> None:
        v = server.verify(ALLOW_SQL, tokens["agent"])
        assert v["allowed"] is True and v["reasons"] == [], (what, v)
        v = server.verify(PAYROLL_SQL, tokens["agent"])
        assert v["allowed"] is False and reason_codes(v) == ["E_EXTERNAL_POLICY"], (what, v)
        assert OPA_REASON in v["reasons"][0]["message"]

    # ---- 1. a closed port: connection refused ----
    audit1 = tmp_path / "audit-closed.jsonl"
    s1 = processes.server(
        config(server_port, opa_url=f"http://127.0.0.1:{CLOSED_PORT}",
               decision_path="haltsql/e2e/decision", on_error=on_error, tokens=tokens,
               work=workdir(tmp_path, "closed"), audit=audit1, timeout_ms=300,
               header_secret=header_secret),
        server_port, name="haltsql-server-closed")
    check_down(s1, "closed port")
    label = "error_denied" if fails_closed else "error_allowed"
    assert opa_metric(s1, label) == 2
    assert opa_metric(s1, "skipped") == len(HALT_DENIED)
    s1.stop()
    log = s1.log()
    assert "opa check failed" in log, log
    assert header_secret not in log
    recs = read_jsonl(audit1)
    assert [r["allowed"] for r in recs[:2]] == [not fails_closed] * 2
    assert recs[0]["codes"] == (["E_EXTERNAL_POLICY"] if fails_closed else [])

    # ---- 2. a real OPA container: up, paused, unpaused, stopped, started ----
    name = unique_name("identity-opa-shadow-opa")
    docker("run", "-d", "--name", name, "-p", f"127.0.0.1:{opa_port}:8181",
           "-v", f"{FIXTURES / 'opa'}:/policies:ro", OPA_IMAGE,
           "run", "--server", "--addr=0.0.0.0:8181", "--log-level=error", "/policies")
    opa_url = f"http://127.0.0.1:{opa_port}"
    try:
        def opa_healthy() -> bool:
            try:
                return requests.get(f"{opa_url}/health", timeout=1).status_code == 200
            except requests.RequestException:
                return False

        wait_until("private OPA healthy", opa_healthy, timeout=60)
        s2 = processes.server(
            config(server_port, opa_url=opa_url, decision_path="haltsql/e2e/decision",
                   on_error=on_error, tokens=tokens, work=workdir(tmp_path, "private"),
                   audit=tmp_path / "audit-private.jsonl", timeout_ms=300,
                   header_secret=header_secret),
            server_port, name="haltsql-server-private")
        check_up(s2, "OPA up")

        docker("pause", name)
        try:
            assert not opa_healthy()
            t0 = time.monotonic()
            v = s2.verify(ALLOW_SQL, tokens["agent"])
            assert time.monotonic() - t0 >= 0.25, "a paused OPA can only time out"
            assert v["allowed"] is (not fails_closed), v
            if fails_closed:
                assert "timed out" in v["reasons"][0]["message"] or \
                    "timeout" in v["reasons"][0]["message"], v
            check_down(s2, "OPA paused")
        finally:
            docker("unpause", name)
        check_up(s2, "OPA unpaused")

        docker("stop", "-t", "2", name)
        check_down(s2, "OPA stopped")
        docker("start", name)
        wait_until("private OPA healthy again", opa_healthy, timeout=60)
        check_up(s2, "OPA restarted")

        assert opa_metric(s2, label) == 1 + 2 + 2  # pause probe, paused, stopped
        assert header_secret not in s2.log()
        s2.stop()

        # ---- 3. OPA up, but the decision is undefined (no such rule) ----
        s3 = processes.server(
            config(server_port, opa_url=opa_url, decision_path="haltsql/e2e/no_such_rule",
                   on_error=on_error, tokens=tokens, work=workdir(tmp_path, "undefined"),
                   audit=tmp_path / "audit-undefined.jsonl", timeout_ms=300),
            server_port, name="haltsql-server-undefined")
        r = requests.post(f"{opa_url}/v1/data/haltsql/e2e/no_such_rule", json={"input": {}},
                          timeout=5)
        assert r.status_code == 200 and "result" not in r.json(), r.text
        check_down(s3, "undefined decision")
        assert opa_metric(s3, label) == 2
    finally:
        docker("rm", "-f", name, check=False)
