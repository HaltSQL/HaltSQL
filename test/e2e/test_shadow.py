"""Scenario: shadow-mode rollout -> report -> suggested policy -> enforce.

A new policy runs in shadow mode on haltsql-server while an agent sends a
realistic workload: benign queries the draft policy is too strict for (a
missing column, function, LIMIT and table), a sensitive column, and
tenant-escape attempts. Then:

1. GET /v1/admin/report shows the would-be denials by code, the suggestions,
   and lists the tenancy codes as never relaxed.
2. `haltsql report AUDIT --suggest` on the server's real audit file gives the
   same suggestions, and `--apply-to` writes a patched policy that allows the
   benign queries while every tenant escape stays denied (the CLI's own
   re-verification says so).
3. The patched policy, switched to mode: enforce, is loaded by a second
   haltsql-server: benign queries are allowed and run in real Postgres with
   the verdict's bind_params (only the caller's tenant's rows come back);
   tenant escapes and the sensitive column are denied.

Ports: 17066-17067.
"""

from __future__ import annotations

import json
from pathlib import Path

from conftest import (
    Cli,
    Postgres,
    Processes,
    new_token,
    pg_exec_exact,
    read_jsonl,
    reason_codes,
    sha256_hex,
)

SHADOW_PORT = 17066
ENFORCE_PORT = 17067
CTX = {"tenant_id": "acme"}

DRAFT_POLICY = """apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: shop-rollout, owner: e2e }
search_path: [app]
statements: { allow: [select] }
require_limit: { max: 50 }
tenancy: { mode: bound, keys: { tenant: "${ctx.tenant_id}" } }
tables:
  app.orders: { columns: [id, tenant_id, total_cents], tenant_column: tenant_id }
functions: { presets: [aggregates] }
mode: shadow
"""

ALLOWED = ["SELECT id, total_cents FROM app.orders WHERE tenant_id = $1 ORDER BY id LIMIT 10"]

# Benign queries the draft denies; code -> what the suggestion must fix.
BENIGN = {
    "SELECT id, status FROM app.orders WHERE tenant_id = $1 ORDER BY id LIMIT 10":
        ["E_COLUMN_DENIED"],
    "SELECT upper(currency) AS c, count(*) AS n FROM app.orders WHERE tenant_id = $1 "
    "GROUP BY 1 ORDER BY 1 LIMIT 10": ["E_COLUMN_DENIED", "E_FUNCTION_DENIED"],
    "SELECT id, total_cents FROM app.orders WHERE tenant_id = $1 ORDER BY id LIMIT 200":
        ["E_LIMIT_TOO_HIGH"],
    "SELECT id, name FROM app.customers WHERE tenant_id = $1 ORDER BY id LIMIT 10":
        ["E_TABLE_DENIED"],
}

# Never made allowable by a suggestion.
SENSITIVE = "SELECT id, email FROM app.customers WHERE tenant_id = $1 ORDER BY id LIMIT 10"
# sql -> (shadow code under the draft, enforce code under the patched policy).
# A query on a table the draft does not list is only E_TABLE_DENIED in the
# shadow run; once the table is added it is tenant-scoped and the missing
# predicate is caught.
ESCAPES = {
    "SELECT id, status FROM app.orders LIMIT 10": ("E_TENANT_MISSING", "E_TENANT_MISSING"),
    "SELECT id, total_cents FROM app.orders WHERE tenant_id = 'globex' LIMIT 10":
        ("E_TENANT_MISMATCH", "E_TENANT_MISMATCH"),
    "SELECT id, name FROM app.customers LIMIT 10": ("E_TABLE_DENIED", "E_TENANT_MISSING"),
    "SELECT id FROM app.orders WHERE tenant_id = $1 OR true LIMIT 10":
        ("E_TENANT_MISSING", "E_TENANT_MISSING"),
    "SELECT o.id, c.name FROM app.orders o JOIN app.customers c ON c.id = o.customer_id "
    "WHERE o.tenant_id = $1 LIMIT 10": ("E_TABLE_DENIED", "E_TENANT_MISSING"),
}
ROUNDS = 3


def seed(pg: Postgres, db: str) -> None:
    with pg.connect(db) as c:
        c.execute("CREATE SCHEMA app")
        c.execute("CREATE TABLE app.customers (id int PRIMARY KEY, tenant_id text NOT NULL,"
                  " name text, email text)")
        c.execute("CREATE TABLE app.orders (id int PRIMARY KEY, tenant_id text NOT NULL,"
                  " customer_id int, status text, currency text, total_cents int)")
        c.execute("INSERT INTO app.customers VALUES (1,'acme','Ann','ann@acme.invalid'),"
                  " (2,'globex','Gus','gus@globex.invalid')")
        c.execute("INSERT INTO app.orders VALUES (10,'acme',1,'open','eur',100),"
                  " (11,'acme',1,'paid','usd',250), (12,'globex',2,'open','eur',999)")


def server_config(port: int, policy: Path, *, agent: str, ops: str, audit: Path) -> str:
    return f"""apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:{port}
  auth:
    tokens:
      - {{ name: agent, token_sha256: {sha256_hex(agent)}, policy: shop-rollout }}
      - {{ name: ops, token_sha256: {sha256_hex(ops)}, policy: shop-rollout }}
  admin: {{ enabled: true, callers: [token:ops] }}
policies:
  - path: {policy}
audit:
  log_raw_sql: true
  sinks:
    - {{ type: file, path: {audit} }}
"""


def suggestion_changes(sg: dict) -> dict[str, dict]:
    return {s["id"]: s["change"] for s in sg["suggestions"]}


EXPECTED_IDS = {
    "shop-rollout/column/app.orders.status",
    "shop-rollout/column/app.orders.currency",
    # from the join escape: the column is benign, the query stays denied for
    # tenancy once app.customers is added (checked in step 3)
    "shop-rollout/column/app.orders.customer_id",
    "shop-rollout/function/upper",
    "shop-rollout/limit",
    "shop-rollout/table/app.customers",
}


def test_shadow_report_suggest_then_enforce(cli: Cli, postgres: Postgres, pg_database: str,
                                            processes: Processes, tmp_path: Path) -> None:
    seed(postgres, pg_database)
    agent, ops = new_token(), new_token()
    policy = tmp_path / "shop.yaml"
    policy.write_text(DRAFT_POLICY)
    audit = tmp_path / "audit.jsonl"
    shadow = processes.server(server_config(SHADOW_PORT, policy, agent=agent, ops=ops, audit=audit),
                              SHADOW_PORT, name="haltsql-server-shadow")

    # ---- the shadow workload: everything is allowed, would-be denials reported ----
    for _ in range(ROUNDS):
        for sql in ALLOWED:
            v = shadow.verify(sql, agent, context=CTX)
            assert v["allowed"] is True and v["shadow_reasons"] == [], (sql, v)
        for sql, codes in BENIGN.items():
            v = shadow.verify(sql, agent, context=CTX)
            assert v["allowed"] is True and v["reasons"] == [], (sql, v)
            got = reason_codes({"reasons": v["shadow_reasons"]})
            assert set(codes) <= set(got), (sql, got)
            assert not any(c.startswith("E_TENANT") for c in got), (sql, got)
        v = shadow.verify(SENSITIVE, agent, context=CTX)
        assert v["allowed"] is True and "E_TABLE_DENIED" in reason_codes(
            {"reasons": v["shadow_reasons"]}), v
        for sql, (code, _) in ESCAPES.items():
            v = shadow.verify(sql, agent, context=CTX)
            assert v["allowed"] is True, (sql, v)
            assert code in reason_codes({"reasons": v["shadow_reasons"]}), (sql, v)

    n_shadow_denied = ROUNDS * (len(BENIGN) + 1 + len(ESCAPES))
    n_total = n_shadow_denied + ROUNDS * len(ALLOWED)

    # ---- 1. GET /v1/admin/report ----
    r = shadow.get("/v1/admin/report", ops)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["summary"]["totals"]["total"] == n_total, rep["summary"]["totals"]
    assert rep["summary"]["totals"]["shadow_denied"] == n_shadow_denied
    assert rep["summary"]["totals"]["denied"] == 0
    by_code = {c["code"]: c for c in rep["summary"]["by_code"]}
    for code in ("E_COLUMN_DENIED", "E_FUNCTION_DENIED", "E_LIMIT_TOO_HIGH", "E_TABLE_DENIED",
                 "E_TENANT_MISSING", "E_TENANT_MISMATCH"):
        assert by_code[code]["shadow_denied"] > 0 and by_code[code]["denied"] == 0, code
    assert by_code["E_TENANT_MISMATCH"]["shadow_denied"] == ROUNDS
    server_sg = rep["suggest"]
    changes = suggestion_changes(server_sg)
    assert set(changes) == EXPECTED_IDS, changes
    assert changes["shop-rollout/limit"] == {"kind": "raise_limit", "current": 50, "proposed": 200}
    assert changes["shop-rollout/function/upper"]["kind"] == "add_function"
    assert changes["shop-rollout/table/app.customers"]["kind"] == "add_table"
    assert "email" not in changes["shop-rollout/table/app.customers"]["columns"]
    never = {c["code"]: c for c in server_sg["codes"]}
    assert never["E_TENANT_MISSING"]["category"] == "never_weaken"
    assert never["E_TENANT_MISMATCH"]["category"] == "never_weaken"
    assert any("email" in json.dumps(p) for p in server_sg["pii_flagged"]), server_sg["pii_flagged"]
    # The report never needs the token and never echoes it.
    assert agent not in r.text and ops not in r.text
    # Only admin callers can read it.
    assert shadow.get("/v1/admin/report", agent).status_code == 403
    assert shadow.get("/v1/admin/report").status_code == 401
    shadow.stop()

    # ---- 2. haltsql report on the server's real audit file ----
    records = read_jsonl(audit)
    assert len(records) == n_total
    assert all(r["allowed"] is True for r in records)
    assert sum(1 for r in records if r["shadow"]) == n_shadow_denied
    p = cli.run("audit", "verify", audit, check=False)
    assert p.returncode == 0, p.stdout + p.stderr

    p = cli.run("report", audit, "--suggest", "--policy-file", policy, "--format", "json")
    cli_rep = json.loads(p.stdout)
    assert cli_rep["summary"]["totals"]["shadow_denied"] == n_shadow_denied
    assert set(suggestion_changes(cli_rep["suggest"])) == EXPECTED_IDS
    assert "hash chain ok" in cli_rep["inputs"][0]["status"], cli_rep["inputs"]

    out = tmp_path / "shop.next.json"
    p = cli.run("report", audit, "--apply-to", policy, "-o", out, "--format", "json")
    assert p.returncode == 0
    notes = " ".join(json.loads(p.stdout)["notes"])
    n_with_sql = n_shadow_denied
    n_tenancy = ROUNDS * sum(1 for c, _ in ESCAPES.values() if c.startswith("E_TENANT"))
    # Benign (4), the two escapes recorded only as E_TABLE_DENIED/E_COLUMN_DENIED and
    # the sensitive query no longer hit their recorded codes (the last three are
    # still denied, by new codes, as step 3 shows); every tenancy denial is kept.
    assert (f"{ROUNDS * 7} of {n_with_sql} denied record(s) with raw SQL no longer hit"
            in notes), notes
    assert f"{n_tenancy} of {n_tenancy} tenancy denial(s) are still denied" in notes, notes
    patched = json.loads(out.read_text())
    assert patched["mode"] == "shadow", "apply-to never changes the mode"
    orders = patched["tables"]["app.orders"]
    assert set(orders["columns"]) == {"id", "tenant_id", "total_cents", "status", "currency",
                                    "customer_id"}
    assert orders["tenant_column"] == "tenant_id"
    customers = patched["tables"]["app.customers"]
    assert "email" not in customers["columns"], "a sensitive column was suggested"
    assert set(customers["columns"]) >= {"id", "name"}
    assert customers["tenant_column"] == "tenant_id", "a new table is always tenant-scoped"
    assert "upper" in patched["functions"]["allow"]
    assert patched["require_limit"]["max"] == 200
    assert patched["tenancy"] == {"mode": "bound", "keys": {"tenant": "${ctx.tenant_id}"}}
    assert out.read_text().find(agent) == -1

    # The usual flow writes YAML; it must say the same thing as the JSON output.
    out_yaml = tmp_path / "shop.next.yaml"
    cli.run("report", audit, "--apply-to", policy, "-o", out_yaml)
    yaml_text = out_yaml.read_text()
    assert yaml_text.startswith("#"), "the YAML output starts with the applied-ids comment"
    header = "".join(line for line in yaml_text.splitlines(True) if line.startswith("#"))
    for sid in EXPECTED_IDS:
        assert sid in header, (sid, header)

    # ---- 3. enforce the patched policy (the YAML file, mode switched by hand) ----
    assert yaml_text.count("mode: shadow") == 1, yaml_text
    enforced = tmp_path / "shop.enforce.yaml"
    enforced.write_text(yaml_text.replace("mode: shadow", "mode: enforce"))
    audit2 = tmp_path / "audit-enforce.jsonl"
    enforce = processes.server(
        server_config(ENFORCE_PORT, enforced, agent=agent, ops=ops, audit=audit2),
        ENFORCE_PORT, name="haltsql-server-enforce")
    db = postgres.connect(pg_database)
    try:
        for sql in ALLOWED + list(BENIGN):
            v = enforce.verify(sql, agent, context=CTX)
            assert v["allowed"] is True and v["reasons"] == [], (sql, v)
            assert v["bind_params"] == [{"param": 1, "value": "acme"}], (sql, v)
            rows = pg_exec_exact(db, sql, v["bind_params"])
            assert rows, sql
            # only acme's rows: globex's order 12 / customer 2 never come back
            assert all(row[0] not in ("12", "2") for row in rows), (sql, rows)
        v = enforce.verify(SENSITIVE, agent, context=CTX)
        assert v["allowed"] is False and reason_codes(v) == ["E_COLUMN_DENIED"], v
        for sql, (_, code) in ESCAPES.items():
            v = enforce.verify(sql, agent, context=CTX)
            assert v["allowed"] is False and code in reason_codes(v), (sql, v)
            assert v["bind_params"] == []
        # The escapes are real: globex rows exist and the unfiltered query would see them.
        with postgres.connect(pg_database) as c:
            assert c.execute("SELECT count(*) FROM app.orders WHERE tenant_id <> 'acme'"
                             ).fetchone()[0] == 1
    finally:
        db.close()
    recs = read_jsonl(audit2)
    assert [r["allowed"] for r in recs] == [True] * (len(ALLOWED) + len(BENIGN)) + \
        [False] * (1 + len(ESCAPES))
    assert all(r["shadow"] is False for r in recs)
