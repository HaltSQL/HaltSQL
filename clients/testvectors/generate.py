#!/usr/bin/env python3
"""Regenerate the shared HaltSQL client test vectors from the real CLI.

Usage (from the repository root)::

    eval $(opam env); dune build ./bin/haltsql/main.exe
    python3 clients/testvectors/generate.py [--haltsql PATH]

Each case is verified with ``haltsql verify --json`` against a fixture under
``test/fixtures/policies`` and written to ``clients/testvectors/cases/<name>.json``.
Run ``--check`` to fail (exit 1) if any committed vector differs from what the
CLI produces now, ignoring ``elapsed_us``.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, List

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CASES_DIR = os.path.join(HERE, "cases")
DEFAULT_BIN = os.path.join(ROOT, "_build", "default", "bin", "haltsql", "main.exe")

ACME = {"tenant_id": "acme"}

# (name, policy fixture stem, sql, context, description)
CASES: List[Dict[str, Any]] = [
    dict(name="saas_allow_bound_simple", policy="saas", ctx=ACME,
         sql="SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50",
         desc="Bound tenancy: one table with its tenant predicate; binds $1 to the tenant."),
    dict(name="saas_allow_join_both_tenanted", policy="saas", ctx=ACME,
         sql="SELECT o.id, c.name FROM orders o JOIN customers c ON c.id = o.customer_id "
             "AND c.tenant_id = $1 WHERE o.tenant_id = $1 LIMIT 20",
         desc="Join where every tenant-scoped table carries its own predicate."),
    dict(name="saas_allow_aggregate", policy="saas", ctx=ACME,
         sql="SELECT status, count(*) AS n, sum(total_cents) FROM orders WHERE tenant_id = $1 "
             "GROUP BY status ORDER BY n DESC LIMIT 10",
         desc="Aggregates from the presets."),
    dict(name="saas_allow_global_table", policy="saas", ctx=ACME,
         sql="SELECT * FROM currencies LIMIT 5",
         desc="Table without a tenant column; * expands from the catalog; no bind params."),
    dict(name="saas_deny_tenant_missing", policy="saas", ctx=ACME,
         sql="SELECT id FROM orders LIMIT 10",
         desc="No tenant predicate."),
    dict(name="saas_deny_column_pii", policy="saas", ctx=ACME,
         sql="SELECT id, email FROM customers WHERE tenant_id = $1 LIMIT 10",
         desc="Column outside the allowlist."),
    dict(name="saas_deny_join_tenant_missing_and_column", policy="saas", ctx=ACME,
         sql="SELECT o.id, c.email FROM orders o JOIN customers c ON c.id = o.customer_id "
             "WHERE o.tenant_id = $1 LIMIT 50",
         desc="Two reasons: a denied column and a missing tenant predicate."),
    dict(name="saas_deny_table_not_in_policy", policy="saas", ctx=ACME,
         sql="SELECT id FROM api_keys WHERE tenant_id = $1 LIMIT 1",
         desc="Table exists in the catalog but not in the policy."),
    dict(name="saas_deny_missing_limit", policy="saas", ctx=ACME,
         sql="SELECT id FROM orders WHERE tenant_id = $1",
         desc="require_limit is on."),
    dict(name="saas_deny_multi_statement", policy="saas", ctx=ACME,
         sql="SELECT id FROM orders WHERE tenant_id = $1 LIMIT 1; DROP TABLE orders",
         desc="Statement smuggling: more than one statement."),
    dict(name="saas_deny_delete_not_allowed", policy="saas", ctx=ACME,
         sql="DELETE FROM orders WHERE tenant_id = $1",
         desc="Statement kind not allowed."),
    dict(name="saas_deny_parse_error", policy="saas", ctx=ACME,
         sql="SELEC id FROM orders",
         desc="Syntax error: statement_kind and fingerprint are null."),
    dict(name="saas_deny_context_missing", policy="saas", ctx={},
         sql="SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10",
         desc="Policy needs ctx.tenant_id but the context is empty."),
    dict(name="saas_deny_or_bypass", policy="saas", ctx=ACME,
         sql="SELECT id FROM orders WHERE tenant_id = $1 OR true LIMIT 10",
         desc="A tenant predicate under OR proves nothing."),
    dict(name="saas_deny_function_side_effect", policy="saas", ctx=ACME,
         sql="SELECT pg_sleep(10) FROM orders WHERE tenant_id = $1 LIMIT 1",
         desc="Function outside the allowlist."),
    dict(name="saas_unicode_literal", policy="saas", ctx=ACME,
         sql="SELECT id FROM orders WHERE tenant_id = $1 AND status = 'pagó ✓' LIMIT 5",
         desc="Non-ASCII SQL: sql_sha256 is over the UTF-8 bytes."),
    dict(name="literal_allow", policy="saas_literal", ctx=ACME,
         sql="SELECT id FROM orders WHERE tenant_id = 'acme' LIMIT 10",
         desc="Literal tenancy: the tenant value is written in the SQL; no bind params."),
    dict(name="literal_deny_other_tenant", policy="saas_literal", ctx=ACME,
         sql="SELECT id FROM orders WHERE tenant_id = 'globex' LIMIT 10",
         desc="Literal tenancy with another tenant's value."),
    dict(name="hierarchical_allow_set", policy="hierarchical",
         ctx={"tenant_ids": ["acme", "acme-eu", "acme-us"]},
         sql="SELECT a.id, a.name FROM accounts a WHERE a.tenant_id = ANY($1) LIMIT 100",
         desc="Tenant set: $1 binds to a list (a Postgres text[] array)."),
    dict(name="composite_allow_two_keys", policy="composite",
         ctx={"org_id": "o1", "workspace_id": "w9"},
         sql="SELECT id, name FROM projects WHERE org_id = $1 AND workspace_id = $2 LIMIT 10",
         desc="Composite keys: two bind params in $n order."),
    dict(name="composite_deny_one_key_missing", policy="composite",
         ctx={"org_id": "o1", "workspace_id": "w9"},
         sql="SELECT id, name FROM projects WHERE org_id = $1 LIMIT 10",
         desc="Composite keys: workspace predicate missing."),
    dict(name="writes_allow_update", policy="writes", ctx=ACME,
         sql="UPDATE tickets SET status = 'closed' WHERE id = 7 AND tenant_id = $1",
         desc="Write allowed by the per-table writes block; statement_kind update."),
    dict(name="writes_deny_update_column", policy="writes", ctx=ACME,
         sql="UPDATE tickets SET created_at = now() WHERE id = 7 AND tenant_id = $1",
         desc="Updating a column outside writes.update."),
    dict(name="shadow_allowed_with_shadow_reasons", policy="shadow", ctx=ACME,
         sql="SELECT id FROM orders LIMIT 10",
         desc="Shadow mode: allowed is true, would-be reasons are in shadow_reasons."),
    dict(name="strict_deny_operator", policy="strict", ctx=ACME,
         sql="SELECT id FROM orders WHERE tenant_id = $1 AND status LIKE 'a%' LIMIT 10",
         desc="Operator outside the allowlist."),
    dict(name="mixed_case_allow_quoted", policy="mixed_case", ctx=ACME,
         sql='SELECT c."Id", c."FullName" FROM "Customers" c WHERE c."TenantId" = $1 LIMIT 5',
         desc="Quoted mixed-case identifiers."),
]

COMPARE = [
    "allowed",
    "reasons[].code",
    "shadow_reasons[].code",
    "policy.name",
    "policy.version",
    "statement_kind",
    "tables",
    "columns",
    "bind_params",
    "fingerprint",
    "sql_sha256",
]


def policy_name(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s.startswith("name:"):
                return s.split(":", 1)[1].strip().strip("'\"")
    raise SystemExit(f"cannot find metadata.name in {path}")


def run_case(binary: str, case: Dict[str, Any]) -> Dict[str, Any]:
    rel = f"test/fixtures/policies/{case['policy']}.yaml"
    proc = subprocess.run(
        [binary, "verify", "--policy", os.path.join(ROOT, rel),
         "--context", json.dumps(case["ctx"]), "--json"],
        input=case["sql"].encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if proc.returncode not in (0, 1):
        raise SystemExit(f"{case['name']}: haltsql exited {proc.returncode}: {proc.stderr.decode()}")
    verdict = json.loads(proc.stdout)
    expect_exit = 0 if verdict["allowed"] else 1
    if proc.returncode != expect_exit:
        raise SystemExit(f"{case['name']}: exit {proc.returncode} disagrees with allowed")
    return {
        "name": case["name"],
        "description": case["desc"],
        "policy_file": rel,
        "request": {
            "sql": case["sql"],
            "context": case["ctx"],
            "policy": policy_name(os.path.join(ROOT, rel)),
        },
        "verdict": verdict,
        "compare": COMPARE,
    }


def _stable(v: Dict[str, Any]) -> Dict[str, Any]:
    v = json.loads(json.dumps(v))
    v["verdict"].pop("elapsed_us", None)
    return v


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--haltsql", default=os.environ.get("HALTSQL_BIN", DEFAULT_BIN))
    ap.add_argument("--check", action="store_true", help="compare instead of writing")
    args = ap.parse_args()
    os.makedirs(CASES_DIR, exist_ok=True)
    names = set()
    drift = 0
    for case in CASES:
        if case["name"] in names:
            raise SystemExit(f"duplicate case name {case['name']}")
        names.add(case["name"])
        vec = run_case(args.haltsql, case)
        path = os.path.join(CASES_DIR, f"{case['name']}.json")
        if args.check:
            try:
                with open(path, encoding="utf-8") as f:
                    old = json.load(f)
            except FileNotFoundError:
                old = None
            if old is None or _stable(old) != _stable(vec):
                print(f"DRIFT {case['name']}")
                drift += 1
        else:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(vec, f, indent=2, ensure_ascii=False)
                f.write("\n")
    if not args.check:
        for fn in os.listdir(CASES_DIR):
            if fn.endswith(".json") and fn[:-5] not in names:
                os.remove(os.path.join(CASES_DIR, fn))
        print(f"wrote {len(CASES)} vectors to {os.path.relpath(CASES_DIR, ROOT)}")
    else:
        print(f"{len(CASES) - drift}/{len(CASES)} vectors up to date")
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main())
