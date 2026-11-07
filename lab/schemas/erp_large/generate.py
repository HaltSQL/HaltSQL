#!/usr/bin/env python3
"""Generate the erp_large fixture: 400+ tables across 12 schemas, plus its policy.

Deterministic for a given (tables, seed). Exercises (PLAN.md §8.2):
  * mixed-case quoted schema/table/column names ("Reporting", "GLAccount", "CustomerRef")
  * reserved words as column names ("order", "user", "group")
  * range-partitioned tables (with a DEFAULT partition) and their partitions
  * a view and a materialized view
  * JSONB, arrays, enums, domains, stored generated columns
  * soft-delete flags (is_deleted, deleted_at), legacy tbl_ prefixes
  * duplicate column names across tables (id, name, status, code, ...)
  * global lookup tables (no tenant column) and tables denied by the policy

Usage:
  python schemas/erp_large/generate.py --tables 420 --seed 7 --out out/_generated/erp
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import Any

LAB = Path(__file__).resolve().parents[2]
if str(LAB) not in sys.path:
    sys.path.insert(0, str(LAB))

from common.ident import qi, qname  # noqa: E402

SCHEMAS: tuple[str, ...] = (
    "finance", "sales", "hr", "inventory", "procurement", "manufacturing",
    "crm", "logistics", "legacy", "Reporting", "projects", "Assets",
)
NOUNS: dict[str, tuple[str, ...]] = {
    "finance": ("GLAccount", "journal", "ledger_entry", "cost_center", "budget", "fiscal_period", "tax_code", "accrual"),
    "sales": ("orders", "order_line", "quote", "price_list", "discount", "territory", "commission", "return"),
    "hr": ("employee", "salary", "position", "department", "leave_request", "review", "benefit", "payslip"),
    "inventory": ("item", "warehouse", "bin", "stock_move", "lot", "serial", "adjustment", "count_sheet"),
    "procurement": ("PurchaseOrder", "supplier", "rfq", "requisition", "receipt", "contract", "catalog", "invoice_match"),
    "manufacturing": ("work_order", "bom", "routing", "machine", "operation", "scrap", "shift", "quality_check"),
    "crm": ("lead", "contact", "campaign", "opportunity", "ticket", "note", "segment", "survey"),
    "logistics": ("shipment", "carrier", "route", "parcel", "dock", "manifest", "tracking_event", "rate_card"),
    "legacy": ("tbl_cust_mstr", "tbl_ord_hdr", "tbl_ord_dtl", "tbl_prod", "tbl_emp", "tbl_xref", "tbl_audit", "tbl_cfg"),
    "Reporting": ("KpiSnapshot", "dashboard", "export_job", "metric", "report_run", "subscription", "alert", "widget"),
    "projects": ("project", "milestone", "timesheet", "task", "risk", "issue", "deliverable", "resource_plan"),
    "Assets": ("Asset", "depreciation", "maintenance", "location", "license", "lease", "disposal", "inspection"),
}
SUFFIXES: tuple[str, ...] = ("", "_hist", "_archive", "_staging", "_v2", "_detail", "_summary", "_map", "_log", "_ext")
SENSITIVE: tuple[tuple[str, str], ...] = (
    ("ssn", "text"), ("salary", "numeric(12,2)"), ("iban", "text"), ("api_secret", "text"),
    ("email", "finance.email_address"), ("password_hash", "text"), ("dob", "date"),
)
EXTRA_POOL: tuple[tuple[str, str], ...] = (
    ("order", "integer"), ("user", "text"), ("group", "text"), ("code", "varchar(32)"),
    ("amount", "finance.money_amount"), ("qty", "integer"), ("tags", "text[]"), ("attrs", "jsonb"),
    ("notes", "text"), ("CustomerRef", "text"), ("ExternalID", "text"), ("priority", "{s}.priority_t"),
    ("score", "double precision"), ("valid_from", "date"), ("ratio", "numeric(5,4)"), ("flags", "integer[]"),
    ("description", "text"), ("region", "text"),
)
UNIT_TABLES: tuple[str, ...] = ()


def _rel(schema: str, name: str) -> str:
    return qname(schema, name)


def generate(tables: int = 420, seed: int = 7) -> tuple[str, dict[str, Any]]:
    rng = random.Random(seed)
    per_schema = max(1, -(-tables // len(SCHEMAS)))  # ceil
    out: list[str] = [
        f"-- haltlab fixture: erp_large (generated: tables={tables}, seed={seed}). Do not edit.",
        "DO $$ BEGIN",
        "  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'haltlab_owner') THEN CREATE ROLE haltlab_owner NOLOGIN; END IF;",
        "  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'haltlab_rls') THEN CREATE ROLE haltlab_rls NOLOGIN NOBYPASSRLS; END IF;",
        "  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'haltlab_cols') THEN CREATE ROLE haltlab_cols NOLOGIN NOBYPASSRLS; END IF;",
        "  EXECUTE format('GRANT haltlab_owner, haltlab_rls, haltlab_cols TO %I', current_user);",
        "END $$;",
    ]
    for s in SCHEMAS:
        out.append(f"CREATE SCHEMA IF NOT EXISTS {qi(s)} AUTHORIZATION haltlab_owner;")
    out += [
        "CREATE DOMAIN finance.email_address AS text CHECK (VALUE LIKE '%@%');",
        "CREATE DOMAIN finance.money_amount AS numeric(14,2) CHECK (VALUE >= 0);",
    ]
    for s in SCHEMAS:
        out.append(f"CREATE TYPE {qi(s)}.status_t AS ENUM ('draft', 'active', 'on_hold', 'closed', 'archived');")
        out.append(f"CREATE TYPE {qi(s)}.priority_t AS ENUM ('low', 'normal', 'high', 'urgent');")

    policy_tables: dict[str, Any] = {}
    sales_orders: tuple[str, str] | None = None
    total = 0
    for s in SCHEMAS:
        made: list[str] = []
        names: list[str] = []
        for suf in SUFFIXES:
            for noun in NOUNS[s]:
                names.append(noun + suf if not noun[0].isupper() else noun + suf.title().replace("_", ""))
        for tname in names[:per_schema]:
            if total >= tables:
                break
            global_table = rng.random() < 0.08 or tname.endswith("_map")
            cols: list[tuple[str, str]] = [("id", "bigserial")]
            if not global_table:
                cols.append(("tenant_id", "text NOT NULL"))
            cols += [("name", "text NOT NULL"), ("status", f"{qi(s)}.status_t NOT NULL DEFAULT 'active'"),
                     ("created_at", "timestamptz NOT NULL")]
            extras = rng.sample(EXTRA_POOL, k=rng.randint(2, 6))
            for cname, ctype in extras:
                cols.append((cname, ctype.format(s=qi(s))))
            ecn = {c for c, _ in extras}
            if "amount" in ecn and "qty" in ecn:
                cols.append(("line_total", "numeric GENERATED ALWAYS AS (amount * qty) STORED"))
            if rng.random() < 0.5:
                cols.append(("is_deleted", "boolean NOT NULL DEFAULT false"))
                cols.append(("deleted_at", "timestamptz"))
            sens: list[str] = []
            if s == "hr" or rng.random() < 0.3:
                for cname, ctype in rng.sample(SENSITIVE, k=rng.randint(1, 2)):
                    cols.append((cname, ctype))
                    sens.append(cname)
            if made and rng.random() < 0.4:
                parent = rng.choice(made)
                cols.append(("parent_id", f"bigint REFERENCES {_rel(s, parent)} (id)"))
            body = ",\n  ".join(f"{qi(c)} {t}" for c, t in cols)
            out.append(f"CREATE TABLE {_rel(s, tname)} (\n  {body},\n  PRIMARY KEY (id)\n);")
            made.append(tname)
            total += 1
            if s == "sales" and tname == "orders":
                sales_orders = (s, tname)
            # policy: deny ~12% of tables entirely; hr salary tables always denied
            denied_table = (s == "hr" and "salary" in tname) or rng.random() < 0.12
            if denied_table:
                continue
            allowed = [c for c, _ in cols if c not in sens]
            if not sens and global_table and rng.random() < 0.7:
                entry: dict[str, Any] = {"columns": "*"}
            else:
                if len(allowed) > 5 and rng.random() < 0.2:
                    allowed.remove(rng.choice([c for c in allowed if c not in ("id", "tenant_id")]))
                entry = {"columns": [_pcol(c) for c in allowed]}
            if not global_table:
                entry["tenant_column"] = "tenant_id"
            policy_tables[_pkey(s, tname)] = entry

        # one partitioned table per schema (parent counted as a table)
        if total < tables + len(SCHEMAS):
            pname = "Events" if s[0].isupper() else "events"
            prel = _rel(s, pname)
            out.append(
                f"CREATE TABLE {prel} (\n  id bigserial,\n  tenant_id text NOT NULL,\n  kind text NOT NULL,\n"
                f"  payload jsonb NOT NULL,\n  {qi('user')} text,\n  created_at timestamptz NOT NULL,\n"
                f"  PRIMARY KEY (id, created_at)\n) PARTITION BY RANGE (created_at);"
            )
            for y in (2024, 2025, 2026):
                out.append(
                    f"CREATE TABLE {_rel(s, f'{pname}_{y}')} PARTITION OF {prel} "
                    f"FOR VALUES FROM ('{y}-01-01') TO ('{y + 1}-01-01');"
                )
            out.append(f"CREATE TABLE {_rel(s, f'{pname}_default')} PARTITION OF {prel} DEFAULT;")
            total += 1
            policy_tables[_pkey(s, pname)] = {
                "columns": ["id", "tenant_id", "kind", "payload", _pcol("user"), "created_at"],
                "tenant_column": "tenant_id",
            }

    # view + materialized view over sales.orders
    if sales_orders is None:
        raise RuntimeError("generator invariant: sales.orders missing (tables too small?)")
    so = _rel(*sales_orders)
    out += [
        f'CREATE VIEW "Reporting".v_open_orders AS\n  SELECT id, tenant_id, name, status, created_at FROM {so}\n'
        "  WHERE status IN ('draft', 'active', 'on_hold');",
        f'CREATE MATERIALIZED VIEW "Reporting".mv_orders_by_month AS\n'
        f"  SELECT tenant_id, date_trunc('month', created_at) AS month, count(*) AS orders\n"
        f"  FROM {so} GROUP BY 1, 2 WITH NO DATA;",
        # PG15+: make the view respect RLS of the caller (oracle accuracy)
        "DO $$ BEGIN IF current_setting('server_version_num')::int >= 150000 THEN "
        "EXECUTE 'ALTER VIEW \"Reporting\".v_open_orders SET (security_invoker = true)'; END IF; END $$;",
    ]
    policy_tables['"Reporting".v_open_orders'] = {
        "columns": ["id", "tenant_id", "name", "status", "created_at"], "tenant_column": "tenant_id"}
    policy_tables['"Reporting".mv_orders_by_month'] = {
        "columns": ["tenant_id", "month", "orders"], "tenant_column": "tenant_id"}

    schemas_arr = ", ".join("'" + s + "'" for s in SCHEMAS)
    out += [
        "-- ownership, RLS (every relation with a tenant_id column, partitions included), grants",
        "DO $$ DECLARE r record; BEGIN",
        "  FOR r IN SELECT n.nspname, c.relname, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace",
        f"           WHERE n.nspname IN ({schemas_arr}) AND c.relkind IN ('r', 'p', 'v', 'm') LOOP",
        "    IF r.relkind = 'v' THEN EXECUTE format('ALTER VIEW %I.%I OWNER TO haltlab_owner', r.nspname, r.relname);",
        "    ELSIF r.relkind = 'm' THEN EXECUTE format('ALTER MATERIALIZED VIEW %I.%I OWNER TO haltlab_owner', r.nspname, r.relname);",
        "    ELSE EXECUTE format('ALTER TABLE %I.%I OWNER TO haltlab_owner', r.nspname, r.relname); END IF;",
        "  END LOOP;",
        "  FOR r IN SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace",
        "           JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped",
        f"           WHERE n.nspname IN ({schemas_arr}) AND c.relkind IN ('r', 'p') LOOP",
        "    EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', r.nspname, r.relname);",
        "    EXECUTE format($p$CREATE POLICY haltlab_tenant ON %I.%I FOR SELECT TO haltlab_rls, haltlab_cols "
        "USING (tenant_id = current_setting('app.tenant_id', true))$p$, r.nspname, r.relname);",
        "  END LOOP;",
        "END $$;",
    ]
    for s in SCHEMAS:
        out.append(f"GRANT USAGE ON SCHEMA {qi(s)} TO haltlab_rls, haltlab_cols;")
        out.append(f"GRANT SELECT ON ALL TABLES IN SCHEMA {qi(s)} TO haltlab_rls;")
        out.append(f"REVOKE ALL ON ALL TABLES IN SCHEMA {qi(s)} FROM haltlab_cols;")
    for key, entry in policy_tables.items():
        rel = key  # policy keys are already valid SQL relation names
        if entry["columns"] == "*":
            out.append(f"GRANT SELECT ON {rel} TO haltlab_cols;")
        else:
            out.append(f"GRANT SELECT ({', '.join(entry['columns'])}) ON {rel} TO haltlab_cols;")

    policy: dict[str, Any] = {
        "apiVersion": "haltsql.dev/v1",
        "kind": "Policy",
        "metadata": {"name": "haltlab-erp-large", "owner": "haltlab",
                     "description": f"generated: tables={tables}, seed={seed}"},
        "dialect": "postgres-17",
        "search_path": ["sales", "finance"],
        "limits": {"max_bytes": 16384, "max_depth": 64, "max_nodes": 20000, "max_joins": 8},
        "statements": {"allow": ["select"]},
        "require_limit": {"max": 1000},
        "tenancy": {"mode": "bound", "keys": {"tenant": "${ctx.tenant_id}"}},
        "tables": policy_tables,
        "functions": {"allow": ["count", "sum", "avg", "min", "max", "coalesce", "date_trunc",
                                "lower", "upper", "now", "round"]},
        "mode": "enforce",
    }
    return "\n".join(out) + "\n", policy


def _pcol(c: str) -> str:
    """Policy column spelling: quote when case/reserved word requires it."""
    return qi(c)


def _pkey(schema: str, name: str) -> str:
    return qname(schema, name)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tables", type=int, default=420)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, default=LAB / "out" / "_generated" / "erp_large")
    a = ap.parse_args(argv)
    import yaml

    sql, policy = generate(a.tables, a.seed)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "erp_large.sql").write_text(sql, encoding="utf-8")
    (a.out / "erp_large.yaml").write_text(yaml.safe_dump(policy, sort_keys=False, width=1000), encoding="utf-8")
    print(f"wrote {a.out}/erp_large.sql and erp_large.yaml ({len(policy['tables'])} policy tables)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
