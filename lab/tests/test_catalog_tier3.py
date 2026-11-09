"""Unit tests for the tier-3 catalog check and the harness options it uses (no database)."""

from __future__ import annotations

from pathlib import Path

from catalogs.tier3 import (TARGETED_TRANSFORM, ManifestColumn, catalog_tables, detected_columns,
                            manifest_columns, resolve_column, structural_check, targeted_queries)
from common.fixtures import get_fixture
from common.policy import load_policy, parse_policy
from common.tenancy import build_universe
from datagen.catalog import ColumnInfo, TableInfo
from generators.evasion import TRANSFORMS
from generators.sqlspec import SchemaModel
from generators.workload import adversarial_workload
from harness.db import column_grant_statements, db_name
from harness.scenario import parse_scenario

LAB = Path(__file__).resolve().parent.parent

MANIFEST = {"metadata": {"source": "dbt"}, "tables": {
    "app.customers": {"columns": {"ssn": {"classifications": ["pii"]}, "Email": {"classifications": ["pii"]}}},
    "users": {"columns": {"password_hash": {"classifications": ["secret"]}}},
    "app.users": {"columns": {"tenant_id": {"classifications": ["pii"]}}},
    "app.gone": {"columns": {"x": {"classifications": ["pii"]}}},
}}

CATALOG = {"kind": "Catalog", "metadata": {"relations": {"app.customers": "table", "app.users": "table",
                                                         "app.users_id_seq": "sequence"}},
           "tables": {"app.customers": {"columns": [{"name": n, "type": "text"} for n in
                                                    ("id", "tenant_id", "name", "email", "ssn")]},
                      "app.users": {"columns": [{"name": n, "type": "text"} for n in
                                                ("id", "tenant_id", "password_hash", "role")]},
                      "app.users_id_seq": {"columns": [{"name": "last_value", "type": "bigint"}]}}}


def _policy(customers_cols, users_cols):
    return parse_policy({"kind": "Policy", "search_path": ["app"], "tenancy": {"mode": "bound", "keys": {
        "tenant": "${ctx.tenant_id}"}}, "tables": {
        "app.customers": {"columns": customers_cols, "tenant_column": "tenant_id"},
        "app.users": {"columns": users_cols, "tenant_column": "tenant_id"}}})


def test_manifest_and_catalog_parsing():
    cols = manifest_columns(MANIFEST)
    assert ManifestColumn("app", "customers", "ssn", ("pii",)) in cols
    assert any(c.schema is None and c.table == "users" for c in cols)
    tables = catalog_tables(CATALOG)
    assert set(tables) == {("app", "customers"), ("app", "users")}  # sequences dropped
    assert resolve_column(ManifestColumn("app", "customers", "Email"), tables) == [("app", "customers", "email")]
    assert resolve_column(ManifestColumn(None, "users", "password_hash"), tables) == [
        ("app", "users", "password_hash")]


def test_structural_check_passes_when_manifest_columns_excluded():
    pol = _policy(["id", "tenant_id", "name"], ["id", "tenant_id", "role"])
    r = structural_check(manifest_columns(MANIFEST), catalog_tables(CATALOG), pol, "tenant_id")
    assert r.ok
    assert sorted(r.targets) == [("app", "customers", "email"), ("app", "customers", "ssn"),
                                 ("app", "users", "password_hash")]
    assert r.missing == ["app.gone.x"] and r.tenant_skipped == ["app.users.tenant_id"]


def test_structural_check_fails_when_tagged_column_allowed_or_nothing_matches():
    pol = _policy("*", ["id", "tenant_id", "role"])
    r = structural_check(manifest_columns(MANIFEST), catalog_tables(CATALOG), pol, "tenant_id")
    assert not r.ok and len(r.failures) == 2  # customers.email and customers.ssn
    empty = structural_check([], catalog_tables(CATALOG), pol, "tenant_id")
    assert not empty.ok and "prove nothing" in empty.failures[0]


def test_targeted_queries_cover_every_column_with_tenant_predicates():
    pol = _policy(["id", "tenant_id", "name"], ["id", "tenant_id", "role"])
    targets = [("app", "customers", "ssn"), ("app", "users", "password_hash")]
    items = targeted_queries(targets, catalog_tables(CATALOG), pol, "single")
    assert {it["transform"] for it in items} == {TARGETED_TRANSFORM}
    assert len({it["id"] for it in items}) == len(items)
    assert all("a.tenant_id = $1" in it["sql"] for it in items)
    per_col = [it for it in items if it["target"]["column"] == "ssn"]
    assert per_col and all("ssn" in it["sql"] for it in per_col)
    kinds = {it["id"].rsplit("-", 1)[1] for it in items}
    assert {"star", "alias_star", "cte_star", "row_to_json", "to_json", "json_agg", "whole_row",
            "direct", "predicate", "cte", "scalar_subquery"} <= kinds


def test_detected_columns_attribution():
    targets = {"t3-app.customers.ssn-only": {"table": "app.customers", "column": "ssn"},
               "t3-app.customers-star": {"table": "app.customers", "column": None}}
    examples = [
        {"id": "w0-a-000001", "findings": ["honeytoken: column marker HTCOL-app_users-email-3 from app.users.email"]},
        {"id": "w3-t3-app.customers.ssn-only", "findings": ["columns: permission denied for table customers"]},
        {"id": "w3-t3-app.customers-star", "findings": ["columns: permission denied for table customers"]},
    ]
    assert detected_columns(examples, targets) == {("app.users", "email"), ("app.customers", "ssn")}


def test_column_grants_follow_policy():
    cat = [TableInfo("app", "customers", "r", [ColumnInfo(n, "text") for n in ("id", "tenant_id", "ssn")]),
           TableInfo("app", "users", "r", [ColumnInfo(n, "text") for n in ("id", "role")]),
           TableInfo("app", "secret", "r", [ColumnInfo("x", "text")])]
    pol = _policy(["id", "tenant_id", "not_in_db"], "*")
    stmts = column_grant_statements(pol, cat)
    assert stmts[0] == "REVOKE ALL ON ALL TABLES IN SCHEMA app FROM haltlab_cols"
    assert "GRANT SELECT (id, tenant_id) ON app.customers TO haltlab_cols" in stmts
    assert "GRANT SELECT ON app.users TO haltlab_cols" in stmts
    assert not any("secret" in s for s in stmts)  # not in the policy: no grant


def test_db_name_run_id_unique_and_bounded():
    assert db_name("pr-smoke", 17) == "haltlab_pr_smoke_pg17"
    a, b = db_name("catalog-tier3", 17, "1_ab"), db_name("catalog-tier3", 17, "2_cd")
    assert a != b and a.endswith("_pg17")
    assert len(db_name("x" * 80, 17, "run")) <= 63 and db_name("x" * 80, 17, "run").endswith("_pg17")


def test_scenario_oracle_policy(tmp_path):
    scn = parse_scenario({"kind": "Scenario", "fixture": "saas_shared", "policy": "p.yaml",
                          "oracle_policy": "truth.yaml", "workloads": [{"benign": {}}]}, tmp_path / "s.yaml")
    assert scn.policy_override == (tmp_path / "p.yaml").resolve()
    assert scn.oracle_policy == (tmp_path / "truth.yaml").resolve()


def test_new_column_transforms_generate_column_attacks():
    fx = get_fixture("saas_shared")
    pol = load_policy(fx.policy)
    cat = [TableInfo("app", "customers", "r", [ColumnInfo(n, "text") for n in
            ("id", "tenant_id", "name", "email", "phone", "ssn", "country", "created_at")], pk=("id",))]
    m = SchemaModel.build(pol, fx.model, cat)  # the catalog makes email/phone/ssn "denied"
    u = build_universe(fx.model, pol.keys, 6)
    names = ["star_over_pii_wrapped", "whole_row_wrapped", "denied_column_wrapped"]
    assert all(n in TRANSFORMS for n in names)
    items = adversarial_workload(m, u, 30, 3, fx.name, names)
    assert {it["transform"] for it in items} == set(names)
    assert all(it["intent"] == "adversarial" and it["leak"] == "column" for it in items)
