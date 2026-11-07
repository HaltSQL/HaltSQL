"""Unit tests for the harness that need no database."""

from __future__ import annotations

from pathlib import Path

import pytest

from common.fixtures import get_fixture
from common.policy import load_policy
from common.tenancy import build_universe
from datagen.honeytokens import Registry, classify, extract_markers
from generators.sqlspec import SchemaModel
from generators.workload import adversarial_workload, benign_workload
from harness.oracles import Finding, ItemResult, bind_values, encode_param, is_explain, tenancy_settings
from harness.report import check_expectations, compute_metrics, corpus_cases, percentile
from harness.scenario import Expect, ScenarioError, load_scenario, parse_scenario

LAB = Path(__file__).resolve().parent.parent


def test_encode_param_scalar_and_array():
    assert encode_param("acme") == b"acme"
    assert encode_param(None) is None
    assert encode_param(["a", 'b"c', "d\\e"]) == b'{"a","b\\"c","d\\\\e"}'


def test_bind_values_positional_with_gaps():
    v = {"bind_params": [{"param": 2, "value": "acme"}]}
    assert bind_values(v) == [None, b"acme"]
    assert bind_values({"bind_params": []}) == []


def test_tenancy_settings_lists_join():
    keys = [("tenant", "tenant_ids")]
    assert tenancy_settings(keys, {"tenant_ids": ["a", "b"]}) == [("app.tenant_ids", "a,b")]
    assert tenancy_settings([("t", "tenant_id")], {}) == [("app.tenant_id", "")]


def test_is_explain():
    assert is_explain("explain select 1")
    assert is_explain("/* c */\n-- x\n  EXPLAIN (ANALYZE) delete from t")
    assert not is_explain("select 'explain'")


def test_percentile():
    assert percentile([], 99) == 0
    assert percentile(list(range(1, 101)), 50) in (50, 51)
    assert percentile([5], 99) == 5


def test_all_scenarios_parse():
    for p in sorted((LAB / "scenarios").glob("*.yaml")):
        load_scenario(p)


def test_scenario_rejects_unknown_keys(tmp_path):
    with pytest.raises(ScenarioError):
        parse_scenario({"kind": "Scenario", "fixture": "saas_shared", "workloads": [{"benign": {}}],
                        "typo": 1}, tmp_path / "x.yaml")
    with pytest.raises(ScenarioError):
        parse_scenario({"kind": "Scenario", "fixture": "saas_shared", "workloads": []}, tmp_path / "x.yaml")


def _workload(n=40):
    fx = get_fixture("saas_shared")
    pol = load_policy(fx.policy)
    m = SchemaModel.build(pol, fx.model)
    u = build_universe(fx.model, pol.keys, 6)
    return benign_workload(m, u, n, 1, fx.name) + adversarial_workload(m, u, n, 1, fx.name)


def test_workloads_are_deterministic():
    assert _workload() == _workload()


def test_metrics_and_expectations():
    items = [{"id": "1", "intent": "benign", "transform": "none"},
             {"id": "2", "intent": "benign", "transform": "none"},
             {"id": "3", "intent": "adversarial", "transform": "or_true"}]
    verdicts = {"1": {"allowed": True, "elapsed_us": 10}, "2": {"allowed": False, "elapsed_us": 20,
                "reasons": [{"code": "E_TENANT_MISSING"}]}, "3": {"allowed": True, "elapsed_us": 30}}
    results = {"1": ItemResult("1", True), "3": ItemResult("3", True, [Finding("rls", "1 row")])}
    m = compute_metrics("17", items, verdicts, results)
    assert (m.benign_denied, m.adversarial_allowed, m.executed, m.escapes) == (1, 1, 2, 1)
    assert m.false_positive_rate == 0.5
    assert m.deny_codes == {"E_TENANT_MISSING": 1}
    fails = check_expectations(m, Expect(escapes=0, false_positive_rate_max=0.1, min_executed=5))
    assert len(fails) == 3


def test_corpus_cases_only_for_escapes():
    items = [{"id": "a", "sql": "SELECT 1", "context": {}, "transform": "t"},
             {"id": "b", "sql": "SELECT 2", "context": {}, "transform": "t"}]
    results = {"a": ItemResult("a", True, [Finding("honeytoken", "tenant marker")]), "b": ItemResult("b", True)}
    doc = corpus_cases(items, results, Path("/p.yaml"), "s")
    assert doc["kind"] == "TestSuite" and [c["sql"] for c in doc["cases"]] == ["SELECT 1"]
    assert corpus_cases(items, {"b": ItemResult("b", True)}, Path("/p.yaml"), "s") is None


def test_honeytoken_classification():
    reg = Registry(owners={"t000": {"tenant": "acme"}, "t001": {"tenant": "globex"}},
                   tables={"app_orders": "app.orders"})
    rows = [("x HT-t000-app_orders-1 y",), ("HT-t001-app_orders-2",), ("HTCOL-app_orders-ssn-3",)]
    leaks = classify(extract_markers(rows), reg, {"tenant": {"acme"}})
    assert sorted(l.kind for l in leaks) == ["column", "tenant"]
