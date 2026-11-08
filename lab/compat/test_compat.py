"""Tests for the compatibility runs (docs/compatibility.md).

    cd lab && .venv/bin/python -m pytest compat/test_compat.py                  # unit
    cd lab && .venv/bin/python -m pytest -m integration compat/test_compat.py   # needs the compat profile

The integration tests run against the local engines of the compose profile
``compat`` (lab/compat/run.sh up) and skip an engine whose port is closed.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import psycopg
import pytest

from common.fixtures import LAB
from compat.__main__ import selftest_problems, table
from compat.engines import ENGINES, get_engine
from harness.scenario import ScenarioError, Workload, load_scenario, parse_scenario
from proxy.runner import upstream_tls

SCENARIOS = LAB / "scenarios"
LOCAL = {"pg18": 55418, "supabase": 55419, "alloydb-omni": 55420, "citus": 55421, "timescaledb": 55422}
CLOUD = ("aurora-postgresql", "neon", "supabase-cloud", "alloydb")


# ------------------------------------------------------------------ unit ---

def test_every_compat_scenario_names_a_known_engine():
    files = sorted(SCENARIOS.glob("compat-*.yaml"))
    assert len(files) == len(LOCAL) + len(CLOUD)
    for f in files:
        scn = load_scenario(f)
        assert scn.engine in ENGINES, f
        assert scn.name == f.stem


def test_local_scenarios_pin_their_port_and_cloud_ones_do_not():
    for name, port in LOCAL.items():
        scn = load_scenario(SCENARIOS / f"compat-{name}.yaml")
        assert scn.raw["environment"]["dsn"].endswith(f"@localhost:{port}/postgres")
    for name in CLOUD:
        scn = load_scenario(SCENARIOS / f"compat-{name}.yaml")
        assert "dsn" not in scn.raw["environment"]
        assert get_engine(scn.engine).cloud


def test_unknown_engine_is_a_scenario_error(tmp_path):
    doc = {"apiVersion": "haltsql.dev/v1", "kind": "Scenario", "metadata": {"name": "x"},
           "environment": {"engine": "oracle"}, "fixture": "saas_shared",
           "workloads": [{"benign": {"queries": 1}}]}
    with pytest.raises(ScenarioError, match="unknown environment.engine"):
        parse_scenario(doc, tmp_path / "x.yaml")
    doc["environment"] = {}
    assert parse_scenario(doc, tmp_path / "x.yaml").engine is None


def test_cloud_engine_without_dsn_refuses_to_fall_back_to_the_lab_server():
    with pytest.raises(ValueError, match="HALTLAB_DSN"):
        get_engine("neon").check_dsn(None)
    get_engine("neon").check_dsn("postgresql://u@h/db")
    get_engine("postgres").check_dsn(None)  # local engines may use the default
    with pytest.raises(ValueError, match="unknown engine"):
        get_engine("mysql")


def test_only_citus_ignores_an_engine_owned_setting():
    assert get_engine("citus").ignored_settings == ("enable_self_join_elimination",
                                                   "citus.enable_local_execution")
    assert all(not e.ignored_settings for n, e in ENGINES.items() if n != "citus")


def test_upstream_tls_follows_sslmode(tmp_path):
    assert upstream_tls({}) is None
    assert upstream_tls({"sslmode": "disable"}) is None
    assert upstream_tls({"sslmode": "require"}) == {"mode": "require"}
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    assert upstream_tls({"sslmode": "verify-full", "sslrootcert": str(ca)}) == \
        {"mode": "verify-full", "ca": str(ca.resolve())}
    # verify-ca has no proxy equivalent; the stricter verify-full is used.
    assert upstream_tls({"sslmode": "verify-ca", "sslrootcert": str(ca)})["mode"] == "verify-full"
    with pytest.raises(ValueError, match="sslrootcert"):
        upstream_tls({"sslmode": "verify-full"})
    with pytest.raises(ValueError, match="sslrootcert"):
        upstream_tls({"sslmode": "verify-full", "sslrootcert": "system"})
    for mode in ("prefer", "allow"):  # silent plaintext fallback: refused
        with pytest.raises(ValueError, match="not supported"):
            upstream_tls({"sslmode": mode})


def _metrics(escapes=120, column_leaks=5, side_effects=3, transforms=None):
    t = transforms if transforms is not None else {
        "or_true": {"total": 10, "allowed": 10, "escapes": 8},
        "wrap_cte": {"total": 10, "allowed": 10, "escapes": 0}}
    return {"metrics": {"escapes": escapes, "column_leaks": column_leaks,
                        "side_effects": side_effects, "by_transform": t}}


def test_selftest_problems():
    assert selftest_problems(_metrics()) == []
    assert "only 3 escapes" in selftest_problems(_metrics(escapes=3))[0]
    assert selftest_problems(_metrics(column_leaks=0)) == ["no column leak detected"]
    assert selftest_problems(_metrics(side_effects=0)) == ["no side effect detected"]
    blind = {"or_true": {"total": 5, "allowed": 5, "escapes": 0}}
    assert "transform or_true leaked nothing" in selftest_problems(_metrics(transforms=blind))
    noisy = {"or_true": {"total": 5, "allowed": 5, "escapes": 5},
             "wrap_cte": {"total": 5, "allowed": 5, "escapes": 1}}
    assert any("wrap_cte" in p for p in selftest_problems(_metrics(transforms=noisy)))
    assert "workload has none of the leaky transforms" in selftest_problems(_metrics(transforms={}))


def test_table_renders_one_row_per_summary(tmp_path):
    s = {"scenario": "compat-x", "file": "scenarios/compat-x.yaml", "engine": "postgres",
         "description": "stock PostgreSQL", "server_version": "18.4", "passed": True,
         "selftest": {"passed": True, "escapes": 160, "column_leaks": 30, "side_effects": 20},
         "haltsql": {"executed": 268, "escapes": 0, "side_effects": 0, "execution_errors": 7,
                     "execution_errors_by_sqlstate": {"42P18": 7}},
         "proxy": {"items": 600, "cli_allowed": 268, "proxy_allowed": 268, "parity_mismatches": 0,
                   "escapes": 0}}
    p = tmp_path / "compat-x.json"
    p.write_text(json.dumps(s))
    out = table([p]).splitlines()
    assert out[0].startswith("| Engine | Version | Scenario | Executed | Escapes | Side effects | Proxy parity")
    assert out[2] == ("| stock PostgreSQL | 18.4 | `scenarios/compat-x.yaml` | 268 | 0 | 0 | "
                      "268/268 same decisions of 600, 0 mismatches, 0 escapes | 7 execution errors (42P18: 7); "
                      "oracle self-test caught: 160 escapes, 30 column leaks, 20 side effects; PASS |")


# ----------------------------------------------------------- integration ---

def _reachable(port: int) -> bool:
    try:
        with psycopg.connect(f"postgresql://postgres:haltlab@localhost:{port}/postgres", connect_timeout=3):
            return True
    except Exception:
        return False


@pytest.mark.integration
@pytest.mark.parametrize("name", sorted(LOCAL))
def test_engine_oracles_see_leaks_and_haltsql_has_none(name, tmp_path):
    """On each engine: the allow-everything verifier leaks (so the oracles work
    there) and the real haltsql binary does not."""
    if not _reachable(LOCAL[name]):
        pytest.skip(f"{name} is not running on localhost:{LOCAL[name]} (lab/compat/run.sh up)")
    from harness.runner import run_scenario
    from harness.verifier import fake_verifier_command, resolve_binary
    try:
        haltsql = resolve_binary()
    except FileNotFoundError as e:
        pytest.skip(str(e))
    scn = copy.copy(load_scenario(SCENARIOS / f"compat-{name}.yaml"))
    scn.name = f"{scn.name}_it"  # its own database
    scn.workloads = [Workload("benign", 80), Workload("adversarial", 300)]

    run_scenario(scn, tmp_path / "selftest", fake_verifier_command() + ["--mode", "allow"])
    st = json.loads((tmp_path / "selftest" / "report.json").read_text())["runs"][0]["metrics"]
    assert st["escapes"] > 20 and st["column_leaks"] > 0 and st["side_effects"] > 0, st

    assert run_scenario(scn, tmp_path / "haltsql", haltsql)
    run = json.loads((tmp_path / "haltsql" / "report.json").read_text())["runs"][0]
    m = run["metrics"]
    assert m["escapes"] == 0 and m["side_effects"] == 0 and m["column_leaks"] == 0, m
    assert m["executed"] >= 50, m
    if name in ("citus", "timescaledb"):
        assert run["engine_notes"], "the engine hook must have converted the fixture"
