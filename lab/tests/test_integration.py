"""Integration tests: need `make up` (Postgres 17 on localhost:5417).

The key self-test: with an allow-everything verifier the oracles MUST find
escapes and side effects; with a deny-everything verifier nothing runs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import psycopg
import pytest

from harness.runner import run_scenario
from harness.scenario import load_scenario
from harness.verifier import fake_verifier_command, resolve_binary

LAB = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.integration


def _db_available() -> bool:
    dsn = os.environ.get("HALTLAB_DSN", "postgresql://postgres:haltlab@localhost:5417/postgres")
    try:
        with psycopg.connect(dsn.replace("{port}", "5417").replace("{version}", "17"), connect_timeout=2):
            return True
    except Exception:
        return False


needs_db = pytest.mark.skipif(not _db_available(), reason="Postgres not running (make up)")


@needs_db
def test_oracles_catch_everything_an_allow_all_verifier_lets_through(tmp_path):
    scn = load_scenario(LAB / "scenarios/oracle-selftest.yaml")
    run_scenario(scn, tmp_path, fake_verifier_command() + ["--mode", "allow"])
    m = json.loads((tmp_path / "report.json").read_text())["runs"][0]["metrics"]
    assert m["escapes"] > 50, m
    assert m["column_leaks"] > 0
    assert m["side_effects"] > 0
    t = m["by_transform"]
    # Unfiltered tenant reads must be caught; filtered, meaning-preserving rewrites must not be.
    for leaky in ("union_unfiltered_branch", "or_true", "left_join_preserved_side", "star_over_pii"):
        assert t[leaky]["escapes"] > 0, leaky
    for safe in ("wrap_cte", "wrap_subquery", "quoted_identifiers", "explain_plain"):
        assert t[safe]["escapes"] == 0, safe
    assert (tmp_path / "new_corpus_cases.yaml").exists()


@needs_db
def test_deny_all_verifier_executes_nothing(tmp_path):
    scn = load_scenario(LAB / "scenarios/oracle-selftest.yaml")
    run_scenario(scn, tmp_path, fake_verifier_command() + ["--mode", "deny"])
    m = json.loads((tmp_path / "report.json").read_text())["runs"][0]["metrics"]
    assert m["executed"] == 0


@needs_db
def test_haltsql_smoke_has_no_escapes(tmp_path):
    try:
        cmd = resolve_binary()
    except FileNotFoundError:
        pytest.skip("haltsql binary not built")
    scn = load_scenario(LAB / "scenarios/pr-smoke.yaml")
    assert run_scenario(scn, tmp_path, cmd)


@needs_db
def test_catalog_tier3_dbt_example_blocks_tagged_pii_and_negative_control_leaks(tmp_path):
    """catalogs/tier3.py on examples/metadata/dbt_manifest.json: the positive run is
    clean, and without the catalog tags every tagged column is seen leaking."""
    import subprocess

    from catalogs.tier3 import main as tier3_main

    try:
        cmd = resolve_binary()
    except FileNotFoundError:
        pytest.skip("haltsql binary not built")
    pii = tmp_path / "pii.json"
    subprocess.run([*cmd, "schema", "import", "--from", "dbt",
                    str(LAB.parent / "examples/metadata/dbt_manifest.json"), "-o", str(pii)],
                   check=True, capture_output=True)
    out = tmp_path / "t3"
    rc = tier3_main(["--pii", str(pii), "--out", str(out), "--benign", "60", "--adversarial", "120",
                     "--column-attacks", "60"])
    summary = json.loads((out / "summary.json").read_text())
    assert rc == 0, summary["failures"]
    assert summary["positive"]["escapes"] == 0 and summary["positive"]["targeted_allowed"] == 0
    assert summary["negative"]["column_leaks"] > 0 and not summary["negative"]["undetected"]
    assert "app.users.full_name" in summary["negative"]["detected"]  # tagged by dbt, granted by the fixture SQL

    empty = tmp_path / "empty.json"
    empty.write_text('{"tables": {}}')
    assert tier3_main(["--pii", str(empty), "--out", str(tmp_path / "e"), "--mode", "positive"]) == 1
