"""Scenario runner: database -> workloads -> HaltSQL -> oracles -> report."""

from __future__ import annotations

import random
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import psycopg

from common.fixtures import LAB, get_fixture, materialize_generated
from common.policy import load_policy
from compat.engines import get_engine
from generators.redteam import load_jsonl
from generators.sqlspec import SchemaModel
from generators.workload import adversarial_workload, benign_workload
from harness import db as labdb
from harness.oracles import ItemResult, Session, check_item
from harness.report import check_expectations, compute_metrics, corpus_cases, write_corpus, write_reports
from harness.scenario import Scenario
from harness.verifier import verify_batch


def log(msg: str) -> None:
    print(f"[haltlab {time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def build_items(scn: Scenario, model: SchemaModel, universe: Any, fixture_name: str, seed: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    rng = random.Random(f"replay:{seed}")
    for i, w in enumerate(scn.workloads):
        if w.kind == "benign":
            batch = benign_workload(model, universe, w.queries, seed + i, fixture_name)
        elif w.kind == "adversarial":
            batch = adversarial_workload(model, universe, w.queries, seed + i, fixture_name, w.transforms)
        else:
            if w.file is None:
                raise ValueError("replay workload needs `file`")
            batch = list(load_jsonl(w.file, context_for=lambda _n: universe.context_for(universe.sample_unit(rng))))
        for it in batch:  # ids unique across workloads
            it["id"] = f"w{i}-{it['id']}"
        items.extend(batch)
    return items


def run_scenario(scn: Scenario, out_dir: Path, verifier_cmd: list[str], keep_db: bool = False,
                 jobs: int | None = None, policy_path: Path | None = None,
                 oracle_policy_path: Path | None = None, run_id: str | None = None) -> bool:
    """Run ``scn``. ``policy_path`` overrides the policy given to the verifier and
    ``oracle_policy_path`` the ground truth the oracles judge against (honeytoken
    columns, ``haltlab_cols`` grants, column-attack targets); by default both are
    the scenario's ``policy``/``oracle_policy`` or the fixture's policy.
    ``run_id`` is added to database names so concurrent runs do not collide."""
    get_engine(scn.engine).check_dsn(scn.dsn)
    fixture = get_fixture(scn.fixture)
    if fixture.generated:
        fixture = materialize_generated(fixture, out_dir / "fixture", scn.erp_tables, int(scn.data.get("seed", 42)))
    policy_path = Path(policy_path or scn.policy_override or fixture.policy)
    oracle_path = Path(oracle_policy_path or scn.oracle_policy or policy_path)
    # The lab only reads tenancy keys, tables and columns from a policy; the
    # oracles' view (``policy``) is the ground truth, the verifier gets policy_path.
    policy = load_policy(oracle_path)
    regrant = oracle_path.resolve() != Path(fixture.policy).resolve()
    if oracle_path.resolve() != policy_path.resolve():
        log(f"verifier policy {policy_path}; oracles judge against {oracle_path}")
    seed = int(scn.data.get("seed", 42))
    runs: list[dict[str, Any]] = []
    failures: list[str] = []
    all_results: dict[str, ItemResult] = {}
    all_items: list[dict[str, Any]] = []

    for version in scn.postgres:
        admin = labdb.admin_dsn(version, scn.dsn)
        name = labdb.db_name(scn.name, version, run_id)
        log(f"Postgres {version}: creating database {name}")
        dsn = labdb.create_database(admin, name)
        try:
            lab = labdb.install(dsn, fixture, policy, scn.data, scn.engine)
            log(f"loaded {lab.dataset.row_count()} rows into {len(lab.catalog)} tables "
                f"(server {lab.server_version})")
            if regrant:
                n = labdb.apply_column_grants(dsn, policy, lab.catalog)
                log(f"granted {labdb.COLS_ROLE} the allowed columns of {n} relation(s) from {oracle_path.name}")
            for note in lab.engine_notes:
                log(f"engine {scn.engine}: {note}")
            model = SchemaModel.build(policy, fixture.model, lab.catalog)
            items = build_items(scn, model, lab.universe, fixture.name, seed)
            log(f"verifying {len(items)} queries with {' '.join(verifier_cmd)}")
            verdicts = verify_batch(verifier_cmd, policy_path, items, jobs)
            allowed = [it for it in items if verdicts[str(it["id"])].get("allowed")]
            log(f"{len(allowed)} allowed; executing them under the oracles")
            results: dict[str, ItemResult] = {}
            with psycopg.connect(dsn, autocommit=True) as conn:
                session = Session(conn.pgconn)
                for it in allowed:
                    ctx = it.get("context") or {}
                    results[str(it["id"])] = check_item(
                        session, it, verdicts[str(it["id"])], policy.keys, lab.dataset.registry,
                        lab.universe.allowed(ctx), scn.statement_timeout_ms,
                        get_engine(scn.engine).ignored_settings)
            metrics = compute_metrics(lab.server_version, items, verdicts, results)
            run_failures = [f"pg{version}: {f}" for f in check_expectations(metrics, scn.expect)]
            failures += run_failures
            examples = [{"id": r.id, "transform": next((i.get("transform") for i in items
                                                         if str(i["id"]) == r.id), None),
                         "findings": [f"{f.oracle}: {f.detail}" for f in r.findings]}
                        for r in results.values() if r.findings]
            errors_by_state = Counter((r.execution_error or "").split(":", 1)[0].removeprefix("rls run ")
                                      for r in results.values() if r.execution_error)
            runs.append({"postgres_version": version, "metrics": metrics.to_json(), "examples": examples,
                         "engine": scn.engine, "engine_notes": lab.engine_notes,
                         "execution_errors_by_sqlstate": dict(errors_by_state),
                         "execution_error_samples": sorted({r.execution_error[:200] for r in results.values()
                                                            if r.execution_error})[:10]})
            log(f"pg{version}: executed={metrics.executed} escapes={metrics.escapes} "
                f"side_effects={metrics.side_effects} fp_rate={metrics.false_positive_rate:.3f}")
            all_results.update(results)
            all_items.extend(items)
        finally:
            if not keep_db:
                labdb.drop_database(admin, name)

    write_reports(out_dir, scn, runs, failures)
    corpus = write_corpus(out_dir, corpus_cases(all_items, all_results, Path(policy_path).resolve(), scn.name))
    log(f"report: {out_dir / 'report.md'}" + (f"; new corpus cases: {corpus}" if corpus else ""))
    for f in failures:
        log(f"FAIL {f}")
    return not failures


def default_out_dir(scn: Scenario) -> Path:
    return LAB / "out" / scn.name
