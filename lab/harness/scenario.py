"""Scenario documents (``kind: Scenario``), PLAN.md §8.2.

Only the keys the harness acts on are interpreted; the rest (``topology``,
``tls``, ``identity``, ...) are carried through to the report so a run records
the environment it claims to emulate. Unknown top-level keys are an error, so
typos don't silently change what a scenario tests.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from common.policy import read_document
from compat.engines import ENGINES

TOP_LEVEL_KEYS = {"apiVersion", "kind", "metadata", "environment", "fixture", "schema", "policy",
                  "oracle_policy", "policies", "data", "workloads", "expect", "oracles", "verifier"}

KNOWN_FAULTS = {"policy-reload-during-load", "upstream-db-restart", "audit-sink-down",
                "network-partition", "pod-kill", "cert-expiry", "clock-skew"}
IMPLEMENTED_FAULTS: set[str] = set()  # faults need the server/proxy topologies; reported as TODO


class ScenarioError(ValueError):
    pass


@dataclass
class Workload:
    kind: str  # benign | adversarial | replay
    queries: int = 0
    file: Path | None = None
    transforms: list[str] | None = None


@dataclass
class Expect:
    escapes: int | None = 0
    side_effects: int | None = 0
    column_leaks: int | None = 0
    false_positive_rate_max: float | None = None
    latency_p99_us_max: int | None = None
    min_executed: int | None = None  # guards against a run that silently checked nothing


@dataclass
class Scenario:
    path: Path
    name: str
    fixture: str
    policy_override: Path | None
    postgres: list[int]
    dsn: str | None
    environment: dict[str, Any]
    data: dict[str, Any]
    workloads: list[Workload]
    expect: Expect
    statement_timeout_ms: int = 2000
    erp_tables: int = 420
    faults: list[str] = field(default_factory=list)
    engine: str | None = None  # Postgres flavour with install hooks (lab/compat/engines.py)
    # Ground truth for the oracles (honeytokens, haltlab_cols grants, column-attack
    # targets) when it differs from the policy given to the verifier. None = same.
    oracle_policy: Path | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


def _int_or_none(v: Any, where: str) -> int | None:
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int):
        raise ScenarioError(f"{where}: expected an integer")
    return v


def parse_scenario(doc: dict[str, Any], path: Path) -> Scenario:
    if doc.get("kind") != "Scenario":
        raise ScenarioError(f"{path}: kind must be Scenario")
    unknown = set(doc) - TOP_LEVEL_KEYS
    if unknown:
        raise ScenarioError(f"{path}: unknown top-level keys {sorted(unknown)}")
    meta = doc.get("metadata") or {}
    name = meta.get("name") or path.stem
    env = doc.get("environment") or {}
    pg = env.get("postgres", [17])
    pg_versions = [pg] if isinstance(pg, int) else list(pg)
    if not all(isinstance(v, int) and 13 <= v <= 18 for v in pg_versions):
        raise ScenarioError(f"{path}: environment.postgres must be versions 13-18")

    fixture = doc.get("fixture")
    schema = doc.get("schema")
    if fixture is None and isinstance(schema, str) and schema.startswith("fixture:"):
        fixture = schema.split(":", 1)[1]
    if not isinstance(fixture, str):
        raise ScenarioError(f"{path}: set `fixture: <name>` (saas_shared, composite, hierarchical, erp_large)")

    policy = doc.get("policy")
    policy_override = (path.parent / policy).resolve() if isinstance(policy, str) else None
    oracle_policy = doc.get("oracle_policy")
    oracle_override = (path.parent / oracle_policy).resolve() if isinstance(oracle_policy, str) else None

    workloads: list[Workload] = []
    for i, w in enumerate(doc.get("workloads") or []):
        if not isinstance(w, dict) or len(w) != 1:
            raise ScenarioError(f"{path}: workloads[{i}] must be a single-key mapping")
        (kind, spec), = w.items()
        spec = spec or {}
        if kind not in ("benign", "adversarial", "replay"):
            raise ScenarioError(f"{path}: workloads[{i}]: unknown workload {kind!r}")
        f = spec.get("file")
        workloads.append(Workload(
            kind=kind,
            queries=int(spec.get("queries", 0)),
            file=(path.parent / f).resolve() if f else None,
            transforms=spec.get("transforms"),
        ))
    if not workloads:
        raise ScenarioError(f"{path}: at least one workload is required")

    e = doc.get("expect") or {}
    fpr = e.get("false_positive_rate")
    fpr_max = fpr.get("max") if isinstance(fpr, dict) else fpr
    lat = e.get("latency_p99_us")
    expect = Expect(
        escapes=_int_or_none(e.get("escapes", 0), "expect.escapes"),
        side_effects=_int_or_none(e.get("side_effects", 0), "expect.side_effects"),
        column_leaks=_int_or_none(e.get("column_leaks", 0), "expect.column_leaks"),
        false_positive_rate_max=float(fpr_max) if fpr_max is not None else None,
        latency_p99_us_max=_int_or_none(lat.get("max") if isinstance(lat, dict) else lat,
                                        "expect.latency_p99_us"),
        min_executed=_int_or_none(e.get("min_executed"), "expect.min_executed"),
    )
    faults = list(env.get("faults") or [])
    bad = [f for f in faults if f not in KNOWN_FAULTS]
    if bad:
        raise ScenarioError(f"{path}: unknown faults {bad}; known: {sorted(KNOWN_FAULTS)}")
    engine = env.get("engine")
    if engine is not None and engine not in ENGINES:
        raise ScenarioError(f"{path}: unknown environment.engine {engine!r}; known: {sorted(ENGINES)}")
    oracles = doc.get("oracles") or {}
    return Scenario(
        path=path,
        name=name,
        fixture=fixture,
        policy_override=policy_override,
        postgres=pg_versions,
        dsn=env.get("dsn") or os.environ.get("HALTLAB_DSN"),
        environment=env,
        data=doc.get("data") or {},
        workloads=workloads,
        expect=expect,
        statement_timeout_ms=int(oracles.get("statement_timeout_ms", 2000)),
        erp_tables=int((doc.get("data") or {}).get("tables", 420)),
        faults=faults,
        engine=engine,
        oracle_policy=oracle_override,
        raw=doc,
    )


def load_scenario(path: str | Path) -> Scenario:
    p = Path(path).resolve()
    return parse_scenario(read_document(p), p)
