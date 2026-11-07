"""Metrics, expectation checks, and report / corpus-case writers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from harness.oracles import ItemResult
from harness.scenario import IMPLEMENTED_FAULTS, Expect


def percentile(values: list[int], p: float) -> int:
    if not values:
        return 0
    s = sorted(values)
    k = min(len(s) - 1, max(0, int(round(p / 100 * (len(s) - 1)))))
    return s[k]


@dataclass
class RunMetrics:
    postgres: str
    total: int = 0
    benign_total: int = 0
    benign_denied: int = 0
    adversarial_total: int = 0
    adversarial_allowed: int = 0
    executed: int = 0
    escapes: int = 0
    column_leaks: int = 0
    side_effects: int = 0
    timeouts: int = 0
    execution_errors: int = 0
    latency_us: dict[str, int] = field(default_factory=dict)
    by_transform: dict[str, dict[str, int]] = field(default_factory=dict)
    deny_codes: dict[str, int] = field(default_factory=dict)

    @property
    def false_positive_rate(self) -> float:
        return self.benign_denied / self.benign_total if self.benign_total else 0.0

    def to_json(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["false_positive_rate"] = round(self.false_positive_rate, 5)
        return d


def compute_metrics(postgres: str, items: list[dict[str, Any]], verdicts: dict[str, dict[str, Any]],
                    results: dict[str, ItemResult]) -> RunMetrics:
    m = RunMetrics(postgres=postgres)
    lat = []
    for it in items:
        v = verdicts[str(it["id"])]
        m.total += 1
        allowed = bool(v.get("allowed"))
        lat.append(int(v.get("elapsed_us") or 0))
        bt = m.by_transform.setdefault(it.get("transform") or "none",
                                       {"total": 0, "allowed": 0, "escapes": 0})
        bt["total"] += 1
        if allowed:
            bt["allowed"] += 1
        for r in v.get("reasons") or []:
            m.deny_codes[r["code"]] = m.deny_codes.get(r["code"], 0) + 1
        if it.get("intent") == "benign":
            m.benign_total += 1
            m.benign_denied += 0 if allowed else 1
        else:
            m.adversarial_total += 1
            m.adversarial_allowed += 1 if allowed else 0
        r = results.get(str(it["id"]))
        if r is None or not r.executed:
            continue
        m.executed += 1
        if r.escape:
            m.escapes += 1
            bt["escapes"] += 1
        m.column_leaks += 1 if r.column_leak else 0
        m.side_effects += 1 if r.side_effect else 0
        m.timeouts += 1 if any(f.oracle == "timeout" for f in r.findings) else 0
        m.execution_errors += 1 if r.execution_error else 0
    m.latency_us = {"p50": percentile(lat, 50), "p95": percentile(lat, 95), "p99": percentile(lat, 99),
                    "max": max(lat) if lat else 0}
    return m


def check_expectations(m: RunMetrics, e: Expect) -> list[str]:
    failures = []
    if e.escapes is not None and m.escapes > e.escapes:
        failures.append(f"escapes {m.escapes} > {e.escapes}")
    if e.column_leaks is not None and m.column_leaks > e.column_leaks:
        failures.append(f"column leaks {m.column_leaks} > {e.column_leaks}")
    if e.side_effects is not None and m.side_effects > e.side_effects:
        failures.append(f"side effects {m.side_effects} > {e.side_effects}")
    if e.false_positive_rate_max is not None and m.false_positive_rate > e.false_positive_rate_max:
        failures.append(f"false-positive rate {m.false_positive_rate:.4f} > {e.false_positive_rate_max}")
    if e.latency_p99_us_max is not None and m.latency_us.get("p99", 0) > e.latency_p99_us_max:
        failures.append(f"p99 latency {m.latency_us['p99']}us > {e.latency_p99_us_max}us")
    if e.min_executed is not None and m.executed < e.min_executed:
        failures.append(f"only {m.executed} allowed queries executed (< {e.min_executed})")
    return failures


def corpus_cases(items: list[dict[str, Any]], results: dict[str, ItemResult], policy: Path,
                 scenario: str) -> dict[str, Any] | None:
    """A TestSuite document (lib/load/test_suite.mli) with one deny case per escape."""
    cases = []
    by_id = {str(it["id"]): it for it in items}
    for rid, r in results.items():
        if not (r.escape or r.side_effect):
            continue
        it = by_id[rid]
        cases.append({
            "name": f"haltlab {scenario} {it.get('transform', 'none')} {rid}",
            "sql": it["sql"],
            "context": it["context"],
            "expect": "deny",
            "tags": ["haltlab", str(it.get("transform", "none"))],
            "found_by": [f"{f.oracle}: {f.detail}" for f in r.findings],
        })
    if not cases:
        return None
    return {"apiVersion": "haltsql.dev/v1", "kind": "TestSuite",
            "metadata": {"name": f"haltlab-{scenario}-escapes",
                         "description": "Queries HaltSQL allowed that the haltlab oracles caught. "
                                        "Move into test/corpus/ after removing `found_by`."},
            "policy": str(policy), "cases": cases}


def write_reports(out_dir: Path, scenario: Any, runs: list[dict[str, Any]], failures: list[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "scenario": scenario.name,
        "file": str(scenario.path),
        "fixture": scenario.fixture,
        "environment": scenario.environment,
        "faults": {f: ("implemented" if f in IMPLEMENTED_FAULTS else "TODO: not yet automated")
                   for f in scenario.faults},
        "runs": runs,
        "passed": not failures,
        "failures": failures,
    }
    (out_dir / "report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    lines = [f"# haltlab report: {scenario.name}", "",
             f"Result: **{'PASS' if not failures else 'FAIL'}**", ""]
    for f in failures:
        lines.append(f"- {f}")
    for run in runs:
        m = run["metrics"]
        lines += ["", f"## Postgres {m['postgres']}", "",
                  "| metric | value |", "|---|---|"]
        for k in ("total", "executed", "escapes", "column_leaks", "side_effects", "timeouts",
                  "execution_errors", "benign_total", "benign_denied", "false_positive_rate",
                  "adversarial_total", "adversarial_allowed"):
            lines.append(f"| {k} | {m[k]} |")
        lat = m["latency_us"]
        lines.append(f"| verify latency p50/p95/p99 (us) | {lat['p50']}/{lat['p95']}/{lat['p99']} |")
        lines += ["", "| transform | total | allowed | escapes |", "|---|---|---|---|"]
        for t, c in sorted(m["by_transform"].items()):
            lines.append(f"| {t} | {c['total']} | {c['allowed']} | {c['escapes']} |")
        if run.get("examples"):
            lines += ["", "### Findings (first 20)", ""]
            for ex in run["examples"][:20]:
                lines.append(f"- `{ex['id']}` ({ex['transform']}): {'; '.join(ex['findings'])}")
    if scenario.faults:
        lines += ["", "## Faults", ""]
        for f in scenario.faults:
            lines.append(f"- {f}: {'implemented' if f in IMPLEMENTED_FAULTS else 'TODO: not yet automated'}")
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_corpus(out_dir: Path, doc: dict[str, Any] | None) -> Path | None:
    if doc is None:
        return None
    p = out_dir / "new_corpus_cases.yaml"
    p.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=1000), encoding="utf-8")
    return p
