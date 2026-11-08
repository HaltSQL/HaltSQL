"""haltlab compatibility runs: one scenario against one Postgres flavour.

    python -m compat run scenarios/compat-pg18.yaml     # oracle self-test + HaltSQL + proxy parity
    python -m compat table                              # Markdown results table from out/compat/*.json

A run has three parts, all against the same engine:

1. Oracle self-test: the scenario's workload with the allow-everything stand-in
   verifier. The oracles MUST report tenant escapes, column leaks and side
   effects; otherwise a clean HaltSQL result on that engine would mean nothing.
2. HaltSQL: the scenario with the real ``haltsql`` binary; its ``expect`` block
   decides pass/fail (zero escapes, side effects and column leaks).
3. Proxy parity: the same scenario through a live ``haltsql-proxy``
   (lab/proxy): same decisions as the CLI, same rows as direct execution, no
   foreign honeytokens.

The summary goes to ``out/compat/<scenario>.json``. Exit 0 only if all three
pass. Environment: HALTSQL_BIN, HALTSQL_PROXY_BIN, HALTLAB_DSN (cloud engines).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from common.fixtures import LAB
from compat.engines import get_engine
from harness.runner import log, run_scenario
from harness.scenario import Scenario, ScenarioError, load_scenario
from harness.verifier import fake_verifier_command, resolve_binary

OUT = LAB / "out" / "compat"
# Transforms that read other tenants' rows or denied columns when allowed, and
# meaning-preserving rewrites that must stay clean (tests/test_integration.py).
LEAKY = ("union_unfiltered_branch", "or_true", "left_join_preserved_side", "star_over_pii")
SAFE = ("wrap_cte", "wrap_subquery", "quoted_identifiers", "explain_plain")


def selftest_problems(run: dict[str, Any]) -> list[str]:
    """Why an allow-everything run does NOT prove the oracles work on this engine."""
    m = run["metrics"]
    out = []
    if m["escapes"] < 50:
        out.append(f"only {m['escapes']} escapes detected (expected >= 50)")
    if m["column_leaks"] == 0:
        out.append("no column leak detected")
    if m["side_effects"] == 0:
        out.append("no side effect detected")
    t = m["by_transform"]
    for name in LEAKY:
        if name in t and t[name]["allowed"] and t[name]["escapes"] == 0:
            out.append(f"transform {name} leaked nothing")
    if not any(name in t for name in LEAKY):
        out.append("workload has none of the leaky transforms")
    for name in SAFE:
        if name in t and t[name]["escapes"]:
            out.append(f"meaning-preserving transform {name} reported {t[name]['escapes']} escapes")
    return out


def _report(out_dir: Path) -> dict[str, Any]:
    return json.loads((out_dir / "report.json").read_text(encoding="utf-8"))


def run_all(scn: Scenario, skip_proxy: bool, skip_selftest: bool) -> dict[str, Any]:
    eng = get_engine(scn.engine)
    eng.check_dsn(scn.dsn)
    base = OUT / scn.name
    summary: dict[str, Any] = {"scenario": scn.name, "file": str(scn.path.relative_to(LAB)),
                               "engine": eng.name, "description": eng.description,
                               "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    if not skip_selftest:
        log(f"[{scn.name}] 1/3 oracle self-test (allow-everything verifier; its FAIL lines are expected)")
        run_scenario(scn, base / "selftest", fake_verifier_command() + ["--mode", "allow"])
        st = _report(base / "selftest")["runs"][0]
        problems = selftest_problems(st)
        summary["selftest"] = {"passed": not problems, "problems": problems,
                               **{k: st["metrics"][k] for k in ("executed", "escapes", "column_leaks",
                                                                 "side_effects")}}

    log(f"[{scn.name}] 2/3 HaltSQL")
    ok = run_scenario(scn, base / "haltsql", resolve_binary())
    rep = _report(base / "haltsql")
    run = rep["runs"][0]
    m = run["metrics"]
    summary["server_version"] = m["postgres"]
    summary["engine_notes"] = run.get("engine_notes", [])
    summary["haltsql"] = {"passed": ok, "failures": rep["failures"],
                          **{k: m[k] for k in ("total", "executed", "escapes", "column_leaks", "side_effects",
                                               "timeouts", "execution_errors", "false_positive_rate")},
                          "execution_errors_by_sqlstate": run.get("execution_errors_by_sqlstate", {})}

    if not skip_proxy:
        from proxy.runner import run as proxy_run  # needs haltsql-proxy only when used
        log(f"[{scn.name}] 3/3 haltsql-proxy parity")
        pok, pm = proxy_run(scn, base / "proxy")
        prep = _report(base / "proxy")
        summary["proxy"] = {"passed": pok, "failures": prep["failures"], **pm.to_json()}

    parts = [summary.get(k, {"passed": True}) for k in ("selftest", "haltsql", "proxy")]
    summary["passed"] = all(p["passed"] for p in parts)
    summary["skipped"] = [k for k, flag in (("selftest", skip_selftest), ("proxy", skip_proxy)) if flag]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{scn.name}.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")
    return summary


def table(paths: list[Path]) -> str:
    """The results table of docs/compatibility.md, from summaries written by `run`."""
    rows = ["| Engine | Version | Scenario | Executed | Escapes | Side effects | Proxy parity | Notes |",
            "|---|---|---|---|---|---|---|---|"]
    for p in sorted(paths):
        s = json.loads(p.read_text(encoding="utf-8"))
        h = s["haltsql"]
        px = s.get("proxy")
        parity = ("not run" if px is None else
                  f"{px['proxy_allowed']}/{px['cli_allowed']} same decisions of {px['items']}, "
                  f"{px['parity_mismatches']} mismatches, {px['escapes']} escapes")
        st = s.get("selftest")
        notes = [f"{h['execution_errors']} execution errors "
                 f"({', '.join(f'{k}: {v}' for k, v in sorted(h['execution_errors_by_sqlstate'].items())) or '-'})"]
        if st:
            notes.append(f"oracle self-test {'caught' if st['passed'] else 'FAILED'}: "
                         f"{st['escapes']} escapes, {st['column_leaks']} column leaks, "
                         f"{st['side_effects']} side effects")
        notes.append("PASS" if s["passed"] else "FAIL")
        rows.append(f"| {s['description']} | {s['server_version']} | `{s['file']}` | {h['executed']} | "
                    f"{h['escapes']} | {h['side_effects']} | {parity} | {'; '.join(notes)} |")
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m compat", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="self-test + HaltSQL + proxy parity for one scenario")
    r.add_argument("scenario", type=Path)
    r.add_argument("--no-proxy", action="store_true", help="skip the haltsql-proxy parity run")
    r.add_argument("--no-selftest", action="store_true", help="skip the oracle self-test")
    t = sub.add_parser("table", help="print the Markdown results table")
    t.add_argument("summaries", type=Path, nargs="*", help="default: out/compat/*.json")
    a = ap.parse_args(argv)

    if a.cmd == "table":
        print(table(a.summaries or list(OUT.glob("*.json"))))
        return 0
    try:
        scn = load_scenario(a.scenario)
        s = run_all(scn, a.no_proxy, a.no_selftest)
    except (ScenarioError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    for part in ("selftest", "haltsql", "proxy"):
        if part in s:
            log(f"[{scn.name}] {part}: {'PASS' if s[part]['passed'] else 'FAIL'} "
                f"{s[part].get('problems') or s[part].get('failures') or ''}")
    log(f"[{scn.name}] {'PASS' if s['passed'] else 'FAIL'}; summary: {OUT / (scn.name + '.json')}")
    return 0 if s["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
