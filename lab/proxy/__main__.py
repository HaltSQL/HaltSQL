"""haltlab, proxy mode: run a Scenario's workloads through haltsql-proxy.

    cd lab && .venv/bin/python -m proxy run proxy/scenarios/proxy-smoke.yaml

Environment: HALTSQL_BIN (reference verifier), HALTSQL_PROXY_BIN (proxy binary),
HALTLAB_DSN (admin DSN). Exit 0 pass, 1 fail, 2 usage/setup error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from common.fixtures import LAB
from harness.runner import log
from harness.scenario import ScenarioError, load_scenario
from proxy.runner import run


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m proxy", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run a scenario through haltsql-proxy")
    r.add_argument("scenario", type=Path)
    r.add_argument("--out", type=Path, help="output directory (default lab/out/<scenario>-proxy)")
    r.add_argument("--keep-db", action="store_true")
    a = ap.parse_args(argv)
    try:
        scn = load_scenario(a.scenario)
    except (ScenarioError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    out = a.out or (LAB / "out" / f"{scn.name}-proxy")
    try:
        ok, m = run(scn, out, keep_db=a.keep_db)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    log(f"items={m.items} cli_allowed={m.cli_allowed} proxy_allowed={m.proxy_allowed} "
        f"executed={m.executed} parity_mismatches={m.parity_mismatches} escapes={m.escapes} "
        f"execution_errors={m.execution_errors}")
    log(f"report: {out / 'report.md'}")
    log("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
