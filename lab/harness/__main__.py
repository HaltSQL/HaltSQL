"""haltlab command line.

    python -m harness run scenarios/pr-smoke.yaml
    python -m harness run scenarios/pr-smoke.yaml --fake-verifier allow   # oracle self-test
    python -m harness run scenarios/pr-smoke.yaml --policy drafted.yaml   # judge another policy
    python -m harness validate scenarios/*.yaml

Environment: HALTSQL_BIN (verifier command), HALTLAB_DSN (admin DSN; may
contain {port} or {version}).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from harness.runner import default_out_dir, log, run_scenario
from harness.scenario import ScenarioError, load_scenario
from harness.verifier import fake_verifier_command, resolve_binary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m harness", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run a scenario")
    r.add_argument("scenario", type=Path)
    r.add_argument("--out", type=Path, help="output directory (default lab/out/<scenario>)")
    r.add_argument("--keep-db", action="store_true", help="keep the lab database for inspection")
    r.add_argument("--jobs", type=int, help="parallel verification (haltsql --jobs)")
    r.add_argument("--fake-verifier", choices=["allow", "deny"],
                   help="use the stand-in verifier instead of haltsql (oracle self-test)")
    r.add_argument("--policy", type=Path,
                   help="policy for the verifier (and, unless --oracle-policy, the oracles); "
                        "overrides the scenario's and the fixture's policy")
    r.add_argument("--oracle-policy", type=Path,
                   help="ground truth for the oracles: honeytokens go in every column it denies and "
                        "haltlab_cols is granted exactly its allowed columns (default: the verifier policy)")
    r.add_argument("--run-id", help="suffix for database names, so concurrent runs on one server do not collide")
    v = sub.add_parser("validate", help="check scenario files")
    v.add_argument("scenarios", type=Path, nargs="+")
    a = ap.parse_args(argv)

    if a.cmd == "validate":
        bad = 0
        for p in a.scenarios:
            try:
                load_scenario(p)
                print(f"ok      {p}")
            except (ScenarioError, OSError, ValueError) as e:
                bad += 1
                print(f"error   {p}: {e}")
        return 1 if bad else 0

    try:
        scn = load_scenario(a.scenario)
    except (ScenarioError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.fake_verifier:
        cmd = fake_verifier_command() + ["--mode", a.fake_verifier]
    else:
        try:
            cmd = resolve_binary()
        except FileNotFoundError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    out = a.out or default_out_dir(scn)
    ok = run_scenario(scn, out, cmd, keep_db=a.keep_db, jobs=a.jobs,
                      policy_path=a.policy.resolve() if a.policy else None,
                      oracle_policy_path=a.oracle_policy.resolve() if a.oracle_policy else None,
                      run_id=a.run_id)
    log("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
