#!/usr/bin/env python3
"""Mutation testing: do the tests notice when a security rule is broken?

    test/mutation/mutate.py test/mutation/engine.py [--only SUBSTRING] [--out FILE]

A mutant list is a Python module with

    MUTANTS    = [(name, file, snippet, replacement), ...]
    EQUIVALENT = {name: why the mutant changes nothing observable}
    TESTS      = "test/analyzer test/parse ..."      (dune test directories), or
    BUILD/TEST = shell commands, for code that is not built with dune

Each mutant is applied to the working tree, the tests are run, and the file is
restored. The result of a mutant is one of

    KILLED     a test failed (or the tests timed out): the rule is protected
    SURVIVED   every test passed: nothing checks this rule
    INVALID    the mutated source does not build: rewrite the mutant
    STALE      the snippet no longer occurs exactly once: update the mutant

The run fails (exit 1) on a SURVIVED mutant that is not listed in EQUIVALENT, on an
INVALID or STALE mutant, and on an EQUIVALENT mutant that is now KILLED (take it out
of the list). Run it from the repository root, on a clean working tree: the sources
are modified in place while it runs.
"""

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time

DUNE = os.environ.get("DUNE", "opam exec -- dune")


def sh(cmd, timeout):
    try:
        p = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    lines = (p.stdout + p.stderr).splitlines()
    keep = [l for l in lines if any(k in l for k in ("FAIL", "ASSERT", "Error", "failed"))]
    return p.returncode, "\n".join(keep[:6])[:400]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mutants")
    ap.add_argument("--only", help="run only mutants whose name contains this text")
    ap.add_argument("--out", help="write the results as JSON")
    ap.add_argument("--timeout", type=int, default=900, help="seconds per test run")
    args = ap.parse_args()

    spec = importlib.util.spec_from_file_location("mutants", args.mutants)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    equivalent = getattr(m, "EQUIVALENT", {})
    build = getattr(m, "BUILD", f"{DUNE} build")
    test = getattr(m, "TEST", f"{DUNE} test --force " + getattr(m, "TESTS", ""))

    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                           capture_output=True, text=True).stdout.strip()
    if dirty:
        sys.exit("the working tree has uncommitted changes; commit or stash them first")
    rc, out = sh(f"{build} && {test}", args.timeout)
    if rc != 0:
        sys.exit("the tests do not pass before any mutation:\n" + out)

    results, bad = [], 0
    todo = [x for x in m.MUTANTS if not args.only or args.only in x[0]]
    for i, (name, path, old, new) in enumerate(todo, start=1):
        src = open(path).read()
        if src.count(old) != 1:
            status, why = "STALE", f"snippet occurs {src.count(old)} times in {path}"
        else:
            started = time.time()
            open(path, "w").write(src.replace(old, new, 1))
            try:
                rc, why = sh(build, args.timeout)
                if rc != 0:
                    status = "INVALID"
                else:
                    rc, why = sh(test, args.timeout)
                    status = "KILLED" if rc != 0 else "SURVIVED"
            finally:
                open(path, "w").write(src)
            why = f"{round(time.time() - started)} s"
        expected_survivor = name in equivalent
        ok = (status == "KILLED" and not expected_survivor) or (
            status == "SURVIVED" and expected_survivor)
        bad += 0 if ok else 1
        note = " (equivalent: " + equivalent[name] + ")" if expected_survivor else ""
        print(f"[{i}/{len(todo)}] {'ok ' if ok else 'BAD'} {status:8s} {name}{note} [{why}]",
              flush=True)
        results.append({"name": name, "file": path, "status": status, "ok": ok})
        if args.out:
            json.dump(results, open(args.out, "w"), indent=1)

    killed = sum(r["status"] == "KILLED" for r in results)
    print(f"{killed} of {len(results)} mutants killed; "
          f"{sum(r['status'] == 'SURVIVED' for r in results)} survived "
          f"({len([r for r in results if r['status'] == 'SURVIVED' and r['ok']])} equivalent); "
          f"{bad} need attention")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
