"""Runs workloads through ``haltsql verify --batch`` (the only HaltSQL contract)."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

LAB = Path(__file__).resolve().parent.parent
REPO = LAB.parent


def resolve_binary() -> list[str]:
    """``HALTSQL_BIN`` (may include arguments), else the dune build output, else PATH."""
    env = os.environ.get("HALTSQL_BIN")
    if env:
        return shlex.split(env)
    for candidate in (REPO / "_build/default/bin/haltsql/main.exe",
                      REPO / "_build/install/default/bin/haltsql"):
        if candidate.exists():
            return [str(candidate)]
    found = shutil.which("haltsql")
    if found:
        return [found]
    raise FileNotFoundError(
        "haltsql binary not found: build it (`dune build` at the repo root) or set HALTSQL_BIN")


def fake_verifier_command() -> list[str]:
    return [sys.executable, str(Path(__file__).with_name("fake_verifier.py"))]


class VerifierError(RuntimeError):
    pass


def verify_batch(cmd: list[str], policy: Path, items: Iterable[dict[str, Any]],
                 jobs: int | None = None) -> dict[str, dict[str, Any]]:
    """Return ``id -> verdict``. Raises if the verifier exits with a load error."""
    lines = [json.dumps({"id": it["id"], "sql": it["sql"], "context": it["context"]},
                        ensure_ascii=False) for it in items]
    argv = [*cmd, "verify", "--policy", str(policy), "--batch"]
    if jobs and jobs > 1:
        argv += ["--jobs", str(jobs)]
    proc = subprocess.run(argv, input="\n".join(lines) + "\n", capture_output=True,
                          text=True, encoding="utf-8")
    if proc.returncode not in (0, 1):
        raise VerifierError(f"{' '.join(argv)} exited {proc.returncode}: {proc.stderr.strip()[:2000]}")
    out: dict[str, dict[str, Any]] = {}
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        v = json.loads(line)
        out[str(v.get("id"))] = v
    missing = [it["id"] for it in items if str(it["id"]) not in out] if isinstance(items, list) else []
    if missing:
        raise VerifierError(f"verifier returned no verdict for {len(missing)} items, e.g. {missing[:3]}")
    return out
