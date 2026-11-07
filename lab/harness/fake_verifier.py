"""Stand-in for ``haltsql verify --batch`` used to self-test the oracles.

``--mode allow`` (default) allows every query and binds ``$n`` to the n-th
tenancy key's context value (the lab's bound-mode convention), so the
evasion workload WILL leak and the oracles MUST report escapes.
``--mode deny`` denies everything (nothing is executed).

Usage mirrors the real CLI: ``fake_verifier.py verify --policy P --batch``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.policy import load_policy  # noqa: E402

_PARAM = re.compile(r"\$(\d+)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["verify"])
    ap.add_argument("--policy", required=True)
    ap.add_argument("--batch", action="store_true", required=True)
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--mode", choices=["allow", "deny"], default="allow")
    a = ap.parse_args(argv)
    policy = load_policy(a.policy)
    for line in sys.stdin:
        if not line.strip():
            continue
        req = json.loads(line)
        sql, ctx = req["sql"], req.get("context") or {}
        used = {int(n) for n in _PARAM.findall(sql)}
        binds = []
        for i, (_key, fieldname) in enumerate(policy.keys, start=1):
            if i in used and fieldname in ctx:
                binds.append({"param": i, "value": ctx[fieldname]})
        allowed = a.mode == "allow"
        print(json.dumps({
            "id": req.get("id"),
            "allowed": allowed,
            "reasons": [] if allowed else [{"code": "E_INTERNAL", "message": "fake deny", "rule": "fake"}],
            "shadow_reasons": [],
            "policy": {"name": policy.name, "version": "fake"},
            "statement_kind": "select",
            "tables": [], "columns": [],
            "bind_params": binds if allowed else [],
            "fingerprint": None,
            "sql_sha256": hashlib.sha256(sql.encode()).hexdigest(),
            "elapsed_us": 1,
        }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
