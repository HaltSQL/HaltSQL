"""CLI: generate workloads without a database (types guessed from column names).

    python -m generators benign  --fixture saas_shared --n 50  --out /tmp/b.jsonl
    python -m generators evasion --fixture saas_shared --n 200 --out /tmp/a.jsonl
    python -m generators transforms        # list transform names
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from common.fixtures import get_fixture
from common.policy import load_policy
from common.tenancy import build_universe
from generators.evasion import TRANSFORMS
from generators.sqlspec import SchemaModel
from generators.workload import adversarial_workload, benign_workload, write_jsonl


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m generators", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kind", choices=["benign", "evasion", "transforms"])
    ap.add_argument("--fixture", default="saas_shared")
    ap.add_argument("--policy", type=Path, help="override the fixture policy")
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--tenants", type=int, default=10)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    if a.kind == "transforms":
        print("\n".join(sorted(TRANSFORMS)))
        return 0
    fx = get_fixture(a.fixture)
    policy = load_policy(a.policy or fx.policy)
    m = SchemaModel.build(policy, fx.model)
    u = build_universe(fx.model, policy.keys, a.tenants)
    items = (benign_workload(m, u, a.n, a.seed, fx.name) if a.kind == "benign"
             else adversarial_workload(m, u, a.n, a.seed, fx.name))
    if a.out:
        write_jsonl(items, a.out)
        print(f"wrote {len(items)} items to {a.out}", file=sys.stderr)
    else:
        import json

        for it in items:
            print(json.dumps(it, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
