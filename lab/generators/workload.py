"""Assemble workloads (lists of JSONL items) from benign templates and transforms."""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any, Iterable

from common.tenancy import Universe
from generators.benign import BenignQuery, benign_queries
from generators.evasion import TRANSFORMS, Ctx, raw_wrappers
from generators.sqlspec import SchemaModel, render

Item = dict[str, Any]


def _context(universe: Universe, rng: random.Random) -> tuple[dict[str, Any], list[str]]:
    unit = universe.sample_unit(rng)
    ctx = universe.context_for(unit)
    allowed = universe.allowed(ctx)
    first_key = universe.keys[0][0]
    others = [u.get(first_key) for u in universe.units if u.get(first_key) not in allowed.get(first_key, set())]
    return ctx, [o for o in others if o]


def benign_workload(m: SchemaModel, universe: Universe, n: int, seed: int, fixture: str | None = None) -> list[Item]:
    rng = random.Random(f"benign:{seed}")
    qs = benign_queries(m, fixture)
    if not qs:
        return []
    items: list[Item] = []
    for i in range(n):
        q = qs[i % len(qs)]
        sql = q.sql
        if q.spec is not None and q.spec.limit and i >= len(qs):  # vary LIMIT on repeats
            sql = render(q.spec.copy(limit=rng.choice([10, 25, 50, 100])), m)
        ctx, _ = _context(universe, rng)
        items.append({"id": f"b-{i:06d}", "sql": sql, "context": ctx, "intent": "benign",
                      "transform": "none", "template": q.template, "leak": None})
    return items


def adversarial_workload(
    m: SchemaModel,
    universe: Universe,
    n: int,
    seed: int,
    fixture: str | None = None,
    transforms: Iterable[str] | None = None,
) -> list[Item]:
    """Round-robin over transforms (so small runs still cover all of them)."""
    rng = random.Random(f"evasion:{seed}")
    qs: list[BenignQuery] = benign_queries(m, fixture)
    names = sorted(transforms) if transforms else sorted(TRANSFORMS)
    unknown = [t for t in names if t not in TRANSFORMS]
    if unknown:
        raise ValueError(f"unknown transforms: {unknown}")
    wrappers = raw_wrappers()
    items: list[Item] = []
    dead: set[str] = set()
    i = 0
    attempts = 0
    while len(items) < n and attempts < n * 20 and len(dead) < len(names):
        attempts += 1
        name = names[i % len(names)]
        i += 1
        if name in dead:
            continue
        ctx, others = _context(universe, rng)
        tc = Ctx(m, rng, ctx, others)
        start = rng.randrange(len(qs))
        variants = []
        for k in range(len(qs)):
            q = qs[(start + k) % len(qs)]
            if q.spec is None and name not in wrappers:
                continue
            variants = TRANSFORMS[name](q, tc)
            if variants:
                break
        if not variants:
            dead.add(name)
            continue
        v = rng.choice(variants)
        items.append({"id": f"a-{len(items):06d}", "sql": v.sql, "context": ctx, "intent": v.intent,
                      "transform": name, "template": q.template, "leak": v.leak})
    return items


def write_jsonl(items: Iterable[Item], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")
            n += 1
    return n


def read_jsonl(path: Path) -> list[Item]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
