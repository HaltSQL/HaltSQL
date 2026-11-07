"""Tenant universe: who the tenants are, how they map to context, who may see what.

Three models (one per hand-written fixture; erp_large uses ``single``):

* ``single``       one key (``tenant``), context ``{tenant_id: "acme"}``
* ``composite``    two keys (``org``, ``workspace``); workspace names repeat
                   across orgs, context ``{org_id: "acme", workspace_id: "eng"}``
* ``hierarchical`` one key whose context value is a list: the tenant plus all
                   of its descendants, ``{tenant_ids: ["acme", "acme-eu"]}``

Every universe contains edge-case tenants that look like a regular one
(``ACME``, ``acme ``, ``acme<ZWSP>``, Cyrillic ``аcme``, ``acme%``,
``acmecorp``, ``o'brien``) and orphan owners (NULL and empty-string tenant ids)
that no context may ever see.
"""

from __future__ import annotations

import bisect
import random
from dataclasses import dataclass, field
from typing import Any

BASE_NAMES: tuple[str, ...] = (
    "acme", "globex", "initech", "umbrella", "hooli", "stark", "wayne", "wonka",
    "tyrell", "cyberdyne", "soylent", "massive", "vandelay", "oscorp", "aperture",
    "duff", "gringotts", "monarch", "pied", "dunder",
)
# Look-alikes of "acme" (which is always tenant #0).
EDGE_NAMES: tuple[str, ...] = (
    "ACME", "acme ", "acme​", "аcme", "acme%", "acmecorp", "o'brien",
)
WORKSPACES: tuple[str, ...] = ("eng", "ops", "sales", "finance")
CHILD_SUFFIXES: tuple[str, ...] = ("eu", "us", "apac")

MODELS = ("single", "composite", "hierarchical")


@dataclass(frozen=True)
class Unit:
    """One tenant (for composite: one (org, workspace) pair)."""

    values: tuple[tuple[str, str | None], ...]  # (tenancy key, value)
    slug: str  # marker-safe id used in honeytokens, e.g. "t003"
    edge: bool = False
    orphan: bool = False
    parent: str | None = None  # hierarchical only

    def get(self, key: str) -> str | None:
        return dict(self.values)[key]

    def project(self, keys: tuple[str, ...]) -> tuple[tuple[str, str | None], ...]:
        d = dict(self.values)
        return tuple((k, d[k]) for k in keys)

    def owner(self) -> dict[str, str | None]:
        return dict(self.values)


@dataclass
class Universe:
    model: str
    keys: list[tuple[str, str]]  # (tenancy key, context field)
    units: list[Unit]  # real tenants (regular + edge), no orphans
    orphans: list[Unit]
    weights: list[float]  # zipf weights aligned with units
    children: dict[str, list[str]] = field(default_factory=dict)  # hierarchical

    # ------------------------------------------------------------- contexts --
    def descendants(self, tenant: str) -> list[str]:
        out = [tenant]
        stack = list(self.children.get(tenant, []))
        while stack:
            t = stack.pop(0)
            out.append(t)
            stack.extend(self.children.get(t, []))
        return out

    def context_for(self, unit: Unit) -> dict[str, Any]:
        ctx: dict[str, Any] = {}
        for key, fieldname in self.keys:
            v = unit.get(key)
            if self.model == "hierarchical":
                assert v is not None
                ctx[fieldname] = self.descendants(v)
            else:
                ctx[fieldname] = v
        return ctx

    def allowed(self, context: dict[str, Any]) -> dict[str, set[str]]:
        """Tenancy key -> set of values this context may see."""
        out: dict[str, set[str]] = {}
        for key, fieldname in self.keys:
            v = context.get(fieldname)
            if isinstance(v, list):
                out[key] = {str(x) for x in v}
            elif v is None:
                out[key] = set()
            else:
                out[key] = {str(v)}
        return out

    @staticmethod
    def owner_visible(owner: dict[str, str | None], allowed: dict[str, set[str]]) -> bool:
        """True iff a row owned by ``owner`` may be seen with ``allowed``."""
        for k, v in owner.items():
            if v is None or v not in allowed.get(k, set()):
                return False
        return True

    def sample_unit(self, rng: random.Random) -> Unit:
        return self.units[_weighted_index(rng, self.cum_weights)]

    @property
    def cum_weights(self) -> list[float]:
        acc, out = 0.0, []
        for w in self.weights:
            acc += w
            out.append(acc)
        return out

    def projected_units(self, keys: tuple[str, ...]) -> list[tuple[tuple[tuple[str, str | None], ...], str, float]]:
        """Distinct projections of the units onto ``keys`` with merged weights.

        Used for tables scoped by a subset of the keys (composite: org-only).
        Returns (values, slug, weight) triples in a deterministic order.
        """
        seen: dict[tuple[tuple[str, str | None], ...], tuple[str, float]] = {}
        all_keys = tuple(k for k, _ in self.keys)
        for u, w in zip(self.units, self.weights):
            proj = u.project(keys)
            if keys == all_keys:
                s = u.slug
            else:
                s = u.slug.split("w")[0] if self.model == "composite" else u.slug
            prev = seen.get(proj)
            seen[proj] = (s, w + (prev[1] if prev else 0.0))
        return [(vals, s, w) for vals, (s, w) in seen.items()]


def _weighted_index(rng: random.Random, cum: list[float]) -> int:
    x = rng.random() * cum[-1]
    return min(bisect.bisect_right(cum, x), len(cum) - 1)


def zipf_weights(n: int, s: float) -> list[float]:
    return [1.0 / ((i + 1) ** s) for i in range(n)]


def parse_skew(skew: str | float | None) -> float:
    """``zipf(1.2)`` or ``1.2`` -> 1.2; ``uniform``/None -> 0."""
    if skew is None or skew == "uniform":
        return 0.0
    if isinstance(skew, (int, float)):
        return float(skew)
    s = str(skew).strip()
    if s.startswith("zipf(") and s.endswith(")"):
        return float(s[5:-1])
    return float(s)


def _names(n: int) -> list[str]:
    return [BASE_NAMES[i] if i < len(BASE_NAMES) else f"t{i:04d}" for i in range(n)]


def build_universe(
    model: str,
    keys: list[tuple[str, str]],
    tenants: int,
    skew: float = 0.0,
    edge_cases: bool = True,
) -> Universe:
    """Deterministic universe (no randomness needed: order defines weights)."""
    if model not in MODELS:
        raise ValueError(f"unknown tenancy model {model!r}")
    tenants = max(tenants, 2)
    units: list[Unit] = []
    children: dict[str, list[str]] = {}
    key_names = [k for k, _ in keys]

    if model == "single":
        if len(key_names) != 1:
            raise ValueError("single tenancy needs exactly one key")
        k = key_names[0]
        for i, name in enumerate(_names(tenants)):
            units.append(Unit(((k, name),), f"t{i:03d}"))
        if edge_cases:
            for j, name in enumerate(EDGE_NAMES):
                units.append(Unit(((k, name),), f"e{j:02d}", edge=True))
        orphans = [Unit(((k, None),), "tnull", orphan=True), Unit(((k, ""),), "tempty", orphan=True)]

    elif model == "composite":
        if len(key_names) != 2:
            raise ValueError("composite tenancy needs exactly two keys (org, workspace)")
        ko, kw = key_names
        orgs = _names(tenants)
        if edge_cases:
            orgs += ["ACME", "acme ", "acmecorp"]
        for i, org in enumerate(orgs):
            edge = i >= tenants
            for j, wsname in enumerate(WORKSPACES[: 1 + (i % len(WORKSPACES))] if not edge else WORKSPACES[:1]):
                units.append(Unit(((ko, org), (kw, wsname)), f"o{i:03d}w{j}", edge=edge))
        orphans = [Unit(((ko, ""), (kw, "")), "tempty", orphan=True)]

    else:  # hierarchical
        if len(key_names) != 1:
            raise ValueError("hierarchical tenancy needs exactly one (list-valued) key")
        k = key_names[0]
        roots = _names(max(1, (tenants + 3) // 4))
        idx = 0
        for root in roots:
            if len(units) >= tenants:
                break
            units.append(Unit(((k, root),), f"t{idx:03d}"))
            idx += 1
            prev_child: str | None = None
            for n, suf in enumerate(CHILD_SUFFIXES):
                if len(units) >= tenants:
                    break
                # third child hangs below the second: a 3-level tree
                parent = prev_child if n == 2 and prev_child else root
                name = f"{root}-{suf}"
                units.append(Unit(((k, name),), f"t{idx:03d}", parent=parent))
                children.setdefault(parent, []).append(name)
                idx += 1
                prev_child = name
        if edge_cases:
            for j, name in enumerate(n for n in EDGE_NAMES if "," not in n):
                units.append(Unit(((k, name),), f"e{j:02d}", edge=True))
        orphans = [Unit(((k, ""),), "tempty", orphan=True)]

    return Universe(
        model=model,
        keys=list(keys),
        units=units,
        orphans=orphans,
        weights=zipf_weights(len(units), skew) if skew > 0 else [1.0] * len(units),
        children=children,
    )
