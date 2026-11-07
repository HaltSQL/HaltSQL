"""Honeytoken markers: format, extraction and leak classification.

Markers are self-describing, so no per-row registry is needed:

* ``HT-<owner-slug>-<table-slug>-<n>``     tenant marker; the owner slug maps
  to a tenant (``Registry.owners``)
* ``HTCOL-<table-slug>-<column-slug>-<n>`` denied-column marker; seeing one in
  any result is a column leak

Slugs only contain ``[a-z0-9_]``, so ``-`` is an unambiguous separator.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from common.ident import slug

MARKER_RE = re.compile(r"HTCOL-[a-z0-9_]+-[a-z0-9_]+-\d+|HT-[a-z0-9_]+-[a-z0-9_]+-\d+")


def table_slug(schema: str, name: str) -> str:
    return slug(f"{schema}_{name}")


def tenant_marker(owner_slug: str, schema: str, table: str, n: int) -> str:
    return f"HT-{owner_slug}-{table_slug(schema, table)}-{n}"


def column_marker(schema: str, table: str, column: str, n: int) -> str:
    return f"HTCOL-{table_slug(schema, table)}-{slug(column)}-{n}"


@dataclass(frozen=True)
class Leak:
    marker: str
    kind: str  # "tenant" | "column" | "unknown"
    table: str
    column: str | None = None
    owner: dict[str, str | None] | None = None


@dataclass
class Registry:
    """owner slug -> owner (tenancy key -> value); tables known to datagen."""

    owners: dict[str, dict[str, str | None]] = field(default_factory=dict)
    tables: dict[str, str] = field(default_factory=dict)  # table slug -> "schema.table"
    columns: dict[str, list[str]] = field(default_factory=dict)  # table slug -> denied column slugs with markers

    def to_json(self) -> dict[str, Any]:
        return {"owners": self.owners, "tables": self.tables, "columns": self.columns}

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Registry":
        return cls(owners=d.get("owners", {}), tables=d.get("tables", {}), columns=d.get("columns", {}))

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_json(), indent=1, ensure_ascii=False), encoding="utf-8")


def _cell_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, (dict, list, tuple)):
        return json.dumps(v, default=str, ensure_ascii=False)
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).decode("utf-8", "replace")
    return str(v)


def extract_markers(rows: Iterable[Iterable[Any]]) -> list[str]:
    seen: list[str] = []
    s: set[str] = set()
    for row in rows:
        for cell in row:
            text = _cell_text(cell)
            if "HT" not in text:
                continue
            for m in MARKER_RE.findall(text):
                if m not in s:
                    s.add(m)
                    seen.append(m)
    return seen


def classify(
    markers: Iterable[str],
    registry: Registry,
    allowed: dict[str, set[str]],
) -> list[Leak]:
    """Return the markers that the caller (``allowed`` tenancy sets) must not see."""
    from common.tenancy import Universe

    leaks: list[Leak] = []
    for m in markers:
        if m.startswith("HTCOL-"):
            _, tslug, cslug, _n = m.split("-")
            leaks.append(Leak(m, "column", registry.tables.get(tslug, tslug), cslug))
            continue
        _, oslug, tslug, _n = m.split("-")
        owner = registry.owners.get(oslug)
        table = registry.tables.get(tslug, tslug)
        if owner is None:
            leaks.append(Leak(m, "unknown", table))
        elif not Universe.owner_visible(owner, allowed):
            leaks.append(Leak(m, "tenant", table, None, owner))
    return leaks
