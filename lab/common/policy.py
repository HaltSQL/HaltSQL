"""Minimal, read-only view of a HaltSQL policy document for the lab.

The lab never decides verdicts (that is HaltSQL's job); it only needs the
policy to: grant haltlab_cols the allowed columns, know tenant columns and
tenancy keys for data generation and query templates, and know which columns
are sensitive (= present in the database but not allowed).

Accepted table forms (PLAN.md §6.5 and lib/core/policy.ml):
  tenant_column: tenant_id                     # single key
  tenant_columns: { org_id: org, workspace_id: workspace }
and tenancy as either ``keys: {tenant: ${ctx.tenant_id}}`` or the short form
``value: ${ctx.tenant_id}`` (key name "tenant").
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from common.ident import normalize_column, split_qualified

_CTX = re.compile(r"^\$\{ctx\.([A-Za-z_][A-Za-z0-9_]*)\}$")


@dataclass(frozen=True)
class PolicyTable:
    schema: str
    name: str
    columns: tuple[str, ...] | None  # None = "*" (all columns)
    tenant_columns: tuple[tuple[str, str], ...]  # (column, tenancy key)

    @property
    def qualified(self) -> tuple[str, str]:
        return (self.schema, self.name)

    @property
    def is_tenant_scoped(self) -> bool:
        return bool(self.tenant_columns)

    def allows_column(self, column: str) -> bool:
        return self.columns is None or column in self.columns


@dataclass
class LabPolicy:
    path: Path
    name: str
    search_path: list[str]
    tenancy_mode: str
    keys: list[tuple[str, str]]  # (tenancy key, context field), document order
    tables: dict[tuple[str, str], PolicyTable]
    functions: list[str]
    require_limit: int | None
    raw: dict[str, Any] = field(repr=False, default_factory=dict)

    def table(self, schema: str, name: str) -> PolicyTable | None:
        return self.tables.get((schema, name))

    def context_field(self, key: str) -> str:
        for k, f in self.keys:
            if k == key:
                return f
        raise KeyError(f"unknown tenancy key {key!r}")

    def param_index(self, key: str) -> int:
        """Bound-mode convention used by the lab: $n is the n-th tenancy key."""
        for i, (k, _f) in enumerate(self.keys, start=1):
            if k == key:
                return i
        raise KeyError(f"unknown tenancy key {key!r}")

    @property
    def schemas(self) -> list[str]:
        seen: list[str] = []
        for s, _ in self.tables:
            if s not in seen:
                seen.append(s)
        return seen


def read_document(path: str | Path) -> dict[str, Any]:
    """Read a YAML or JSON document (by extension)."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        doc = json.loads(text)
    else:
        doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise ValueError(f"{p}: top level must be a mapping")
    return doc


def _ctx_field(value: Any, where: str) -> str:
    if not isinstance(value, str) or not (m := _CTX.match(value.strip())):
        raise ValueError(f"{where}: expected ${{ctx.<field>}}, got {value!r}")
    return m.group(1)


def parse_policy(doc: dict[str, Any], path: Path | None = None) -> LabPolicy:
    if doc.get("kind") != "Policy":
        raise ValueError("not a Policy document (kind != Policy)")
    search_path = [s.lower() for s in doc.get("search_path", ["public"])]
    tenancy = doc.get("tenancy") or {}
    keys: list[tuple[str, str]] = []
    if "keys" in tenancy:
        for k, v in (tenancy["keys"] or {}).items():
            keys.append((str(k), _ctx_field(v, f"tenancy.keys.{k}")))
    elif "value" in tenancy:
        keys.append(("tenant", _ctx_field(tenancy["value"], "tenancy.value")))
    tables: dict[tuple[str, str], PolicyTable] = {}
    for qname, spec in (doc.get("tables") or {}).items():
        parts = split_qualified(str(qname))
        if len(parts) == 1:
            parts = [search_path[0], parts[0]]
        if len(parts) != 2:
            raise ValueError(f"tables.{qname}: expected schema.table")
        spec = spec or {}
        cols_raw = spec.get("columns", "*")
        columns = None if cols_raw == "*" else tuple(normalize_column(c) for c in cols_raw)
        tcols: list[tuple[str, str]] = []
        if "tenant_column" in spec:
            if len(keys) != 1:
                raise ValueError(f"tables.{qname}: tenant_column needs exactly one tenancy key")
            tcols.append((normalize_column(spec["tenant_column"]), keys[0][0]))
        for col, key in (spec.get("tenant_columns") or {}).items():
            if key not in {k for k, _ in keys}:
                raise ValueError(f"tables.{qname}: unknown tenancy key {key!r}")
            tcols.append((normalize_column(col), str(key)))
        tables[(parts[0], parts[1])] = PolicyTable(parts[0], parts[1], columns, tuple(tcols))
    funcs = (doc.get("functions") or {}).get("allow", [])
    rl = doc.get("require_limit")
    return LabPolicy(
        path=path or Path("<memory>"),
        name=str((doc.get("metadata") or {}).get("name", "unnamed")),
        search_path=search_path,
        tenancy_mode=str(tenancy.get("mode", "bound")),
        keys=keys,
        tables=tables,
        functions=[str(f).lower() for f in funcs],
        require_limit=int(rl["max"]) if isinstance(rl, dict) and "max" in rl else None,
        raw=doc,
    )


def load_policy(path: str | Path) -> LabPolicy:
    p = Path(path)
    return parse_policy(read_document(p), p.resolve())
