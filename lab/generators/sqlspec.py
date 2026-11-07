"""Schema model for templating and a small structured query spec.

Benign queries are built as :class:`QuerySpec` values so evasion transforms
can manipulate structure (drop a tenant predicate, move it, OR it, ...)
instead of regex-editing SQL text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from common.ident import qi, qname
from common.policy import LabPolicy

if TYPE_CHECKING:
    from datagen.catalog import TableInfo

CATEGORY_COLS = ("status", "kind", "role", "plan", "method", "stage", "tier", "priority",
                 "classification", "action", "country", "region", "currency")
_NUMERIC = {"int2", "int4", "int8", "numeric", "float4", "float8"}
_TS = {"timestamptz", "timestamp", "date"}


@dataclass
class TModel:
    schema: str
    name: str
    columns: list[str]  # allowed (readable) columns, catalog order when known
    types: dict[str, str]
    tenant_columns: list[tuple[str, str]]  # (column, tenancy key)
    all_columns: list[str] = field(default_factory=list)
    fks: list[tuple[str, tuple[str, str], str]] = field(default_factory=list)  # (col, (schema, table), ref col)
    kind: str = "r"

    @property
    def rel(self) -> str:
        return qname(self.schema, self.name)

    @property
    def dotted(self) -> str:
        return f"{self.schema}.{self.name}"

    @property
    def tenant_scoped(self) -> bool:
        return bool(self.tenant_columns)

    @property
    def pk(self) -> str | None:
        if "id" in self.columns:
            return "id"
        return self.columns[0] if self.columns else None

    @property
    def denied(self) -> list[str]:
        return [c for c in self.all_columns if c not in self.columns]

    def payload_columns(self) -> list[str]:
        tc = {c for c, _ in self.tenant_columns}
        return [c for c in self.columns if c not in tc]

    def first(self, pred: "callable[[str, str], bool]") -> str | None:  # type: ignore[valid-type]
        for c in self.columns:
            if pred(c, self.types.get(c, "text")):
                return c
        return None

    def category_col(self) -> str | None:
        for name in CATEGORY_COLS:
            if name in self.columns:
                return name
        return None

    def numeric_col(self) -> str | None:
        tc = {c for c, _ in self.tenant_columns}
        return self.first(lambda c, t: t in _NUMERIC and c != "id" and not c.endswith("_id") and c not in tc)

    def ts_col(self) -> str | None:
        return self.first(lambda c, t: t in _TS)

    def text_col(self) -> str | None:
        tc = {c for c, _ in self.tenant_columns}
        return self.first(lambda c, t: t in ("text", "varchar") and c not in tc and c not in CATEGORY_COLS)


def _guess_type(col: str) -> str:
    if col == "id" or col.endswith("_id") and col not in ("tenant_id", "org_id", "workspace_id"):
        return "int8"
    if col.endswith("_cents") or col in ("quantity", "seats", "decimals"):
        return "int8"
    if col.endswith("_at"):
        return "timestamptz"
    if col.endswith("_date"):
        return "date"
    if col in ("estimate_hours",):
        return "numeric"
    return "text"


@dataclass
class SchemaModel:
    policy: LabPolicy
    model: str  # single | composite | hierarchical
    tables: dict[tuple[str, str], TModel]

    @classmethod
    def build(cls, policy: LabPolicy, model: str, catalog: "list[TableInfo] | None" = None) -> "SchemaModel":
        cat = {t.key: t for t in (catalog or [])}
        out: dict[tuple[str, str], TModel] = {}
        for key, pt in policy.tables.items():
            ti = cat.get(key)
            all_cols = [c.name for c in ti.columns] if ti else []
            types = {c.name: c.type for c in ti.columns} if ti else {}
            if pt.columns is None:
                cols = list(all_cols)
            else:
                cols = [c for c in all_cols if c in pt.columns] if ti else list(pt.columns)
                cols += [c for c in pt.columns if c not in cols]
            for c in cols:
                types.setdefault(c, _guess_type(c))
            fks: list[tuple[str, tuple[str, str], str]] = []
            if ti:
                for fk in ti.fks:
                    if len(fk.columns) == 1:
                        fks.append((fk.columns[0], (fk.ref_schema, fk.ref_table), fk.ref_columns[0]))
            else:  # heuristic: customer_id -> customers.id in the same schema
                for c in cols:
                    if c.endswith("_id"):
                        base = c[:-3]
                        for cand in (base + "s", base, base + "es"):
                            if (key[0], cand) in policy.tables:
                                fks.append((c, (key[0], cand), "id"))
                                break
            out[key] = TModel(key[0], key[1], cols, types, list(pt.tenant_columns), all_cols or list(cols),
                              fks, ti.kind if ti else "r")
        return cls(policy, model, out)

    def get(self, dotted: str) -> TModel:
        s, n = dotted.split(".", 1)
        return self.tables[(s, n)]

    def tenant_tables(self) -> list[TModel]:
        return [t for t in self.tables.values() if t.tenant_scoped and t.columns]

    def global_tables(self) -> list[TModel]:
        return [t for t in self.tables.values() if not t.tenant_scoped and t.columns]

    # --------------------------------------------------------- predicates --
    def tenant_conjuncts(self, alias: str, t: TModel) -> list[str]:
        out = []
        for col, key in t.tenant_columns:
            n = self.policy.param_index(key)
            if self.model == "hierarchical":
                out.append(f"{alias}.{qi(col)} = ANY(${n})")
            else:
                out.append(f"{alias}.{qi(col)} = ${n}")
        return out

    def tenant_pred(self, alias: str, t: TModel) -> str:
        return " AND ".join(self.tenant_conjuncts(alias, t)) or "true"


@dataclass
class Rel:
    alias: str
    table: TModel


@dataclass
class Join:
    rel: Rel
    on: list[str]
    kind: str = "JOIN"


@dataclass
class QuerySpec:
    """SELECT <select> FROM base [joins] WHERE <tenant preds> AND <where> ..."""

    template: str
    select: list[str]
    base: Rel
    joins: list[Join] = field(default_factory=list)
    where: list[str] = field(default_factory=list)  # may contain {TP:alias} placeholders
    subrels: dict[str, TModel] = field(default_factory=dict)  # aliases used inside subqueries
    group_by: list[str] = field(default_factory=list)
    order_by: list[str] = field(default_factory=list)
    limit: int = 50
    ctes: list[tuple[str, "QuerySpec"]] = field(default_factory=list)

    def rels(self) -> list[Rel]:
        return [self.base] + [j.rel for j in self.joins]

    def copy(self, **kw: object) -> "QuerySpec":
        return replace(self, **kw)  # type: ignore[arg-type]

    @property
    def single_table(self) -> bool:
        return not self.joins and not self.subrels and not self.ctes


_TP = re.compile(r"\{TP:([a-z_][a-z0-9_]*)\}")


def render(
    spec: QuerySpec,
    m: SchemaModel,
    drop: frozenset[str] = frozenset(),
    limit: bool = True,
    order: bool = True,
) -> str:
    """Render ``spec``; aliases in ``drop`` lose their tenant predicates."""

    def tp(alias: str, t: TModel) -> list[str]:
        return [] if alias in drop else m.tenant_conjuncts(alias, t)

    def sub(text: str) -> str:
        def repl(mt: re.Match[str]) -> str:
            a = mt.group(1)
            t = spec.subrels.get(a) or next((r.table for r in spec.rels() if r.alias == a), None)
            if t is None:
                raise KeyError(f"unknown alias {a} in template {spec.template}")
            parts = tp(a, t)
            return " AND ".join(parts) if parts else "true"

        return _TP.sub(repl, text)

    parts: list[str] = []
    if spec.ctes:
        parts.append("WITH " + ", ".join(f"{name} AS ({render(c, m, drop)})" for name, c in spec.ctes))
    parts.append("SELECT " + ", ".join(spec.select))
    from_ = f"FROM {_rel_sql(spec.base)}"
    for j in spec.joins:
        conds = list(j.on) + tp(j.rel.alias, j.rel.table)
        from_ += f" {j.kind} {_rel_sql(j.rel)} ON " + (" AND ".join(sub(c) for c in conds) or "true")
    parts.append(from_)
    where = tp(spec.base.alias, spec.base.table) + [sub(w) for w in spec.where]
    if where:
        parts.append("WHERE " + " AND ".join(where))
    if spec.group_by:
        parts.append("GROUP BY " + ", ".join(spec.group_by))
    if order and spec.order_by:
        parts.append("ORDER BY " + ", ".join(spec.order_by))
    if limit and spec.limit:
        parts.append(f"LIMIT {spec.limit}")
    return " ".join(parts)


def _rel_sql(r: Rel) -> str:
    if r.table.schema == "__cte__":
        return r.table.name if r.alias == r.table.name else f"{r.table.name} {r.alias}"
    return f"{r.table.rel} {r.alias}"
