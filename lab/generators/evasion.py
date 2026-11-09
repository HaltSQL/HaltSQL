"""Evasion transforms (PLAN.md §8.3) applied to benign queries.

Each transform returns zero or more :class:`Variant` values. ``intent`` is
``benign`` for semantics- and policy-preserving rewrites (they measure false
positives) and ``adversarial`` for everything HaltSQL should deny. ``leak``
names what the lab oracles should observe if HaltSQL wrongly allows it
(``tenant`` | ``column`` | ``side_effect`` | ``resource`` | None); it lets the
self-test (allow-everything verifier) measure oracle recall. ``None`` means
the rewrite is policy-violating but not observably harmful (e.g. the tenant
filter moved to an outer query).
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from common.ident import qi
from generators.benign import BenignQuery
from generators.sqlspec import Join, QuerySpec, Rel, SchemaModel, TModel, render


@dataclass(frozen=True)
class Variant:
    sql: str
    intent: str  # benign | adversarial
    leak: str | None = None


@dataclass
class Ctx:
    """What a transform may know about the request."""

    model: SchemaModel
    rng: random.Random
    context: dict[str, Any]
    other_values: list[str] = field(default_factory=list)  # tenant ids the caller must NOT see


Transform = Callable[[BenignQuery, Ctx], list[Variant]]
TRANSFORMS: dict[str, Transform] = {}


def transform(name: str) -> Callable[[Transform], Transform]:
    def deco(fn: Transform) -> Transform:
        TRANSFORMS[name] = fn
        return fn

    return deco


# ------------------------------------------------------------------ helpers --
def _tenant_base(q: BenignQuery) -> QuerySpec | None:
    s = q.spec
    if s is None or not s.base.table.tenant_scoped or s.ctes:
        return None
    return s


def _bare_pred(c: Ctx, t: TModel) -> str:
    """Tenant predicate without an alias (for DELETE/UPDATE targets)."""
    return " AND ".join(x.replace("x.", "", 1) for x in c.model.tenant_conjuncts("x", t))


def _pidx(c: Ctx, t: TModel, i: int = 0) -> int:
    return c.model.policy.param_index(t.tenant_columns[i][1])


def _eq(c: Ctx, alias: str, t: TModel, i: int = 0) -> str:
    col = t.tenant_columns[i][0]
    n = _pidx(c, t, i)
    if c.model.model == "hierarchical":
        return f"{alias}.{qi(col)} = ANY(${n})"
    return f"{alias}.{qi(col)} = ${n}"


def _other_tenant_table(c: Ctx, t: TModel) -> TModel | None:
    cands = [x for x in c.model.tenant_tables() if x.dotted != t.dotted and x.text_col() and x.pk]
    return c.rng.choice(cands) if cands else None


def _lim(c: Ctx) -> int:
    return c.rng.choice([10, 20, 50])


def _quote_rels(sql: str, q: BenignQuery, style: str) -> str:
    rels: list[TModel] = []
    if q.spec:
        rels = [r.table for r in q.spec.rels()] + list(q.spec.subrels.values())
        for _n, cte in q.spec.ctes:
            rels += [r.table for r in cte.rels()]
    elif q.raw:
        rels = []  # raw templates: only touch the schema prefix
    out = sql
    for t in {x.dotted: x for x in rels if x.schema != "__cte__"}.values():
        plain = t.rel
        if style == "quoted":
            new = f'"{t.schema}"."{t.name}"'
        elif style == "upper":
            if t.schema != t.schema.lower() or t.name != t.name.lower() or '"' in plain:
                continue
            new = f"{t.schema.upper()}.{t.name.upper()}"
        else:  # unicode escape of the first letter of the schema
            s0 = t.schema[0]
            new = f'U&"\\{ord(s0):04x}{t.schema[1:]}".{qi(t.name)}'
        out = re.sub(rf"(?<![\w.\"]){re.escape(plain)}(?![\w\"])", lambda _m, n=new: n, out)
    return out


# ============================================================ benign rewrites
@transform("wrap_cte")
def _wrap_cte(q: BenignQuery, c: Ctx) -> list[Variant]:
    return [Variant(f"WITH q AS ({q.sql}) SELECT * FROM q LIMIT {_lim(c)}", "benign")]


@transform("wrap_subquery")
def _wrap_subquery(q: BenignQuery, c: Ctx) -> list[Variant]:
    return [Variant(f"SELECT * FROM ({q.sql}) AS sq LIMIT {_lim(c)}", "benign")]


@transform("quoted_identifiers")
def _quoted(q: BenignQuery, c: Ctx) -> list[Variant]:
    if q.spec is None:
        return []
    return [Variant(_quote_rels(q.sql, q, "quoted"), "benign")]


@transform("upper_case_identifiers")
def _upper(q: BenignQuery, c: Ctx) -> list[Variant]:
    if q.spec is None:
        return []
    out = _quote_rels(q.sql, q, "upper")
    return [Variant(out, "benign")] if out != q.sql else []


@transform("unicode_escape_identifier")
def _uescape(q: BenignQuery, c: Ctx) -> list[Variant]:
    if q.spec is None:
        return []
    return [Variant(_quote_rels(q.sql, q, "unicode"), "benign")]


@transform("comment_noise")
def _comments(q: BenignQuery, c: Ctx) -> list[Variant]:
    sql = q.sql.replace(" FROM ", "\n/* analytics: monthly report */ FROM ", 1)
    sql = sql.replace(" WHERE ", " -- filtered per tenant\nWHERE ", 1)
    return [Variant(sql, "benign")]


@transform("lateral_filtered")
def _lateral_filtered(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or s.group_by or not s.base.table.pk:
        return []
    o = _other_tenant_table(c, s.base.table)
    if o is None:
        return []
    a = s.base.alias
    t = s.base.table
    lat = (f"SELECT l.{qi(o.text_col() or o.pk or 'id')} AS peek FROM {o.rel} l WHERE "
           f"{c.model.tenant_pred('l', o)} ORDER BY l.{qi(o.pk or 'id')} LIMIT 1")
    sql = (f"SELECT {a}.{qi(t.pk or 'id')}, x.peek FROM {t.rel} {a} JOIN LATERAL ({lat}) x ON true "
           f"WHERE {c.model.tenant_pred(a, t)} ORDER BY {a}.{qi(t.pk or 'id')} LIMIT {_lim(c)}")
    return [Variant(sql, "benign")]


@transform("star_allowed")
def _star_allowed(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or s.base.table.denied or not s.single_table:
        return []
    a, t = s.base.alias, s.base.table
    return [Variant(f"SELECT * FROM {t.rel} {a} WHERE {c.model.tenant_pred(a, t)} "
                    f"ORDER BY {a}.{qi(t.pk or 'id')} LIMIT {_lim(c)}", "benign")]


# ======================================================= tenant-proof attacks
@transform("drop_tenant_filter")
def _drop(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None:
        return []
    return [Variant(render(s, c.model, drop=frozenset({s.base.alias})), "adversarial", "tenant")]


@transform("drop_join_tenant_filter")
def _drop_join(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = q.spec
    if s is None:
        return []
    out = []
    for j in s.joins:
        if j.rel.table.tenant_scoped:
            # semantically safe only if FKs never cross tenants; the data has some that do
            out.append(Variant(render(s, c.model, drop=frozenset({j.rel.alias})), "adversarial", "tenant"))
    for a in s.subrels:
        out.append(Variant(render(s, c.model, drop=frozenset({a})), "adversarial", None))
    return out[:1] if out else []


@transform("union_unfiltered_branch")
def _union(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or not s.single_table:
        return []
    a = render(s, c.model)
    b = render(s, c.model, drop=frozenset({s.base.alias}))
    return [Variant(f"({a}) UNION ALL ({b}) LIMIT {_lim(c) * 2}", "adversarial", "tenant")]


@transform("except_unfiltered")
def _except(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or not s.single_table:
        return []
    a = render(s, c.model, limit=False, order=False)
    b = render(s, c.model, drop=frozenset({s.base.alias}), limit=False, order=False)
    return [Variant(f"({b}) EXCEPT ({a}) LIMIT {_lim(c)}", "adversarial", "tenant")]


@transform("filter_moved_outward")
def _outward(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or not s.single_table or s.group_by:
        return []
    t = s.base.table
    extra = [f"{s.base.alias}.{qi(col)} AS __t{i}" for i, (col, _k) in enumerate(t.tenant_columns)]
    inner = render(s.copy(select=s.select + extra), c.model, drop=frozenset({s.base.alias}), limit=False,
                   order=False)
    conds = []
    for i, (_col, key) in enumerate(t.tenant_columns):
        n = c.model.policy.param_index(key)
        conds.append(f"sq.__t{i} = ANY(${n})" if c.model.model == "hierarchical" else f"sq.__t{i} = ${n}")
    sql = f"SELECT * FROM ({inner}) AS sq WHERE {' AND '.join(conds)} LIMIT {_lim(c)}"
    return [Variant(sql, "adversarial", None)]  # policy-violating, not a leak


@transform("or_true")
def _or_true(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None:
        return []
    tp = c.model.tenant_pred(s.base.alias, s.base.table)
    v1 = render(s.copy(where=[f"({tp} OR 1 = 1)"] + s.where), c.model, drop=frozenset({s.base.alias}))
    return [Variant(v1, "adversarial", "tenant")]


@transform("or_tenant")
def _or_tenant(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or not s.base.table.pk:
        return []
    a, t = s.base.alias, s.base.table
    tp = c.model.tenant_pred(a, t)
    cond = f"({a}.{qi(t.pk or 'id')} > 0 OR {tp})"
    return [Variant(render(s.copy(where=[cond] + s.where), c.model, drop=frozenset({a})), "adversarial", "tenant")]


@transform("or_tenant_is_null")
def _or_null(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None:
        return []
    a, t = s.base.alias, s.base.table
    col = t.tenant_columns[0][0]
    cond = f"({_eq(c, a, t)} OR {a}.{qi(col)} IS NULL OR {a}.{qi(col)} = '')"
    rest = [_eq(c, a, t, i) for i in range(1, len(t.tenant_columns))]
    return [Variant(render(s.copy(where=[cond] + rest + s.where), c.model, drop=frozenset({a})),
                    "adversarial", "tenant")]


@transform("not_equivalent")
def _not_eq(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None:
        return []
    a, t = s.base.alias, s.base.table
    conds = []
    for i, (col, key) in enumerate(t.tenant_columns):
        n = c.model.policy.param_index(key)
        if c.model.model == "hierarchical":
            conds.append(f"NOT ({a}.{qi(col)} <> ALL(${n}))")
        else:
            conds.append(f"NOT ({a}.{qi(col)} <> ${n})")
    return [Variant(render(s.copy(where=conds + s.where), c.model, drop=frozenset({a})), "adversarial", None)]


@transform("not_inverted")
def _not_inv(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None:
        return []
    a, t = s.base.alias, s.base.table
    tp = c.model.tenant_pred(a, t)
    return [Variant(render(s.copy(where=[f"NOT ({tp})"] + s.where), c.model, drop=frozenset({a})),
                    "adversarial", "tenant")]


@transform("left_join_preserved_side")
def _left_join(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None:
        return []
    a, t = s.base.alias, s.base.table
    o = None
    joins = list(s.joins)
    if not joins:
        o = _other_tenant_table(c, t)
        if o is None or not o.pk:
            return []
        joins = [Join(Rel("lj", o), [f"lj.{qi(o.pk or 'id')} = {a}.{qi(t.pk or 'id')}"])]
    # base predicate moves into the ON clause of a LEFT JOIN: it no longer filters the base rows
    new_joins = [Join(j.rel, j.on + c.model.tenant_conjuncts(a, t), "LEFT JOIN") for j in joins]
    return [Variant(render(s.copy(joins=new_joins), c.model, drop=frozenset({a})), "adversarial", "tenant")]


@transform("cte_name_shadowing")
def _cte_shadow(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or not s.base.table.pk:
        return []
    t = s.base.table
    name = qi(t.name)
    pk = qi(t.pk or "id")
    cols = ", ".join(f"y.{qi(x)}" for x in [t.pk or "id"] + t.payload_columns()[:2])
    # CTE named like the table filters; the outer query reads the schema-qualified table unfiltered
    v1 = (f"WITH {name} AS (SELECT * FROM {t.rel} x WHERE {c.model.tenant_pred('x', t)}) "
          f"SELECT {cols} FROM {t.rel} y ORDER BY y.{pk} LIMIT {_lim(c)}")
    # CTE unfiltered, outer filters on the CTE: safe result, but the inner occurrence is unproven
    inner_cols = ", ".join(dict.fromkeys([t.pk or "id"] + [col for col, _ in t.tenant_columns]))
    v2 = (f"WITH {name} AS (SELECT {', '.join(qi(x) for x in inner_cols.split(', '))} FROM {t.rel}) "
          f"SELECT z.{pk} FROM {name} z WHERE {c.model.tenant_pred('z', t)} ORDER BY z.{pk} LIMIT {_lim(c)}")
    return [Variant(v1, "adversarial", "tenant"), Variant(v2, "adversarial", None)]


@transform("alias_shadowing")
def _alias_shadow(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or not s.base.table.pk:
        return []
    t = s.base.table
    o = _other_tenant_table(c, t)
    if o is None:
        return []
    alias = qi(t.name)
    pk = qi(t.pk or "id")
    sql = (f"SELECT x.{pk} FROM {t.rel} x JOIN {o.rel} {alias} ON true "
           f"WHERE {c.model.tenant_pred(alias, o)} ORDER BY x.{pk} LIMIT {_lim(c)}")
    return [Variant(sql, "adversarial", "tenant")]


@transform("unicode_identifier_unfiltered")
def _u_unfiltered(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None:
        return []
    sql = render(s, c.model, drop=frozenset({s.base.alias}))
    return [Variant(_quote_rels(sql, q, "unicode"), "adversarial", "tenant")]


@transform("quoted_case_unfiltered")
def _q_unfiltered(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None:
        return []
    sql = render(s, c.model, drop=frozenset({s.base.alias}))
    up = _quote_rels(sql, q, "upper")
    return [Variant(up if up != sql else _quote_rels(sql, q, "quoted"), "adversarial", "tenant")]


@transform("tenant_literal_other")
def _literal_other(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or not c.other_values or c.model.model == "composite":
        return []
    a, t = s.base.alias, s.base.table
    lit = c.rng.choice(c.other_values).replace("'", "''")
    col = qi(t.tenant_columns[0][0])
    return [Variant(render(s.copy(where=[f"{a}.{col} = '{lit}'"] + s.where), c.model, drop=frozenset({a})),
                    "adversarial", "tenant")]


@transform("tenant_literal_own")
def _literal_own(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or c.model.model != "single":
        return []
    a, t = s.base.alias, s.base.table
    fieldname = c.model.policy.context_field(t.tenant_columns[0][1])
    own = str(c.context.get(fieldname, "")).replace("'", "''")
    col = qi(t.tenant_columns[0][0])
    # bound mode requires $n: a literal (even the right one) must be denied; not a leak
    return [Variant(render(s.copy(where=[f"{a}.{col} = '{own}'"] + s.where), c.model, drop=frozenset({a})),
                    "adversarial", None)]


@transform("lookalike_case_fold")
def _lookalike(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None:
        return []
    a, t = s.base.alias, s.base.table
    col = qi(t.tenant_columns[0][0])
    n = _pidx(c, t)
    rest = [_eq(c, a, t, i) for i in range(1, len(t.tenant_columns))]
    if c.model.model == "hierarchical":
        variants = [f"lower({a}.{col}) = ANY(${n})", f"upper({a}.{col}) = ANY(${n})"]
    else:
        variants = [f"lower({a}.{col}) = lower(${n})", f"trim({a}.{col}) = ${n}",
                    f"{a}.{col} LIKE ${n} || '%'", f"{a}.{col} ILIKE ${n}"]
    w = c.rng.choice(variants)
    return [Variant(render(s.copy(where=[w] + rest + s.where), c.model, drop=frozenset({a})), "adversarial", "tenant")]


@transform("composite_partial_key")
def _partial(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or len(s.base.table.tenant_columns) < 2:
        return []
    a, t = s.base.alias, s.base.table
    i = c.rng.randrange(len(t.tenant_columns))
    return [Variant(render(s.copy(where=[_eq(c, a, t, i)] + s.where), c.model, drop=frozenset({a})),
                    "adversarial", "tenant")]


@transform("param_out_of_range")
def _param_oob(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None:
        return []
    a, t = s.base.alias, s.base.table
    col = qi(t.tenant_columns[0][0])
    bad = len(c.model.policy.keys) + 1
    return [Variant(render(s.copy(where=[f"{a}.{col} = ${bad}"] + s.where), c.model, drop=frozenset({a})),
                    "adversarial", None)]


@transform("scalar_subquery_unfiltered")
def _scalar(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or s.group_by or not s.single_table:
        return []
    o = _other_tenant_table(c, s.base.table)
    if o is None:
        return []
    peek = f"(SELECT max(z.{qi(o.text_col() or 'id')}) FROM {o.rel} z) AS peek"
    return [Variant(render(s.copy(select=s.select + [peek]), c.model), "adversarial", "tenant")]


@transform("exists_unfiltered")
def _exists_unf(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or not s.base.table.pk:
        return []
    o = _other_tenant_table(c, s.base.table)
    if o is None or not o.pk:
        return []
    cond = f"EXISTS (SELECT 1 FROM {o.rel} z WHERE z.{qi(o.pk)} = {s.base.alias}.{qi(s.base.table.pk or 'id')})"
    return [Variant(render(s.copy(where=s.where + [cond]), c.model), "adversarial", None)]


@transform("lateral_unfiltered")
def _lateral_unf(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or s.group_by or not s.base.table.pk:
        return []
    o = _other_tenant_table(c, s.base.table)
    if o is None:
        return []
    a, t = s.base.alias, s.base.table
    lat = f"SELECT l.{qi(o.text_col() or 'id')} AS peek FROM {o.rel} l ORDER BY l.{qi(o.pk or 'id')} DESC LIMIT 1"
    sql = (f"SELECT {a}.{qi(t.pk or 'id')}, x.peek FROM {t.rel} {a} CROSS JOIN LATERAL ({lat}) x "
           f"WHERE {c.model.tenant_pred(a, t)} ORDER BY {a}.{qi(t.pk or 'id')} LIMIT {_lim(c)}")
    return [Variant(sql, "adversarial", "tenant")]


# ============================================================= column attacks
def _denied_table(q: BenignQuery) -> tuple[str, TModel] | None:
    s = _tenant_base(q)
    if s is None:
        return None
    return s.base.alias, s.base.table


@transform("star_over_pii")
def _star_pii(q: BenignQuery, c: Ctx) -> list[Variant]:
    d = _denied_table(q)
    if d is None or not d[1].denied:
        return []
    a, t = d
    tp = c.model.tenant_pred(a, t)
    pk = qi(t.pk or "id")
    return [Variant(f"SELECT * FROM {t.rel} {a} WHERE {tp} ORDER BY {a}.{pk} LIMIT {_lim(c)}", "adversarial", "column"),
            Variant(f"SELECT {a}.* FROM {t.rel} {a} WHERE {tp} ORDER BY {a}.{pk} LIMIT {_lim(c)}", "adversarial", "column")]


@transform("whole_row_reference")
def _whole_row(q: BenignQuery, c: Ctx) -> list[Variant]:
    d = _denied_table(q)
    if d is None or not d[1].denied:
        return []
    a, t = d
    tp = c.model.tenant_pred(a, t)
    pk = qi(t.pk or "id")
    exprs = [f"row_to_json({a}) AS r", f"{a}::text AS r", f"{a} AS r", f"to_jsonb({a}) AS r"]
    e = c.rng.choice(exprs)
    return [Variant(f"SELECT {e} FROM {t.rel} {a} WHERE {tp} ORDER BY {a}.{pk} LIMIT {_lim(c)}", "adversarial", "column")]


@transform("star_over_pii_wrapped")
def _star_pii_wrapped(q: BenignQuery, c: Ctx) -> list[Variant]:
    """``*`` over a table with denied columns, hidden inside a CTE or derived table."""
    d = _denied_table(q)
    if d is None or not d[1].denied:
        return []
    a, t = d
    tp = c.model.tenant_pred(a, t)
    pk = qi(t.pk or "id")
    inner = f"SELECT * FROM {t.rel} {a} WHERE {tp}"
    lim = _lim(c)
    return [Variant(f"WITH q AS ({inner}) SELECT * FROM q ORDER BY q.{pk} LIMIT {lim}", "adversarial", "column"),
            Variant(f"SELECT sq.* FROM ({inner}) AS sq ORDER BY sq.{pk} LIMIT {lim}", "adversarial", "column"),
            Variant(f"SELECT * FROM (SELECT {a}.* FROM {t.rel} {a} WHERE {tp}) AS sq LIMIT {lim}",
                    "adversarial", "column")]


@transform("whole_row_wrapped")
def _whole_row_wrapped(q: BenignQuery, c: Ctx) -> list[Variant]:
    """Whole-row values through JSON/aggregate functions and CTEs."""
    d = _denied_table(q)
    if d is None or not d[1].denied:
        return []
    a, t = d
    tp = c.model.tenant_pred(a, t)
    pk = qi(t.pk or "id")
    lim = _lim(c)
    return [Variant(f"SELECT to_json({a}) AS r FROM {t.rel} {a} WHERE {tp} ORDER BY {a}.{pk} LIMIT {lim}",
                    "adversarial", "column"),
            Variant(f"SELECT json_agg({a}) AS r FROM {t.rel} {a} WHERE {tp} LIMIT 1", "adversarial", "column"),
            Variant(f"SELECT jsonb_agg({a}) AS r FROM {t.rel} {a} WHERE {tp} LIMIT 1", "adversarial", "column"),
            Variant(f"SELECT row({a}.*)::text AS r FROM {t.rel} {a} WHERE {tp} ORDER BY {a}.{pk} LIMIT {lim}",
                    "adversarial", "column"),
            Variant(f"WITH q AS (SELECT * FROM {t.rel} {a} WHERE {tp}) SELECT row_to_json(q) AS r FROM q "
                    f"LIMIT {lim}", "adversarial", "column")]


@transform("denied_column_wrapped")
def _denied_wrapped(q: BenignQuery, c: Ctx) -> list[Variant]:
    """One denied column read through a CTE, a derived table, a scalar subquery or a cast."""
    d = _denied_table(q)
    if d is None or not d[1].denied:
        return []
    a, t = d
    col = qi(c.rng.choice(t.denied))
    tp = c.model.tenant_pred(a, t)
    tpb = c.model.tenant_pred("b", t)
    pk = qi(t.pk or "id")
    lim = _lim(c)
    return [Variant(f"WITH q AS (SELECT {a}.{col} AS v FROM {t.rel} {a} WHERE {tp}) SELECT v FROM q LIMIT {lim}",
                    "adversarial", "column"),
            Variant(f"SELECT sq.v FROM (SELECT {a}.{col} AS v FROM {t.rel} {a} WHERE {tp}) AS sq LIMIT {lim}",
                    "adversarial", "column"),
            Variant(f"SELECT {a}.{pk}, (SELECT b.{col} FROM {t.rel} b WHERE b.{pk} = {a}.{pk} AND {tpb}) AS v "
                    f"FROM {t.rel} {a} WHERE {tp} ORDER BY {a}.{pk} LIMIT {lim}", "adversarial", "column"),
            Variant(f"SELECT {a}.{col}::text AS v FROM {t.rel} {a} WHERE {tp} ORDER BY {a}.{pk} LIMIT {lim}",
                    "adversarial", "column")]


@transform("denied_column_direct")
def _denied_direct(q: BenignQuery, c: Ctx) -> list[Variant]:
    d = _denied_table(q)
    if d is None or not d[1].denied:
        return []
    a, t = d
    col = c.rng.choice(t.denied)
    tp = c.model.tenant_pred(a, t)
    return [Variant(f"SELECT {a}.{qi(t.pk or 'id')}, {a}.{qi(col)} FROM {t.rel} {a} WHERE {tp} "
                    f"ORDER BY {a}.{qi(t.pk or 'id')} LIMIT {_lim(c)}", "adversarial", "column")]


@transform("denied_column_in_predicate")
def _denied_pred(q: BenignQuery, c: Ctx) -> list[Variant]:
    d = _denied_table(q)
    if d is None or not d[1].denied:
        return []
    a, t = d
    col = c.rng.choice(t.denied)
    tp = c.model.tenant_pred(a, t)
    # oracle: column privilege (reading a denied column in WHERE is still reading it)
    return [Variant(f"SELECT count(*) AS n FROM {t.rel} {a} WHERE {tp} AND {a}.{qi(col)} IS NOT NULL LIMIT 1",
                    "adversarial", "column")]


@transform("system_catalog")
def _syscat(q: BenignQuery, c: Ctx) -> list[Variant]:
    return [Variant("SELECT relname, relkind FROM pg_catalog.pg_class ORDER BY relname LIMIT 20", "adversarial"),
            Variant("SELECT table_name, column_name FROM information_schema.columns ORDER BY 1, 2 LIMIT 50",
                    "adversarial")]


@transform("regclass_cast")
def _regclass(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None:
        return []
    t = s.base.table
    lit = t.rel.replace("'", "''")
    return [Variant(f"SELECT '{lit}'::regclass AS r LIMIT 1", "adversarial"),
            Variant(f"SELECT 'pg_sleep'::regproc AS p LIMIT 1", "adversarial")]


# =============================================================== side effects
@transform("data_modifying_cte")
def _dml_cte(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or not s.base.table.pk:
        return []
    t = s.base.table
    tp = _bare_pred(c, t)
    pk = qi(t.pk or "id")
    txt = t.text_col()
    out = [Variant(f"WITH d AS (DELETE FROM {t.rel} WHERE {tp} RETURNING {pk}) SELECT count(*) AS n FROM d LIMIT 1",
                   "adversarial", "side_effect")]
    if txt:
        out.append(Variant(f"WITH u AS (UPDATE {t.rel} SET {qi(txt)} = 'pwned' WHERE {tp} RETURNING {pk}) "
                           f"SELECT {pk} FROM u LIMIT 10", "adversarial", "side_effect"))
    return [c.rng.choice(out)]


@transform("explain_analyze")
def _explain_analyze(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    out = [Variant(f"EXPLAIN ANALYZE {q.sql}", "adversarial")]
    if s is not None and s.base.table.pk:
        t = s.base.table
        tp = _bare_pred(c, t)
        out.append(Variant(f"EXPLAIN ANALYZE DELETE FROM {t.rel} WHERE {tp}", "adversarial", "side_effect"))
    return [c.rng.choice(out)]


@transform("explain_plain")
def _explain(q: BenignQuery, c: Ctx) -> list[Variant]:
    return [Variant(f"EXPLAIN {q.sql}", "adversarial")]


@transform("side_effect_functions")
def _side_fns(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    victim = c.rng.choice(c.other_values) if c.other_values else "globex"
    victim = victim.replace("'", "''")
    out = [
        Variant(f"SELECT set_config('app.tenant_id', '{victim}', false) AS v LIMIT 1", "adversarial", "side_effect"),
        Variant("SELECT pg_advisory_lock(424242) AS l LIMIT 1", "adversarial", "side_effect"),
        Variant("SELECT pg_sleep(30) AS z LIMIT 1", "adversarial", "resource"),
        Variant("SELECT x FROM dblink('dbname=postgres', 'SELECT 1') AS t(x int) LIMIT 1", "adversarial"),
        Variant("SELECT pg_read_file('/etc/passwd') AS f LIMIT 1", "adversarial"),
    ]
    if s is not None:
        t = s.base.table
        out.append(Variant(f"SELECT nextval(pg_get_serial_sequence('{t.rel}', 'id')) AS n LIMIT 1",
                           "adversarial", "side_effect"))
        # changes the RLS context mid-query: the side-effect oracle must catch it even if RLS is fooled
        out.append(Variant(render(s.copy(where=s.where + [f"set_config('app.tenant_id', '{victim}', true) IS NOT NULL"]),
                                  c.model), "adversarial", "side_effect"))
    return [c.rng.choice(out)]


@transform("srf_in_from")
def _srf(q: BenignQuery, c: Ctx) -> list[Variant]:
    return [Variant("SELECT g FROM generate_series(1, 2000000000) AS g ORDER BY g DESC LIMIT 5", "adversarial", "resource")]


@transform("select_into")
def _select_into(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or s.group_by or s.joins:
        return []
    sql = render(s, c.model)
    sql = sql.replace(" FROM ", " INTO TEMP TABLE haltlab_leak FROM ", 1)
    return [Variant(sql, "adversarial", "side_effect")]


@transform("locking_clause")
def _locking(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None or s.group_by or s.ctes or s.subrels or s.joins:
        return []
    if any("(" in x for x in s.select):
        return []
    mode = c.rng.choice(["FOR UPDATE", "FOR SHARE", "FOR NO KEY UPDATE"])
    return [Variant(f"{q.sql} {mode}", "adversarial", "side_effect")]


@transform("multi_statement")
def _multi(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    out = [Variant(f"{q.sql}; SELECT 1", "adversarial")]
    if s is not None:
        t = s.base.table
        txt = t.text_col()
        if txt:
            out.append(Variant(f"SELECT 1 AS one LIMIT 1; UPDATE {t.rel} SET {qi(txt)} = 'pwned'",
                               "adversarial", "side_effect"))
    return [c.rng.choice(out)]


@transform("comment_hidden_filter")
def _comment_hidden(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None:
        return []
    a, t = s.base.alias, s.base.table
    tp = c.model.tenant_pred(a, t)
    unf = render(s, c.model, drop=frozenset({a}))
    if " WHERE " in unf:
        v1 = unf.replace(" WHERE ", f" WHERE /* {tp} AND */ ", 1)
    else:
        v1 = unf.replace(" FROM ", " /* WHERE-less on purpose */ FROM ", 1)
        v1 = re.sub(r"( GROUP BY | ORDER BY | LIMIT )", f" /* WHERE {tp} */\\1", v1, count=1)
    v2 = re.sub(r"( GROUP BY | ORDER BY | LIMIT )", f" -- AND {tp}\n\\1", unf, count=1)
    return [Variant(c.rng.choice([v1, v2]), "adversarial", "tenant")]


@transform("dollar_quoted_filter")
def _dollar(q: BenignQuery, c: Ctx) -> list[Variant]:
    s = _tenant_base(q)
    if s is None:
        return []
    a, t = s.base.alias, s.base.table
    tp = c.model.tenant_pred(a, t)
    unf = render(s.copy(select=[f"$q$ WHERE {tp} $q$ AS note"] + s.select), c.model, drop=frozenset({a}))
    return [Variant(unf, "adversarial", "tenant")]


# ------------------------------------------------------------- applying ----
def apply(name: str, q: BenignQuery, c: Ctx) -> list[Variant]:
    return TRANSFORMS[name](q, c)


def raw_wrappers() -> set[str]:
    """Transforms that also work on raw (hand-written) templates."""
    return {"wrap_cte", "wrap_subquery", "comment_noise", "explain_analyze", "explain_plain", "multi_statement",
            "system_catalog", "srf_in_from", "side_effect_functions"}

