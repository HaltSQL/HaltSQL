"""Benign query templates: realistic analytics that the policy SHOULD allow.

Two sources:
* generic templates derived from any SchemaModel (list, group-by, time series,
  FK joins, IN/EXISTS subqueries, CTEs, text search, global lookups), each as
  a structured QuerySpec so evasion transforms can mutate them;
* hand-written, fixture-specific templates (raw SQL with ``{TP:alias}``
  placeholders for the tenant predicate of that alias).

All benign queries: correct tenant predicate on every tenant-scoped relation in
every scope, LIMIT within policy, only allowed columns and functions, and a
total ORDER BY so the owner and RLS oracle runs are comparable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from common.ident import RESERVED, qi
from generators.sqlspec import Join, QuerySpec, Rel, SchemaModel, TModel, render

_TP = re.compile(r"\{TP:([a-z_][a-z0-9_]*)\}")


@dataclass(frozen=True)
class RawTemplate:
    name: str
    sql: str  # with {TP:alias}
    rels: dict[str, str]  # alias -> "schema.table"


@dataclass
class BenignQuery:
    template: str
    sql: str
    spec: QuerySpec | None = None
    raw: RawTemplate | None = None


HAND_TEMPLATES: dict[str, list[RawTemplate]] = {
    "saas_shared": [
        RawTemplate("saas.revenue_by_month",
                    "SELECT date_trunc('month', o.created_at) AS month, o.currency, sum(o.total_cents) AS revenue_cents, "
                    "count(*) AS orders FROM app.orders o WHERE {TP:o} AND o.status <> 'cancelled' "
                    "GROUP BY 1, 2 ORDER BY 1, 2 LIMIT 200", {"o": "app.orders"}),
        RawTemplate("saas.top_customers",
                    "SELECT c.id, c.name, sum(o.total_cents) AS spend FROM app.customers c "
                    "JOIN app.orders o ON o.customer_id = c.id AND {TP:o} WHERE {TP:c} "
                    "GROUP BY c.id, c.name ORDER BY spend DESC, c.id LIMIT 10",
                    {"c": "app.customers", "o": "app.orders"}),
        RawTemplate("saas.invoice_aging",
                    "SELECT i.status, count(*) AS n, sum(i.amount_cents) AS amount FROM app.invoices i "
                    "WHERE {TP:i} AND i.due_date < '2026-06-01' GROUP BY i.status ORDER BY i.status LIMIT 20",
                    {"i": "app.invoices"}),
        RawTemplate("saas.payment_mix",
                    "SELECT p.method, count(*) AS n, round(avg(p.amount_cents)) AS avg_cents FROM app.payments p "
                    "WHERE {TP:p} GROUP BY p.method ORDER BY n DESC, p.method LIMIT 10", {"p": "app.payments"}),
        RawTemplate("saas.sku_sales",
                    "SELECT oi.sku, sum(oi.quantity) AS units, sum(oi.quantity * oi.unit_price_cents) AS gross "
                    "FROM app.order_items oi JOIN app.orders o ON o.id = oi.order_id AND {TP:o} WHERE {TP:oi} "
                    "GROUP BY oi.sku ORDER BY gross DESC, oi.sku LIMIT 25",
                    {"oi": "app.order_items", "o": "app.orders"}),
        RawTemplate("saas.audit_actions",
                    "SELECT e.action, count(*) AS n FROM app.audit_events e WHERE {TP:e} "
                    "AND e.created_at >= now() - interval '365 days' GROUP BY e.action ORDER BY n DESC, e.action LIMIT 10",
                    {"e": "app.audit_events"}),
        RawTemplate("saas.users_by_role",
                    "SELECT u.role, count(*) AS n, max(u.last_login_at) AS last_login FROM app.users u "
                    "WHERE {TP:u} GROUP BY u.role ORDER BY u.role LIMIT 10", {"u": "app.users"}),
        RawTemplate("saas.orders_with_currency",
                    "SELECT o.id, o.total_cents, cur.symbol, cur.decimals FROM app.orders o "
                    "JOIN app.currencies cur ON cur.code = o.currency WHERE {TP:o} ORDER BY o.id LIMIT 50",
                    {"o": "app.orders"}),
        RawTemplate("saas.open_invoices",
                    "SELECT i.number, i.amount_cents, o.status AS order_status FROM app.invoices i "
                    "JOIN app.orders o ON o.id = i.order_id AND {TP:o} WHERE {TP:i} AND i.status = 'open' "
                    "ORDER BY i.id LIMIT 100", {"i": "app.invoices", "o": "app.orders"}),
        RawTemplate("saas.customers_by_country",
                    "SELECT c.country, count(*) AS customers FROM app.customers c WHERE {TP:c} "
                    "GROUP BY c.country ORDER BY c.country LIMIT 50", {"c": "app.customers"}),
        RawTemplate("saas.status_cte",
                    "WITH t AS (SELECT o.status, count(*) AS n FROM app.orders o WHERE {TP:o} GROUP BY o.status) "
                    "SELECT t.status, t.n FROM t ORDER BY t.status LIMIT 20", {"o": "app.orders"}),
        RawTemplate("saas.audit_detail_ref",
                    "SELECT e.id, e.detail ->> 'ref' AS ref FROM app.audit_events e WHERE {TP:e} "
                    "ORDER BY e.id DESC LIMIT 20", {"e": "app.audit_events"}),
    ],
    "composite": [
        RawTemplate("composite.tasks_by_project",
                    "SELECT p.name, t.status, count(*) AS n, sum(t.estimate_hours) AS hours FROM ws.tasks t "
                    "JOIN ws.projects p ON p.id = t.project_id AND {TP:p} WHERE {TP:t} "
                    "GROUP BY p.name, t.status ORDER BY p.name, t.status LIMIT 200",
                    {"t": "ws.tasks", "p": "ws.projects"}),
        RawTemplate("composite.doc_classification",
                    "SELECT d.classification, count(*) AS n FROM ws.documents d WHERE {TP:d} "
                    "GROUP BY d.classification ORDER BY d.classification LIMIT 10", {"d": "ws.documents"}),
        RawTemplate("composite.org_billing",
                    "SELECT b.plan, sum(b.seats) AS seats FROM ws.billing_accounts b WHERE {TP:b} "
                    "GROUP BY b.plan ORDER BY b.plan LIMIT 10", {"b": "ws.billing_accounts"}),
    ],
    "hierarchical": [
        RawTemplate("hier.pipeline_by_stage",
                    "SELECT o.stage, count(*) AS n, sum(o.amount_cents) AS amount FROM crm.opportunities o "
                    "WHERE {TP:o} GROUP BY o.stage ORDER BY o.stage LIMIT 20", {"o": "crm.opportunities"}),
        RawTemplate("hier.accounts_per_tenant",
                    "SELECT a.tenant_id, count(*) AS accounts FROM crm.accounts a WHERE {TP:a} "
                    "GROUP BY a.tenant_id ORDER BY a.tenant_id LIMIT 100", {"a": "crm.accounts"}),
        RawTemplate("hier.activity_feed",
                    "SELECT x.id, x.kind, x.created_at, o.title FROM crm.activities x "
                    "JOIN crm.opportunities o ON o.id = x.opportunity_id AND {TP:o} WHERE {TP:x} "
                    "ORDER BY x.created_at DESC, x.id LIMIT 50",
                    {"x": "crm.activities", "o": "crm.opportunities"}),
    ],
}


def render_raw(t: RawTemplate, m: SchemaModel, drop: frozenset[str] = frozenset()) -> str:
    def repl(mt: re.Match[str]) -> str:
        a = mt.group(1)
        if a in drop:
            return "true"
        return m.tenant_pred(a, m.get(t.rels[a]))

    return _TP.sub(repl, t.sql)


def _alias(t: TModel, taken: set[str]) -> str:
    words = re.split(r"[^a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", t.name).lower())
    base = "".join(w[0] for w in words if w) or "t"
    if not base[0].isalpha():
        base = "t" + base
    a, i = base, 1
    while a in taken or a in RESERVED or a in ("as", "on", "do", "is", "in", "to", "or", "by"):
        a = f"{base}{i}"
        i += 1
    taken.add(a)
    return a


def _col(alias: str, c: str) -> str:
    return f"{alias}.{qi(c)}"


def generic_specs(m: SchemaModel) -> list[QuerySpec]:
    specs: list[QuerySpec] = []
    tables = sorted(m.tenant_tables(), key=lambda t: t.dotted)
    children: dict[tuple[str, str], list[tuple[TModel, str, str]]] = {}
    for t in tables:
        for col, ref, refcol in t.fks:
            if col in t.columns:
                children.setdefault(ref, []).append((t, col, refcol))

    for t in tables:
        pk = t.pk
        if pk is None:
            continue
        taken: set[str] = set()
        a = _alias(t, taken)
        base = Rel(a, t)
        payload = [c for c in t.payload_columns() if c != pk][:4]
        order_pk = [_col(a, pk)]

        specs.append(QuerySpec(f"generic.list:{t.dotted}", [_col(a, pk)] + [_col(a, c) for c in payload],
                               base, order_by=order_pk, limit=50))
        cat = t.category_col()
        if cat:
            specs.append(QuerySpec(f"generic.group:{t.dotted}", [_col(a, cat), "count(*) AS n"], base,
                                   group_by=[_col(a, cat)], order_by=["n DESC", _col(a, cat)], limit=20))
            inner = QuerySpec(f"generic.cte_inner:{t.dotted}", [_col(a, cat) + " AS k", "count(*) AS n"], base,
                              group_by=[_col(a, cat)], limit=0)
            xt = TModel("__cte__", "x", ["k", "n"], {}, [])
            specs.append(QuerySpec(f"generic.cte:{t.dotted}", ["x.k", "x.n"], Rel("x", xt),
                                   order_by=["x.n DESC", "x.k"], limit=10, ctes=[("x", inner)]))
        ts = t.ts_col()
        num = t.numeric_col()
        if ts:
            sel = [f"date_trunc('month', {_col(a, ts)}) AS month", "count(*) AS n"]
            if num:
                sel.append(f"sum({_col(a, num)}) AS total")
            specs.append(QuerySpec(f"generic.monthly:{t.dotted}", sel, base, group_by=["1"],
                                   order_by=["1"], limit=36))
            specs.append(QuerySpec(f"generic.recent:{t.dotted}", [_col(a, pk), _col(a, ts)], base,
                                   where=[f"{_col(a, ts)} >= now() - interval '400 days'"],
                                   order_by=[f"{_col(a, ts)} DESC", _col(a, pk)], limit=25))
            specs.append(QuerySpec(f"generic.agg:{t.dotted}", [f"max({_col(a, ts)}) AS last_seen", "count(*) AS n"],
                                   base, limit=1))
        txt = t.text_col()
        if txt:
            specs.append(QuerySpec(f"generic.search:{t.dotted}", [_col(a, pk), _col(a, txt)], base,
                                   where=[f"lower({_col(a, txt)}) LIKE 'ht-%'"], order_by=order_pk, limit=20))
        for col, ref, refcol in t.fks:
            rt = m.tables.get(ref)
            if rt is None or col not in t.columns or refcol not in rt.columns:
                continue
            b = _alias(rt, set(taken))
            if b == a:
                b = b + "2"
            rpayload = [c for c in rt.payload_columns() if c != refcol][:2]
            sel = [_col(a, pk), _col(a, col)] + [_col(b, c) for c in rpayload]
            specs.append(QuerySpec(f"generic.join:{t.dotted}->{rt.dotted}", sel, base,
                                   joins=[Join(Rel(b, rt), [f"{_col(b, refcol)} = {_col(a, col)}"])],
                                   order_by=order_pk, limit=50))
            if rt.tenant_scoped:
                specs.append(QuerySpec(
                    f"generic.in_subquery:{t.dotted}->{rt.dotted}", [_col(a, pk), _col(a, col)], base,
                    where=[f"{_col(a, col)} IN (SELECT s.{qi(refcol)} FROM {rt.rel} s WHERE {{TP:s}})"],
                    subrels={"s": rt}, order_by=order_pk, limit=50))
        for child, ccol, refcol in children.get((t.schema, t.name), []):
            if refcol != pk or not child.tenant_scoped:
                continue
            specs.append(QuerySpec(
                f"generic.exists:{t.dotted}<-{child.dotted}", [_col(a, pk)] + [_col(a, c) for c in payload[:1]], base,
                where=[f"EXISTS (SELECT 1 FROM {child.rel} s WHERE s.{qi(ccol)} = {_col(a, pk)} AND {{TP:s}})"],
                subrels={"s": child}, order_by=order_pk, limit=50))
            break
    for g in sorted(m.global_tables(), key=lambda t: t.dotted):
        a = _alias(g, set())
        cols = g.columns[:5]
        specs.append(QuerySpec(f"generic.lookup:{g.dotted}", [_col(a, c) for c in cols], Rel(a, g),
                               order_by=[_col(a, cols[0])], limit=100))
    return specs


def benign_queries(m: SchemaModel, fixture: str | None = None) -> list[BenignQuery]:
    out = [BenignQuery(s.template, render(s, m), spec=s) for s in generic_specs(m)]
    for t in HAND_TEMPLATES.get(fixture or "", []):
        if all(dotted.split(".", 1)[0] in m.policy.schemas for dotted in t.rels.values()):
            try:
                out.append(BenignQuery(t.name, render_raw(t, m), raw=t))
            except KeyError:
                continue
    return out
