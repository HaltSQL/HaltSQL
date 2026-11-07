"""Deterministic row generation from (catalog, policy, universe, config)."""

from __future__ import annotations

import bisect
import datetime as dt
import hashlib
import json
import random
import uuid
from dataclasses import dataclass, field
from typing import Any

from common.ident import qi, qname, slug
from common.policy import LabPolicy
from common.tenancy import Universe
from datagen.catalog import ColumnInfo, TableInfo
from datagen.honeytokens import Registry, column_marker, table_slug, tenant_marker

VOCAB: dict[str, tuple[str, ...]] = {
    "status": ("draft", "open", "paid", "void", "shipped", "cancelled"),
    "plan": ("free", "pro", "enterprise"),
    "role": ("admin", "member", "viewer", "billing"),
    "method": ("card", "ach", "wire", "paypal"),
    "kind": ("call", "email", "meeting", "note"),
    "stage": ("prospect", "qualified", "proposal", "won", "lost"),
    "tier": ("gold", "silver", "bronze"),
    "classification": ("public", "internal", "confidential", "restricted"),
    "priority": ("low", "normal", "high", "urgent"),
    "action": ("login", "export", "update", "delete", "invite"),
    "country": ("US", "DE", "FR", "GB", "IN", "BR", "JP", "CA"),
    "region": ("na", "emea", "apac", "latam"),
    "symbol": ("$", "€", "£", "¥"),
    "code": ("USD", "EUR", "GBP", "JPY", "INR", "BRL", "CAD", "AUD", "CHF", "SEK", "NOK", "DKK",
             "PLN", "MXN", "ZAR", "SGD", "HKD", "NZD", "KRW", "CNY", "TRY", "ILS", "AED", "THB"),
}
VOCAB["currency"] = VOCAB["code"]
WORDS: tuple[str, ...] = ("alpha", "bravo", "cobalt", "delta", "ember", "fjord", "garnet", "harbor")
_TEXT_TYPES = {"text", "varchar", "bpchar", "citext", "name"}
_EPOCH = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
_SPAN_DAYS = 1035  # 2024-01-01 .. 2026-10-31


@dataclass
class DataConfig:
    scale: float = 1.0
    tenants: int = 10
    skew: float = 1.2
    seed: int = 42
    rows_per_table: int = 1000  # tenant-scoped table rows at scale 1.0
    global_rows: int = 24
    cross_tenant_fk_rate: float = 0.02  # legacy data: child row points at another tenant's parent
    orphan_rows: bool = True  # NULL / '' tenant rows
    edge_cases: bool = True

    @classmethod
    def from_scenario(cls, d: dict[str, Any]) -> "DataConfig":
        from common.tenancy import parse_skew

        scale = d.get("scale", 1.0)
        named = {"tiny": 0.05, "small": 0.2, "sf1": 1.0, "sf10": 10.0, "sf100": 100.0}
        if isinstance(scale, str):
            scale = named[scale.lower()]
        return cls(
            scale=float(scale),
            tenants=int(d.get("tenants", 10)),
            skew=parse_skew(d.get("skew", "zipf(1.2)")),
            seed=int(d.get("seed", 42)),
            rows_per_table=int(d.get("rows_per_table", 1000)),
            global_rows=int(d.get("global_rows", 24)),
            cross_tenant_fk_rate=float(d.get("cross_tenant_fk_rate", 0.02)),
            orphan_rows=bool(d.get("orphan_rows", True)),
            edge_cases=bool(d.get("edge_cases", True)),
        )


@dataclass
class TableData:
    table: TableInfo
    columns: list[str]
    rows: list[tuple[Any, ...]]


@dataclass
class Dataset:
    tables: list[TableData]
    registry: Registry
    serials: list[tuple[str, str, str, int]] = field(default_factory=list)  # schema, table, column, max

    def row_count(self) -> int:
        return sum(len(t.rows) for t in self.tables)


def _table_rng(seed: int, table: TableInfo) -> random.Random:
    h = hashlib.sha256(f"{seed}:{table.dotted}".encode()).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def tenant_column_keys(policy: LabPolicy) -> dict[str, str]:
    """Column name -> tenancy key, from every policy table (used for denied tables too)."""
    out: dict[str, str] = {}
    for t in policy.tables.values():
        for col, key in t.tenant_columns:
            out.setdefault(col, key)
    return out


def _fit(value: str, col: ColumnInfo) -> str | None:
    if col.char_max is not None and len(value) > col.char_max:
        return None
    return value


def _vocab_for(col: ColumnInfo) -> tuple[str, ...] | None:
    return VOCAB.get(col.name.lower())


class _Gen:
    def __init__(self, policy: LabPolicy, universe: Universe, cfg: DataConfig,
                 unit_tables: tuple[str, ...], column_roles: dict[tuple[str, str], str]) -> None:
        self.policy = policy
        self.universe = universe
        self.cfg = cfg
        self.unit_tables = set(unit_tables)
        self.column_roles = column_roles
        self.tcol_keys = tenant_column_keys(policy)
        self.key_order = [k for k, _ in universe.keys]
        self.registry = Registry()
        # generated rows per table, as dicts, for FK resolution
        self.rows: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self.owner_of: dict[tuple[str, str], list[tuple[tuple[str, str | None], ...]]] = {}
        self.index: dict[tuple[tuple[str, str], tuple[tuple[str, str | None], ...]], list[int]] = {}
        self.unit_by_values = {u.values: u for u in universe.units}
        self.serials: list[tuple[str, str, str, int]] = []
        for u in universe.units + universe.orphans:
            self.registry.owners[u.slug] = u.owner()

    # ------------------------------------------------------------------ table --
    def table(self, t: TableInfo) -> TableData:
        rng = _table_rng(self.cfg.seed, t)
        pt = self.policy.table(t.schema, t.name)
        tcols = {c.name: self.tcol_keys[c.name] for c in t.columns if c.name in self.tcol_keys}
        if pt is not None and pt.tenant_columns:
            tcols = dict(pt.tenant_columns)
        keys = tuple(k for k in self.key_order if k in tcols.values())
        tsl = table_slug(t.schema, t.name)
        self.registry.tables[tsl] = t.dotted

        # owners for each row
        owners: list[tuple[tuple[tuple[str, str | None], ...], str]] = []
        if keys:
            proj = self.universe.projected_units(keys)
            if t.dotted in self.unit_tables:
                owners = [(vals, s) for vals, s, _w in proj]
            else:
                n = max(len(proj), round(self.cfg.rows_per_table * self.cfg.scale))
                owners = [(vals, s) for vals, s, _w in proj]
                cum, acc = [], 0.0
                for _v, _s, w in proj:
                    acc += w
                    cum.append(acc)
                for _ in range(n - len(proj)):
                    i = min(bisect.bisect_right(cum, rng.random() * acc), len(proj) - 1)
                    owners.append((proj[i][0], proj[i][1]))
                if self.cfg.orphan_rows:
                    for o in self.universe.orphans:  # two NULL/'' tenant rows each
                        owners += [(o.project(keys), o.slug)] * 2
        else:
            owners = [((), "global")] * max(1, round(self.cfg.global_rows))

        cols = [c for c in t.columns if not c.generated and not c.identity_always]
        # columns whose tenant value is NULL but NOT NULL in the schema: drop such orphan rows
        out_rows: list[tuple[Any, ...]] = []
        dict_rows: list[dict[str, Any]] = []
        row_owners: list[tuple[tuple[str, str | None], ...]] = []
        serial_max: dict[str, int] = {}
        for vals, oslug in owners:
            ov = dict(vals)
            if any(ov.get(tcols[c.name]) is None and not c.nullable for c in cols if c.name in tcols):
                continue
            n = len(dict_rows) + 1
            row: dict[str, Any] = {}
            fk_cols = self._fill_fks(t, rng, ov, keys, tcols, row)
            for c in cols:
                if c.name in row and c.name in fk_cols:
                    continue
                row[c.name] = self._value(t, c, rng, n, ov, oslug, tcols, pt, keys, vals)
                if c.serial and isinstance(row[c.name], int):
                    serial_max[c.name] = max(serial_max.get(c.name, 0), row[c.name])
            dict_rows.append(row)
            row_owners.append(vals)
            out_rows.append(tuple(row[c.name] for c in cols))
        self.rows[t.key] = dict_rows
        self.owner_of[t.key] = row_owners
        for i, vals in enumerate(row_owners):
            self.index.setdefault((t.key, vals), []).append(i)
        td = TableData(t, [c.name for c in cols], out_rows)
        self.serials.extend((t.schema, t.name, c, m) for c, m in serial_max.items())
        return td

    # -------------------------------------------------------------------- FKs --
    def _fill_fks(self, t: TableInfo, rng: random.Random, ov: dict[str, str | None],
                  keys: tuple[str, ...], tcols: dict[str, str], row: dict[str, Any]) -> set[str]:
        filled: set[str] = set()
        for fk in t.fks:
            pkey = (fk.ref_schema, fk.ref_table)
            parents = self.rows.get(pkey)
            if not parents or pkey == t.key:
                for c in fk.columns:
                    if c not in tcols:
                        row[c] = None
                        filled.add(c)
                continue
            includes_tenant = any(c in tcols for c in fk.columns)
            pkeys_owner = self.owner_of[pkey][0] if self.owner_of[pkey] else ()
            pkeyset = tuple(k for k, _ in pkeys_owner)
            choice: int | None = None
            if pkeyset and set(pkeyset) <= set(ov):
                proj = tuple((k, ov[k]) for k in pkeyset)
                cands = self.index.get((pkey, proj), [])
                cross = (not includes_tenant) and rng.random() < self.cfg.cross_tenant_fk_rate
                if cands and not cross:
                    choice = cands[rng.randrange(len(cands))]
            if choice is None:
                if includes_tenant:
                    # cannot satisfy the tenant part elsewhere; leave NULL
                    for c in fk.columns:
                        if c not in tcols:
                            row[c] = None
                            filled.add(c)
                    continue
                choice = rng.randrange(len(parents))
            prow = parents[choice]
            for c, rc in zip(fk.columns, fk.ref_columns):
                if c in tcols:
                    continue
                row[c] = prow.get(rc)
                filled.add(c)
        return filled

    # ------------------------------------------------------------------ value --
    def _value(self, t: TableInfo, c: ColumnInfo, rng: random.Random, n: int,
               ov: dict[str, str | None], oslug: str, tcols: dict[str, str], pt: Any,
               keys: tuple[str, ...], vals: tuple[tuple[str, str | None], ...]) -> Any:
        if c.name in tcols:
            return ov.get(tcols[c.name])
        role = self.column_roles.get((t.dotted, c.name))
        if role == "parent":
            u = self.unit_by_values.get(vals)
            return u.parent if u else None
        if c.serial:
            return n
        if c.enum_labels:
            labels = list(c.enum_labels)
            return [labels[n % len(labels)]] if c.is_array else labels[rng.randrange(len(labels))]
        allowed = pt is not None and pt.allows_column(c.name)
        tenant_scoped = bool(keys)
        pk_single = t.pk == (c.name,)
        ty = c.type
        if ty in _TEXT_TYPES:
            v = self._text(t, c, rng, n, oslug, allowed, tenant_scoped, pk_single)
            return [v, "x"] if c.is_array and v is not None else v
        if c.is_array:
            return [n, n + 1] if ty in ("int2", "int4", "int8") else None
        if ty in ("int2",):
            return rng.randint(0, 100)
        if ty in ("int4",):
            return rng.randint(1, 1000) if not pk_single else n
        if ty in ("int8",):
            return n if pk_single else rng.randint(100, 1_000_000)
        if ty == "numeric":
            hi = 1.0 if "ratio" in c.name else 9000.0
            return round(rng.uniform(0, hi), 2 if hi > 1 else 4)
        if ty in ("float4", "float8"):
            return round(rng.uniform(0, 100), 3)
        if ty == "bool":
            return rng.random() < (0.1 if "deleted" in c.name else 0.5)
        if ty == "date":
            return (_EPOCH + dt.timedelta(days=rng.randrange(_SPAN_DAYS))).date()
        if ty in ("timestamptz", "timestamp"):
            if c.name == "deleted_at" and rng.random() < 0.9:
                return None
            ts = _EPOCH + dt.timedelta(seconds=rng.randrange(_SPAN_DAYS * 86400))
            return ts if ty == "timestamptz" else ts.replace(tzinfo=None)
        if ty in ("jsonb", "json"):
            if not allowed:
                return json.dumps({"secret": column_marker(t.schema, t.name, c.name, n)})
            if tenant_scoped:
                return json.dumps({"ref": tenant_marker(oslug, t.schema, t.name, n), "n": n})
            return json.dumps({"n": n})
        if ty == "uuid":
            return str(uuid.UUID(int=rng.getrandbits(128)))
        if ty == "inet":
            return f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
        if ty == "interval":
            return dt.timedelta(days=rng.randrange(60))
        if ty == "bytea":
            return bytes(rng.getrandbits(8) for _ in range(8))
        return None

    def _text(self, t: TableInfo, c: ColumnInfo, rng: random.Random, n: int, oslug: str,
              allowed: bool, tenant_scoped: bool, pk_single: bool) -> str | None:
        is_email = "email" in c.name.lower() or (c.domain or "").endswith("email_address")
        vocab = _vocab_for(c)
        if not allowed:
            v = column_marker(t.schema, t.name, c.name, n)
            if is_email:
                v += "@example.test"
            fitted = _fit(v, c)
            if fitted is not None:
                self.registry.columns.setdefault(table_slug(t.schema, t.name), [])
                cs = slug(c.name)
                if cs not in self.registry.columns[table_slug(t.schema, t.name)]:
                    self.registry.columns[table_slug(t.schema, t.name)].append(cs)
                return fitted
        if c.name.lower() == "card_last4":
            return f"{rng.randrange(10000):04d}"
        if vocab is not None:
            if pk_single:
                v = vocab[(n - 1) % len(vocab)] + ("" if n <= len(vocab) else str(n))
            else:
                v = vocab[rng.randrange(len(vocab))]
            f = _fit(v, c)
            return f if f is not None else v[: c.char_max]
        if tenant_scoped:
            v = f"{tenant_marker(oslug, t.schema, t.name, n)} {WORDS[n % len(WORDS)]} {c.name}"
            if is_email:
                v = f"{tenant_marker(oslug, t.schema, t.name, n)}@example.test"
        else:
            v = f"{WORDS[n % len(WORDS)]} {n}" if not is_email else f"user{n}@example.test"
        f = _fit(v, c)
        if f is not None:
            return f
        # too short for a marker: deterministic short code
        width = c.char_max or 8
        base = "".join(chr(97 + ((n // 26**i) % 26)) for i in range(width))
        return base[:width]


def generate(
    catalog: list[TableInfo],
    policy: LabPolicy,
    universe: Universe,
    cfg: DataConfig,
    unit_tables: tuple[str, ...] = (),
    column_roles: dict[tuple[str, str], str] | None = None,
) -> Dataset:
    """Generate rows for every insertable table in ``catalog`` (already FK-sorted)."""
    g = _Gen(policy, universe, cfg, unit_tables, column_roles or {})
    tables = [g.table(t) for t in catalog if t.insertable]
    return Dataset(tables=tables, registry=g.registry, serials=g.serials)


def load(conn: Any, ds: Dataset) -> None:
    """COPY the dataset in, fix sequences, refresh materialized views."""
    with conn.cursor() as cur:
        for td in ds.tables:
            if not td.rows:
                continue
            cols = ", ".join(qi(c) for c in td.columns)
            with cur.copy(f"COPY {qname(td.table.schema, td.table.name)} ({cols}) FROM STDIN") as cp:
                for r in td.rows:
                    cp.write_row(r)
        for schema, table, col, mx in ds.serials:
            cur.execute(
                "SELECT setval(pg_get_serial_sequence(%s, %s), %s)",
                (qname(schema, table), col, mx),
            )
    conn.commit()
