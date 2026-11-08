"""Tier-3 catalog check: PII tagged in a data catalog is blocked against real Postgres.

Every data-catalog integration (dbt, DataHub, OpenMetadata, Unity Catalog, ...)
produces a PII manifest (docs/schema-and-pii.md). This check proves that the
manifest, and nothing else, keeps those columns away from an agent:

1. Create a fresh database from a lab fixture and ``haltsql schema pull`` it.
2. ``haltsql policy draft --pii <manifest> --no-name-heuristics`` (so the only
   reason a column is excluded is the manifest), then ``haltsql lint-policy``.
3. Structural check: every manifest column that exists in the database is
   absent from the drafted policy.
4. Positive run: haltlab with the drafted policy as both the verifier policy and
   the oracle ground truth (honeytokens in every denied column, ``haltlab_cols``
   granted exactly the allowed columns), with benign, adversarial, column-attack
   and per-manifest-column targeted workloads. Expect 0 escapes, 0 column leaks,
   and every targeted query denied.
5. Negative control: the verifier gets a policy drafted from an EMPTY manifest
   (or the allow-everything fake verifier) while the oracles still judge against
   the manifest. The oracles must detect a leak of every manifest column in the
   database; otherwise the positive result would be vacuous.

    python -m catalogs.tier3 --pii pii.json                  # positive + negative control
    python -m catalogs.tier3 --pii pii.json --mode positive
    python -m catalogs.tier3 --pii a.json --pii b.json --fixture saas_shared --keep

Exit status: 0 pass, 1 check failed, 2 usage or infrastructure error.
Environment: HALTSQL_BIN, HALTLAB_DSN (as for ``python -m harness``).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import psycopg
import yaml

from common.fixtures import LAB, Fixture, get_fixture, materialize_generated
from common.ident import qi, qname, slug, split_qualified
from common.policy import LabPolicy, load_policy
from generators.sqlspec import SchemaModel
from harness import db as labdb
from harness.runner import log, run_scenario
from harness.scenario import load_scenario
from harness.verifier import fake_verifier_command, resolve_binary

TARGETED_TRANSFORM = "catalog_targeted"
COLUMN_TRANSFORMS = ["star_over_pii", "star_over_pii_wrapped", "whole_row_reference", "whole_row_wrapped",
                     "denied_column_direct", "denied_column_wrapped", "denied_column_in_predicate"]


class Tier3Error(RuntimeError):
    """Infrastructure or usage problem (exit 2), as opposed to a failed check."""


# ------------------------------------------------------------ manifest ----
@dataclass(frozen=True)
class ManifestColumn:
    schema: str | None  # None when the manifest names the table without a schema
    table: str
    column: str
    labels: tuple[str, ...] = ()

    @property
    def dotted(self) -> str:
        return f"{self.schema + '.' if self.schema else ''}{self.table}.{self.column}"


def manifest_columns(doc: dict[str, Any]) -> list[ManifestColumn]:
    """Columns of a PII manifest (``haltsql schema import``/``schema fetch`` output)."""
    out: list[ManifestColumn] = []
    tables = doc.get("tables")
    if not isinstance(tables, dict):
        raise ValueError("PII manifest: `tables` must be an object")
    for tkey, spec in tables.items():
        parts = split_qualified(str(tkey))
        schema, table = (parts[-2], parts[-1]) if len(parts) >= 2 else (None, parts[0])
        for col, info in ((spec or {}).get("columns") or {}).items():
            labels = tuple(str(x) for x in (info or {}).get("classifications") or [])
            out.append(ManifestColumn(schema, table, str(col), labels))
    return out


def load_manifests(paths: Iterable[Path]) -> list[ManifestColumn]:
    seen: dict[str, ManifestColumn] = {}
    for p in paths:
        for mc in manifest_columns(json.loads(Path(p).read_text(encoding="utf-8"))):
            seen.setdefault(mc.dotted.lower(), mc)
    return list(seen.values())


# ------------------------------------------------------------- catalog ----
def catalog_tables(doc: dict[str, Any]) -> dict[tuple[str, str], list[str]]:
    """``(schema, table) -> columns`` from a ``haltsql schema pull`` snapshot."""
    out: dict[tuple[str, str], list[str]] = {}
    for tkey, spec in (doc.get("tables") or {}).items():
        parts = split_qualified(str(tkey))
        if len(parts) != 2:
            continue
        cols = (spec or {}).get("columns") or []
        out[(parts[0], parts[1])] = [c["name"] if isinstance(c, dict) else str(c) for c in cols]
    kinds = (doc.get("metadata") or {}).get("relations") or {}
    for tkey, kind in kinds.items():  # sequences are never queried as data
        parts = split_qualified(str(tkey))
        if kind == "sequence" and len(parts) == 2:
            out.pop((parts[0], parts[1]), None)
    return out


def resolve_column(mc: ManifestColumn, tables: dict[tuple[str, str], list[str]]) -> list[tuple[str, str, str]]:
    """Database columns a manifest entry names: exact, then case-insensitive."""
    hits: list[tuple[str, str, str]] = []
    for (s, t), cols in tables.items():
        if t != mc.table and t.lower() != mc.table.lower():
            continue
        if mc.schema is not None and s != mc.schema and s.lower() != mc.schema.lower():
            continue
        col = mc.column if mc.column in cols else next((c for c in cols if c.lower() == mc.column.lower()), None)
        if col is not None:
            hits.append((s, t, col))
    return hits


@dataclass
class Structural:
    targets: list[tuple[str, str, str]] = field(default_factory=list)  # in DB and excluded: the subjects
    missing: list[str] = field(default_factory=list)  # manifest columns not in the database
    tenant_skipped: list[str] = field(default_factory=list)  # tenant columns can never be excluded
    failures: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures


def structural_check(manifest: list[ManifestColumn], tables: dict[tuple[str, str], list[str]],
                     policy: LabPolicy, tenant_column: str) -> Structural:
    """Every manifest column present in the database must be absent from ``policy``."""
    r = Structural()
    for mc in manifest:
        hits = resolve_column(mc, tables)
        if not hits:
            r.missing.append(mc.dotted)
            continue
        for s, t, c in hits:
            if c == tenant_column:
                r.tenant_skipped.append(f"{s}.{t}.{c}")
                continue
            pt = policy.table(s, t)
            if pt is not None and pt.allows_column(c):
                r.failures.append(f"{s}.{t}.{c} is tagged in the catalog but allowed by the drafted policy")
            elif (s, t, c) not in r.targets:
                r.targets.append((s, t, c))
    if not r.targets and not r.failures:
        r.failures.append("no manifest column exists in the fixture database: the check would prove nothing "
                          "(wrong fixture, or table names that do not match `schema.table`?)")
    return r


# ---------------------------------------------------- targeted queries ----
def targeted_queries(targets: list[tuple[str, str, str]], tables: dict[tuple[str, str], list[str]],
                     policy: LabPolicy, model: str, limit: int = 20) -> list[dict[str, Any]]:
    """Adversarial queries aimed at exactly the manifest columns.

    Per table: ``*``, ``t.*``, ``*`` inside a CTE and a derived table, and the
    whole row through ``row_to_json``/``to_json``/``to_jsonb``/``json_agg``/
    ``::text``/a bare row reference. Per column: a direct read, a predicate, a
    CTE, a derived table, a scalar subquery, a cast and an ORDER BY. Single-column
    items carry ``meta.target`` so a column-privilege finding is attributable.
    Tenant predicates come from the oracle policy (``$n`` bound to the caller)."""
    sm = SchemaModel.build(policy, model)
    by_table: dict[tuple[str, str], list[str]] = {}
    for s, t, c in targets:
        by_table.setdefault((s, t), []).append(c)
    items: list[dict[str, Any]] = []

    def add(ident: str, sql: str, table: str, column: str | None) -> None:
        items.append({"id": f"t3-{ident}", "sql": sql, "intent": "adversarial", "transform": TARGETED_TRANSFORM,
                      "leak": "column", "target": {"table": table, "column": column}})

    for (s, t), cols in sorted(by_table.items()):
        rel = qname(s, t)
        dotted = f"{s}.{t}"
        tm = sm.tables.get((s, t))
        tp = sm.tenant_pred("a", tm) if tm else "true"
        tpb = sm.tenant_pred("b", tm) if tm else "true"
        allowed = [c for c in tables.get((s, t), []) if tm is None or c in tm.columns]
        pk = qi("id" if "id" in tables.get((s, t), []) else (allowed or tables[(s, t)])[0])
        w = f"FROM {rel} a WHERE {tp}"
        for kind, sql in [
            ("star", f"SELECT * {w} ORDER BY a.{pk} LIMIT {limit}"),
            ("alias_star", f"SELECT a.* {w} ORDER BY a.{pk} LIMIT {limit}"),
            ("cte_star", f"WITH q AS (SELECT * {w}) SELECT * FROM q LIMIT {limit}"),
            ("derived_star", f"SELECT sq.* FROM (SELECT a.* {w}) AS sq LIMIT {limit}"),
            ("row_to_json", f"SELECT row_to_json(a) AS r {w} LIMIT {limit}"),
            ("to_json", f"SELECT to_json(a) AS r {w} LIMIT {limit}"),
            ("to_jsonb", f"SELECT to_jsonb(a) AS r {w} LIMIT {limit}"),
            ("json_agg", f"SELECT json_agg(a) AS r {w} LIMIT 1"),
            ("row_text", f"SELECT a::text AS r {w} LIMIT {limit}"),
            ("whole_row", f"SELECT a {w} LIMIT {limit}"),
            ("cte_row_to_json", f"WITH q AS (SELECT * {w}) SELECT row_to_json(q) AS r FROM q LIMIT {limit}"),
        ]:
            add(f"{dotted}-{kind}", sql, dotted, None)
        for c in cols:
            qc = qi(c)
            for kind, sql in [
                ("direct", f"SELECT a.{pk}, a.{qc} {w} ORDER BY a.{pk} LIMIT {limit}"),
                ("only", f"SELECT a.{qc} {w} LIMIT {limit}"),
                ("predicate", f"SELECT count(*) AS n {w} AND a.{qc} IS NOT NULL LIMIT 1"),
                ("cte", f"WITH q AS (SELECT a.{qc} AS v {w}) SELECT v FROM q LIMIT {limit}"),
                ("derived", f"SELECT sq.v FROM (SELECT a.{qc} AS v {w}) AS sq LIMIT {limit}"),
                ("scalar_subquery", f"SELECT a.{pk}, (SELECT b.{qc} FROM {rel} b WHERE b.{pk} = a.{pk} "
                                    f"AND {tpb}) AS v {w} ORDER BY a.{pk} LIMIT {limit}"),
                ("cast", f"SELECT a.{qc}::text AS v {w} LIMIT {limit}"),
                ("order_by", f"SELECT a.{pk} {w} ORDER BY a.{qc} LIMIT {limit}"),
            ]:
                add(f"{dotted}.{c}-{kind}", sql, dotted, c)
    return items


def write_jsonl(items: list[dict[str, Any]], path: Path) -> None:
    path.write_text("".join(json.dumps(it, ensure_ascii=False) + "\n" for it in items), encoding="utf-8")


# ------------------------------------------------------------ coverage ----
_HONEY = re.compile(r"^honeytoken: column marker \S+ from (?P<table>.+)\.(?P<col>[a-z0-9_]+)$")
_RUN_PREFIX = re.compile(r"^w\d+-")


def detected_columns(examples: list[dict[str, Any]], targets_by_id: dict[str, dict[str, Any]]
                     ) -> set[tuple[str, str]]:
    """``(schema.table, column-slug)`` pairs some oracle saw leak.

    Honeytoken findings name the column; a column-privilege finding is
    attributed only to single-column targeted items (``meta.target.column``)."""
    seen: set[tuple[str, str]] = set()
    for ex in examples:
        target = targets_by_id.get(_RUN_PREFIX.sub("", str(ex.get("id", ""))))
        for f in ex.get("findings") or []:
            m = _HONEY.match(f)
            if m:
                seen.add((m.group("table"), m.group("col")))
            elif f.startswith("columns:") and target and target.get("column"):
                seen.add((target["table"], slug(target["column"])))
    return seen


# ------------------------------------------------------------ pipeline ----
def _haltsql(cmd: list[str], args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run([*cmd, *args], capture_output=True, text=True, env=env)
    for line in (proc.stderr or "").splitlines():
        log(f"  haltsql: {line}")
    return proc


def pull_catalog(cmd: list[str], admin: str, fixture: Fixture, schemas: list[str], run_id: str,
                 out: Path, keep_db: bool) -> None:
    """Create a fresh database from the fixture and snapshot it with ``haltsql schema pull``."""
    name = labdb.db_name("t3pull", 0, run_id).removesuffix("_pg0")
    log(f"creating database {name} from {fixture.schema_sql}")
    dsn = labdb.create_database(admin, name)
    try:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(Path(fixture.schema_sql).read_text(encoding="utf-8"))  # type: ignore[arg-type]
        info = psycopg.conninfo.conninfo_to_dict(dsn)
        env = dict(os.environ)
        if info.get("password"):
            env["PGPASSWORD"] = str(info["password"])
        url = f"postgres://{info.get('user') or 'postgres'}@{info.get('host') or 'localhost'}:" \
              f"{info.get('port') or 5432}/{name}"
        args = ["schema", "pull", "--dsn", url, "-o", str(out)]
        for s in schemas:
            args += ["--schema", s]
        proc = _haltsql(cmd, args, env)
        if proc.returncode != 0:
            raise Tier3Error(f"haltsql schema pull exited {proc.returncode}")
    finally:
        if not keep_db:
            labdb.drop_database(admin, name)


def draft_policy(cmd: list[str], catalog: Path, manifests: list[Path], tenant_column: str,
                 schemas: list[str], out: Path) -> None:
    args = ["policy", "draft", "--catalog", str(catalog), "--tenant-column", tenant_column,
            "--no-name-heuristics", "-o", str(out), "--name", out.stem]
    for m in manifests:
        args += ["--pii", str(m)]
    for s in schemas:
        args += ["--schema", s]
    proc = _haltsql(cmd, args)
    if proc.returncode != 0:
        raise Tier3Error(f"haltsql policy draft exited {proc.returncode}")
    lint = _haltsql(cmd, ["lint-policy", str(out)])
    for line in lint.stdout.splitlines():
        log(f"  lint: {line}")
    if lint.returncode != 0:
        raise Tier3Error(f"haltsql lint-policy {out.name} exited {lint.returncode}")


def write_scenario(path: Path, name: str, fixture: str, targeted: Path, args: argparse.Namespace,
                   negative: bool) -> None:
    doc = {
        "apiVersion": "haltsql.dev/v1",
        "kind": "Scenario",
        "metadata": {"name": name},
        "environment": {"postgres": [args.pg], "topology": "embedded"},
        "fixture": fixture,
        "data": {"scale": "tiny", "tenants": 8, "skew": "zipf(1.2)", "seed": args.seed},
        "workloads": [
            {"benign": {"queries": args.benign}},
            {"adversarial": {"queries": args.adversarial}},
            {"adversarial": {"queries": args.column_attacks, "transforms": COLUMN_TRANSFORMS}},
            {"replay": {"file": targeted.name}},
        ],
        # The negative control records leaks instead of failing on them; tier3 asserts them.
        "expect": ({"escapes": None, "side_effects": None, "column_leaks": None} if negative else
                   {"escapes": 0, "side_effects": 0, "column_leaks": 0, "min_executed": 50}),
    }
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _report(out: Path) -> dict[str, Any]:
    return json.loads((out / "report.json").read_text(encoding="utf-8"))


def run(args: argparse.Namespace) -> int:
    run_id = args.run_id or f"{os.getpid()}_{secrets.token_hex(3)}"
    out = (args.out or LAB / "out" / "catalog-tier3" / run_id).resolve()
    out.mkdir(parents=True, exist_ok=True)
    manifests = [p.resolve() for p in args.pii]
    for p in manifests:
        if not p.is_file():
            raise Tier3Error(f"PII manifest not found: {p}")
    try:
        cmd = resolve_binary()
    except FileNotFoundError as e:
        raise Tier3Error(str(e)) from None
    fixture = get_fixture(args.fixture)
    if fixture.generated:
        fixture = materialize_generated(fixture, out / "fixture", 420, args.seed)
    schemas = load_policy(fixture.policy).schemas
    admin = labdb.admin_dsn(args.pg, os.environ.get("HALTLAB_DSN"))
    log(f"tier 3 run {run_id}: fixture {fixture.name}, manifests {', '.join(p.name for p in manifests)}; "
        f"output {out}")

    # 1-2. Authoritative snapshot, drafted policy, lint.
    catalog = out / "catalog.json"
    pull_catalog(cmd, admin, fixture, schemas, run_id, catalog, args.keep_db)
    policy_path = out / "policy.catalog.yaml"
    draft_policy(cmd, catalog, manifests, args.tenant_column, schemas, policy_path)
    policy = load_policy(policy_path)

    # 3. Structural check.
    tables = catalog_tables(json.loads(catalog.read_text(encoding="utf-8")))
    manifest = load_manifests(manifests)
    st = structural_check(manifest, tables, policy, args.tenant_column)
    log(f"structural: {len(manifest)} manifest column(s); {len(st.targets)} in the database and excluded")
    for m in st.missing:
        log(f"  note: {m} is not in the {fixture.name} database (ignored)")
    for m in st.tenant_skipped:
        log(f"  warning: {m} is the tenant column; policy draft never excludes it (not checked)")
    for f in st.failures:
        log(f"  FAIL {f}")
    summary: dict[str, Any] = {
        "run_id": run_id, "fixture": fixture.name, "manifests": [str(p) for p in manifests],
        "policy": str(policy_path), "catalog": str(catalog),
        "structural": {"ok": st.ok, "targets": [".".join(t) for t in st.targets], "missing": st.missing,
                       "tenant_skipped": st.tenant_skipped, "failures": st.failures},
    }
    failures = [f"structural: {f}" for f in st.failures]
    if not st.ok:
        return _finish(out, summary, failures)

    targeted = targeted_queries(st.targets, tables, policy, fixture.model)
    targeted_path = out / "targeted.jsonl"
    write_jsonl(targeted, targeted_path)
    targets_by_id = {it["id"]: it["target"] for it in targeted}
    log(f"wrote {len(targeted)} targeted queries for {len(st.targets)} manifest column(s)")

    # 4. Positive run: drafted policy for the verifier and the oracles.
    if args.mode in ("positive", "both"):
        scn_path = out / "positive.scenario.yaml"
        write_scenario(scn_path, "catalog-tier3", fixture.name, targeted_path, args, negative=False)
        pos_out = out / "positive"
        log("positive run: verifier and oracles use the catalog-drafted policy")
        ok = run_scenario(load_scenario(scn_path), pos_out, cmd, keep_db=args.keep_db, jobs=args.jobs,
                          policy_path=policy_path, oracle_policy_path=policy_path, run_id=f"{run_id}p")
        rep = _report(pos_out)
        m = rep["runs"][0]["metrics"]
        tgt = m["by_transform"].get(TARGETED_TRANSFORM, {"total": 0, "allowed": 0})
        summary["positive"] = {"passed": ok, "report": str(pos_out / "report.md"), "executed": m["executed"],
                               "escapes": m["escapes"], "column_leaks": m["column_leaks"],
                               "side_effects": m["side_effects"], "targeted_total": tgt["total"],
                               "targeted_allowed": tgt["allowed"],
                               "false_positive_rate": m["false_positive_rate"]}
        if not ok:
            failures += [f"positive: {f}" for f in rep["failures"]]
        if tgt["allowed"]:
            failures.append(f"positive: {tgt['allowed']} of {tgt['total']} queries that read a manifest column "
                            f"were allowed")
        log(f"positive: executed={m['executed']} escapes={m['escapes']} column_leaks={m['column_leaks']} "
            f"targeted allowed={tgt['allowed']}/{tgt['total']}")

    # 5. Negative control: the verifier lacks the catalog tags; the oracles must notice.
    if args.mode in ("negative", "both"):
        if args.negative_control == "fake-allow":
            neg_cmd = fake_verifier_command() + ["--mode", "allow"]
            neg_policy = policy_path
            log("negative control: allow-everything fake verifier; oracles use the catalog-drafted policy")
        else:
            empty = out / "pii.empty.json"
            empty.write_text(json.dumps({"metadata": {"source": "tier3-negative-control"}, "tables": {}}) + "\n",
                             encoding="utf-8")
            neg_policy = out / "policy.no-catalog.yaml"
            draft_policy(cmd, catalog, [empty], args.tenant_column, schemas, neg_policy)
            neg_cmd = cmd
            log("negative control: verifier uses a policy drafted from an EMPTY manifest; "
                "oracles use the catalog-drafted policy")
        scn_path = out / "negative.scenario.yaml"
        write_scenario(scn_path, "catalog-tier3-negative", fixture.name, targeted_path, args, negative=True)
        neg_out = out / "negative"
        run_scenario(load_scenario(scn_path), neg_out, neg_cmd, keep_db=args.keep_db, jobs=args.jobs,
                     policy_path=neg_policy, oracle_policy_path=policy_path, run_id=f"{run_id}n")
        rep = _report(neg_out)
        run0 = rep["runs"][0]
        m = run0["metrics"]
        seen = detected_columns(run0.get("examples") or [], targets_by_id)
        undetected = [f"{s}.{t}.{c}" for s, t, c in st.targets if (f"{s}.{t}", slug(c)) not in seen]
        summary["negative"] = {"control": args.negative_control, "report": str(neg_out / "report.md"),
                               "executed": m["executed"], "escapes": m["escapes"],
                               "column_leaks": m["column_leaks"],
                               "detected": sorted(".".join(t) for t in st.targets
                                                  if (f"{t[0]}.{t[1]}", slug(t[2])) in seen),
                               "undetected": undetected}
        log(f"negative: executed={m['executed']} column_leaks={m['column_leaks']} "
            f"manifest columns detected leaking {len(st.targets) - len(undetected)}/{len(st.targets)}")
        if not m["column_leaks"]:
            failures.append("negative control: no column leak detected without the catalog tags; "
                            "the oracles are vacuous for this manifest")
        for u in undetected:
            failures.append(f"negative control: no oracle detected a leak of {u} without the catalog tags")
    return _finish(out, summary, failures)


def _finish(out: Path, summary: dict[str, Any], failures: list[str]) -> int:
    summary["passed"] = not failures
    summary["failures"] = failures
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    for f in failures:
        log(f"FAIL {f}")
    log(f"summary: {out / 'summary.json'}")
    log("TIER3 PASS" if not failures else "TIER3 FAIL")
    return 0 if not failures else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m catalogs.tier3", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pii", type=Path, action="append", required=True,
                    help="PII manifest (haltsql schema import/fetch output); repeatable, merged")
    ap.add_argument("--fixture", default="saas_shared", help="lab fixture (default saas_shared)")
    ap.add_argument("--tenant-column", default="tenant_id")
    ap.add_argument("--mode", choices=["both", "positive", "negative"], default="both",
                    help="positive run, negative control, or both (default)")
    ap.add_argument("--negative-control", choices=["empty-manifest", "fake-allow"], default="empty-manifest",
                    help="what the verifier gets in the negative control (default: a policy drafted "
                         "from an empty manifest)")
    ap.add_argument("--pg", type=int, default=17, help="Postgres version (port 54NN; default 17)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--benign", type=int, default=200)
    ap.add_argument("--adversarial", type=int, default=400)
    ap.add_argument("--column-attacks", type=int, default=200)
    ap.add_argument("--jobs", type=int)
    ap.add_argument("--out", type=Path, help="output directory (default lab/out/catalog-tier3/<run id>)")
    ap.add_argument("--run-id", help="unique id for database names (default <pid>_<random>)")
    ap.add_argument("--keep-db", action="store_true", help="keep the databases for inspection")
    a = ap.parse_args(argv)
    try:
        return run(a)
    except (Tier3Error, ValueError, OSError, psycopg.Error) as e:
        log(f"error: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
