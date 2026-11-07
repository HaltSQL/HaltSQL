"""Registry of schema fixtures (lab/schemas) and their policies (lab/policies).

Adding a fixture: write ``schemas/<name>.sql`` (tables, roles, RLS, grants),
``policies/<name>.yaml|json``, and register it here. Data generation and the
generic query templates are derived from the live catalog plus the policy, so
nothing else is required; fixture-specific benign templates are optional
(generators/benign.py).
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path

import yaml

LAB = Path(__file__).resolve().parent.parent
SCHEMAS = LAB / "schemas"
POLICIES = LAB / "policies"


@dataclass(frozen=True)
class Fixture:
    name: str
    model: str  # tenancy model, see common/tenancy.py
    policy: Path
    schema_sql: Path | None = None
    generated: bool = False  # schema+policy produced by schemas/<name>/generate.py
    # Tables that hold exactly one row per tenant unit ("schema.table").
    unit_tables: tuple[str, ...] = ()
    # (schema.table, column) -> special filler: "parent" (hierarchical parent id)
    column_roles: dict[tuple[str, str], str] = field(default_factory=dict)
    description: str = ""


FIXTURES: dict[str, Fixture] = {
    "saas_shared": Fixture(
        name="saas_shared",
        model="single",
        policy=POLICIES / "saas_shared.yaml",
        schema_sql=SCHEMAS / "saas_shared.sql",
        unit_tables=("app.orgs",),
        description="Shared tables keyed by tenant_id; PII columns; global currencies",
    ),
    "composite": Fixture(
        name="composite",
        model="composite",
        policy=POLICIES / "composite.yaml",
        schema_sql=SCHEMAS / "composite.sql",
        unit_tables=("ws.workspaces",),
        description="(org_id, workspace_id) composite tenant key",
    ),
    "hierarchical": Fixture(
        name="hierarchical",
        model="hierarchical",
        policy=POLICIES / "hierarchical.json",
        schema_sql=SCHEMAS / "hierarchical.sql",
        unit_tables=("crm.tenants",),
        column_roles={("crm.tenants", "parent_tenant_id"): "parent"},
        description="Parent org sees child orgs via a tenant_ids context list",
    ),
    "erp_large": Fixture(
        name="erp_large",
        model="single",
        policy=POLICIES / "erp_large.yaml",  # written by the generator
        generated=True,
        description="400+ tables across 12 schemas, generated (schemas/erp_large/generate.py)",
    ),
}


def get_fixture(name: str) -> Fixture:
    try:
        return FIXTURES[name]
    except KeyError:
        raise KeyError(f"unknown fixture {name!r}; known: {', '.join(sorted(FIXTURES))}") from None


def materialize_generated(fixture: Fixture, out_dir: Path, tables: int, seed: int) -> Fixture:
    """Run schemas/<name>/generate.py and return a Fixture pointing at the output."""
    gen_path = SCHEMAS / fixture.name / "generate.py"
    spec = importlib.util.spec_from_file_location(f"haltlab_gen_{fixture.name}", gen_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {gen_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    sql, policy = mod.generate(tables=tables, seed=seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    sql_path = out_dir / f"{fixture.name}.sql"
    pol_path = out_dir / f"{fixture.name}.yaml"
    sql_path.write_text(sql, encoding="utf-8")
    pol_path.write_text(yaml.safe_dump(policy, sort_keys=False, width=1000), encoding="utf-8")
    return Fixture(
        name=fixture.name,
        model=fixture.model,
        policy=pol_path,
        schema_sql=sql_path,
        generated=False,
        unit_tables=tuple(getattr(mod, "UNIT_TABLES", ())),
        description=fixture.description,
    )
