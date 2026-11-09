#!/usr/bin/env python3
"""Checks `haltsql schema fetch --from openmetadata` output against what seed.py applied.

  assert_fetch.py EXPECTED.json PII.json SNAPSHOT.json

- the PII manifest has exactly the expected columns, each with exactly the expected
  classifications, source "openmetadata";
- the catalog snapshot is non-authoritative, untyped, and lists the 9 saas_shared
  tables of the requested database only (not the API-only lake table).
"""

import json
import sys

SAAS_TABLES = {
    "app.audit_events",
    "app.currencies",
    "app.customers",
    "app.invoices",
    "app.order_items",
    "app.orders",
    "app.orgs",
    "app.payments",
    "app.users",
}


def main():
    expected_path, pii_path, snap_path = sys.argv[1:4]
    expected = json.load(open(expected_path))
    pii = json.load(open(pii_path))
    snap = json.load(open(snap_path))
    errors = []

    got = {}
    for table, t in pii["tables"].items():
        for col, c in t["columns"].items():
            got[f"{table}.{col}"] = sorted(c["classifications"])
            if c.get("source") != "openmetadata":
                errors.append(f"{table}.{col}: source {c.get('source')!r}")
    want = {k: sorted(v) for k, v in expected.items()}
    for k in sorted(set(want) | set(got)):
        if k not in got:
            errors.append(f"missing from manifest: {k} {want[k]}")
        elif k not in want:
            errors.append(f"unexpected in manifest: {k} {got[k]}")
        elif got[k] != want[k]:
            errors.append(f"{k}: classifications {got[k]} != {want[k]}")

    meta = snap.get("metadata", {})
    if meta.get("authoritative") is not False:
        errors.append(f"snapshot metadata.authoritative = {meta.get('authoritative')!r}")
    tables = set(snap.get("tables", {}))
    if tables != SAAS_TABLES:
        errors.append(f"snapshot tables {sorted(tables)} != {sorted(SAAS_TABLES)}")
    for tname, t in snap.get("tables", {}).items():
        cols = t.get("columns", [])
        typed = [c.get("name") for c in cols if isinstance(c, dict) and c.get("type")]
        if typed:
            errors.append(f"snapshot {tname}: typed columns {typed}")

    if errors:
        print("FAIL:\n  " + "\n  ".join(errors))
        sys.exit(1)
    print(f"OK: manifest = {len(want)} applied labels exactly; snapshot = "
          f"{len(tables)} tables, non-authoritative")


if __name__ == "__main__":
    main()
