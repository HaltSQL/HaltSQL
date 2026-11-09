"""Trim real dbt artifacts into small unit-test fixtures.

Usage: python trim_fixture.py TARGET_DIR OUT_DIR

Writes OUT_DIR/dbt_manifest_1_12.json and OUT_DIR/dbt_catalog_1_12.json: the
models and the PII-relevant sources of test/catalog_live/dbt/project, with the
keys the importer reads (and the real neighbouring keys of each column), minus
absolute paths, macros, graphs and run metadata.
"""

import json
import os
import sys

target, out = sys.argv[1], sys.argv[2]
NODE_KEYS = [
    "database", "schema", "name", "resource_type", "package_name", "unique_id",
    "source_name", "identifier", "alias", "relation_name", "description",
    "tags", "meta", "config", "columns",
]
CONFIG_KEYS = ["enabled", "alias", "schema", "materialized", "tags", "meta", "persist_docs"]
SOURCES = ["customers", "users", "payments", "audit_events", "orgs"]
META_KEYS = ["dbt_schema_version", "dbt_version", "generated_at", "adapter_type", "project_name"]


def trim_node(n):
    t = {k: n[k] for k in NODE_KEYS if k in n}
    if "config" in t:
        t["config"] = {k: t["config"][k] for k in CONFIG_KEYS if k in t["config"]}
    return t


def keep_source(uid):
    return uid.rsplit(".", 1)[-1] in SOURCES


m = json.load(open(os.path.join(target, "manifest.json")))
manifest = {
    "metadata": {k: m["metadata"][k] for k in META_KEYS if k in m["metadata"]},
    "nodes": {u: trim_node(n) for u, n in sorted(m["nodes"].items())},
    "sources": {u: trim_node(n) for u, n in sorted(m["sources"].items()) if keep_source(u)},
}
c = json.load(open(os.path.join(target, "catalog.json")))
catalog = {
    "metadata": {k: c["metadata"][k] for k in META_KEYS if k in c["metadata"]},
    "nodes": {u: {k: n[k] for k in ("metadata", "columns", "unique_id")}
              for u, n in sorted(c["nodes"].items())},
    "sources": {u: {k: n[k] for k in ("metadata", "columns", "unique_id")}
                for u, n in sorted(c["sources"].items()) if keep_source(u)},
    "errors": None,
}
for name, doc in (("dbt_manifest_1_12.json", manifest), ("dbt_catalog_1_12.json", catalog)):
    text = json.dumps(doc, indent=1, sort_keys=False) + "\n"
    assert "/Users/" not in text and "/home/" not in text and "/tmp/" not in text, name
    with open(os.path.join(out, name), "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {name} ({len(text)} bytes)")
