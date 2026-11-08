#!/usr/bin/env python3
"""Seed a live OpenMetadata instance the way a governance team would.

1. Creates a source database in the lab Postgres from lab/schemas/saas_shared.sql.
2. Ingests it with OpenMetadata's real Postgres connector (`metadata ingest`, from the
   openmetadata-ingestion package matching the server version).
3. Labels columns through the REST API (JSON-patch on /api/v1/tables/{id}):
   classification tags, a glossary term, a nested STRUCT child, and labels that must NOT
   count as PII (Tier.Tier1, a non-PII classification, a column description).
4. Creates a read-only bot (DataConsumer role) and writes its JWT to --token-out: that is
   the credential `haltsql schema fetch` uses.

Prints the expected PII manifest entries (schema.table.column -> labels) as JSON on
stdout, so run.sh can compare them with what HaltSQL fetches.

Every step is idempotent: re-running against the same instance converges.

Usage (see run.sh):
  python seed.py --om-url http://127.0.0.1:8595 --pg-host 127.0.0.1 --pg-port 5417 \
      --src-db om_src_1234 --service haltsql_lab_pg --token-out /tmp/tok \
      --metadata-bin venv/bin/metadata
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SCHEMA_SQL = os.path.join(ROOT, "lab", "schemas", "saas_shared.sql")

# ------------------------------------------------------------------ the labels
# (schema, table, column) -> list of (tagFQN, source). Applied verbatim.
COLUMN_LABELS = {
    ("app", "customers", "email"): [("PII.Sensitive", "Classification")],
    ("app", "customers", "phone"): [("PersonalData.Personal", "Classification")],
    ("app", "customers", "ssn"): [
        ("PII.Sensitive", "Classification"),
        ("PersonalData.SpecialCategory", "Classification"),
    ],
    ("app", "users", "email"): [("PII.Sensitive", "Classification")],
    # Glossary only: proves glossary terms are read.
    ("app", "users", "full_name"): [("Business.PersonalInformation", "Glossary")],
    ("app", "users", "password_hash"): [("PII.Sensitive", "Classification")],
    ("app", "payments", "card_token"): [("PII.Sensitive", "Classification")],
    # OpenMetadata defines PII.NonSensitive as PII that is publicly available: still PII.
    ("app", "payments", "card_last4"): [("PII.NonSensitive", "Classification")],
    ("app", "audit_events", "ip"): [("PersonalData.Personal", "Classification")],
    # Must NOT count: a tier tag and a non-PII classification.
    ("app", "orders", "note"): [("Tier.Tier1", "Classification")],
    ("app", "invoices", "amount_cents"): [("DataDomain.Finance", "Classification")],
}
# Table-level tag: must not flag any column.
TABLE_LABELS = {("app", "customers"): [("Tier.Tier1", "Classification")]}
# Column description mentioning PII words: descriptions are not labels.
COLUMN_DESCRIPTIONS = {
    ("app", "orgs", "name"): "Legal name; may contain the owner's personal email address."
}
# Expected PII manifest for the source database (default matcher terms).
EXPECTED = {
    "app.customers.email": ["PII.Sensitive"],
    "app.customers.phone": ["PersonalData.Personal"],
    "app.customers.ssn": ["PII.Sensitive", "PersonalData.SpecialCategory"],
    "app.users.email": ["PII.Sensitive"],
    "app.users.full_name": ["Business.PersonalInformation"],
    "app.users.password_hash": ["PII.Sensitive"],
    "app.payments.card_token": ["PII.Sensitive"],
    "app.payments.card_last4": ["PII.NonSensitive"],
    "app.audit_events.ip": ["PersonalData.Personal"],
}

# A second database registered through the API only (not in Postgres): a table with a
# STRUCT column whose child is tagged. Used to capture nested-children responses, and as
# a decoy that a --database filter must exclude.
LAKE_DB = "lake"
LAKE_SCHEMA = "events"
LAKE_TABLE = {
    "name": "page_views",
    "columns": [
        {"name": "id", "dataType": "BIGINT", "dataTypeDisplay": "bigint"},
        {
            "name": "context",
            "dataType": "STRUCT",
            "dataTypeDisplay": "struct<user_email:varchar,user_agent:varchar>",
            "children": [
                {
                    "name": "user_email",
                    "dataType": "VARCHAR",
                    "dataLength": 256,
                    "dataTypeDisplay": "varchar",
                    "tags": [
                        {
                            "tagFQN": "PII.Sensitive",
                            "source": "Classification",
                            "labelType": "Manual",
                            "state": "Confirmed",
                        }
                    ],
                },
                {
                    "name": "user_agent",
                    "dataType": "VARCHAR",
                    "dataLength": 256,
                    "dataTypeDisplay": "varchar",
                },
            ],
        },
        {"name": "url", "dataType": "TEXT", "dataTypeDisplay": "text"},
    ],
}


def log(msg):
    print(f"[seed] {msg}", file=sys.stderr, flush=True)


class Om:
    def __init__(self, url):
        self.url = url.rstrip("/")
        self.token = None

    def call(self, method, path, body=None, ctype="application/json", ok=(200, 201)):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", ctype)
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            if e.code in ok:
                return e.code, None
            raise RuntimeError(f"{method} {path} -> {e.code}: {raw[:500]}") from None

    def get(self, path):
        return self.call("GET", path)[1]

    def put(self, path, body):
        return self.call("PUT", path, body)[1]

    def patch(self, path, ops):
        return self.call("PATCH", path, ops, ctype="application/json-patch+json")[1]

    def try_get(self, path):
        try:
            return self.get(path)
        except RuntimeError as e:
            if "-> 404" in str(e):
                return None
            raise


def wait_ready(om, timeout=600):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            v = om.get("/api/v1/system/version")
            log(f"server version {v.get('version')}")
            return v
        except Exception:
            time.sleep(5)
    raise SystemExit("OpenMetadata did not become ready")


def login_admin(om):
    pw = base64.b64encode(b"admin").decode()
    _, r = om.call(
        "POST",
        "/api/v1/users/login",
        {"email": "admin@open-metadata.org", "password": pw},
    )
    om.token = r["accessToken"]


def bot_jwt(om, bot_name):
    bot = om.get(f"/api/v1/bots/name/{bot_name}")
    uid = bot["botUser"]["id"]
    am = om.get(f"/api/v1/users/auth-mechanism/{uid}")
    return am["config"]["JWTToken"]


def create_source_db(args):
    import psycopg2  # from openmetadata-ingestion[postgres]

    conn = psycopg2.connect(
        host=args.pg_host,
        port=args.pg_port,
        user=args.pg_user,
        password=args.pg_password,
        dbname="postgres",
    )
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (args.src_db,))
        exists = cur.fetchone() is not None
        if not exists:
            cur.execute(f'CREATE DATABASE "{args.src_db}"')
    conn.close()
    if exists:
        log(f"database {args.src_db} exists")
        return
    with open(SCHEMA_SQL) as f:
        sql = f.read()
    conn = psycopg2.connect(
        host=args.pg_host,
        port=args.pg_port,
        user=args.pg_user,
        password=args.pg_password,
        dbname=args.src_db,
    )
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(sql)
    conn.close()
    log(f"created database {args.src_db} from {os.path.relpath(SCHEMA_SQL, ROOT)}")


def ingest(args, om):
    jwt = bot_jwt(om, "ingestion-bot")
    pg_host = args.ingest_pg_host or args.pg_host
    cfg = {
        "source": {
            "type": "postgres",
            "serviceName": args.service,
            "serviceConnection": {
                "config": {
                    "type": "Postgres",
                    "username": args.pg_user,
                    "authType": {"password": args.pg_password},
                    "hostPort": f"{pg_host}:{args.pg_port}",
                    "database": args.src_db,
                    "ingestAllDatabases": False,
                }
            },
            "sourceConfig": {
                "config": {
                    "type": "DatabaseMetadata",
                    "schemaFilterPattern": {"includes": ["^app$"]},
                    "includeViews": True,
                    "includeTags": False,
                    "includeStoredProcedures": False,
                    "includeDDL": False,
                }
            },
        },
        "sink": {"type": "metadata-rest", "config": {}},
        "workflowConfig": {
            "loggerLevel": "WARN",
            "openMetadataServerConfig": {
                "hostPort": args.om_url.rstrip("/") + "/api",
                "authProvider": "openmetadata",
                "securityConfig": {"jwtToken": jwt},
            },
        },
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        path = f.name
    try:
        log(f"metadata ingest (service {args.service}, database {args.src_db})")
        subprocess.run([args.metadata_bin, "ingest", "-c", path], check=True)
    finally:
        os.unlink(path)


def ensure_classification(om, name, desc, tags):
    if om.try_get(f"/api/v1/classifications/name/{name}") is None:
        om.put("/api/v1/classifications", {"name": name, "description": desc})
    for t, d in tags:
        om.put("/api/v1/tags", {"name": t, "classification": name, "description": d})


def ensure_glossary(om):
    om.put(
        "/api/v1/glossaries",
        {"name": "Business", "displayName": "Business", "description": "Business glossary"},
    )
    om.put(
        "/api/v1/glossaryTerms",
        {
            "glossary": "Business",
            "name": "PersonalInformation",
            "displayName": "Personal Information",
            "description": "Information that identifies a natural person.",
        },
    )


def tag_label(fqn, source):
    return {"tagFQN": fqn, "source": source, "labelType": "Manual", "state": "Confirmed"}


def apply_labels(om, args):
    db_fqn = f"{args.service}.{args.src_db}"
    tables = {}
    for (schema, table, _c) in list(COLUMN_LABELS) + list(COLUMN_DESCRIPTIONS):
        tables.setdefault((schema, table), None)
    for key in TABLE_LABELS:
        tables.setdefault(key, None)
    for (schema, table) in sorted(tables):
        fqn = f"{db_fqn}.{schema}.{table}"
        t = om.get(f"/api/v1/tables/name/{fqn}?fields=columns,tags")
        ops = []
        for i, col in enumerate(t["columns"]):
            key = (schema, table, col["name"])
            have = {x["tagFQN"] for x in col.get("tags") or []}
            if not col.get("tags"):
                pending = [l for l in COLUMN_LABELS.get(key, []) if l[0] not in have]
                if pending:
                    ops.append(
                        {
                            "op": "add",
                            "path": f"/columns/{i}/tags",
                            "value": [tag_label(*l) for l in pending],
                        }
                    )
            else:
                for n, l in enumerate(
                    [l for l in COLUMN_LABELS.get(key, []) if l[0] not in have]
                ):
                    ops.append(
                        {
                            "op": "add",
                            "path": f"/columns/{i}/tags/{len(col['tags']) + n}",
                            "value": tag_label(*l),
                        }
                    )
            if key in COLUMN_DESCRIPTIONS and col.get("description") != COLUMN_DESCRIPTIONS[key]:
                ops.append(
                    {
                        "op": "add",
                        "path": f"/columns/{i}/description",
                        "value": COLUMN_DESCRIPTIONS[key],
                    }
                )
        have_t = {x["tagFQN"] for x in t.get("tags") or []}
        pending_t = [l for l in TABLE_LABELS.get((schema, table), []) if l[0] not in have_t]
        if pending_t:
            if not t.get("tags"):
                ops.append(
                    {"op": "add", "path": "/tags", "value": [tag_label(*l) for l in pending_t]}
                )
            else:
                for n, l in enumerate(pending_t):
                    ops.append(
                        {"op": "add", "path": f"/tags/{len(t['tags']) + n}", "value": tag_label(*l)}
                    )
        if ops:
            om.patch(f"/api/v1/tables/{t['id']}", ops)
            log(f"PATCH {fqn}: {len(ops)} op(s)")
        else:
            log(f"{fqn}: already labelled")


def ensure_lake(om, args):
    om.put("/api/v1/databases", {"name": LAKE_DB, "service": args.service})
    om.put(
        "/api/v1/databaseSchemas",
        {"name": LAKE_SCHEMA, "database": f"{args.service}.{LAKE_DB}"},
    )
    body = dict(LAKE_TABLE)
    body["databaseSchema"] = f"{args.service}.{LAKE_DB}.{LAKE_SCHEMA}"
    om.put("/api/v1/tables", body)
    log(f"table {args.service}.{LAKE_DB}.{LAKE_SCHEMA}.{LAKE_TABLE['name']} (API-only)")


def ensure_reader_bot(om, name="haltsql-reader"):
    """A dedicated bot whose user has only the DataConsumer role."""
    existing = om.try_get(f"/api/v1/bots/name/{name}")
    if existing is None:
        role = om.get("/api/v1/roles/name/DataConsumer")
        om.call(
            "POST",
            "/api/v1/users",
            {
                "name": name,
                "email": f"{name}@open-metadata.org",
                "isBot": True,
                "roles": [role["id"]],
                "botName": name,
                "authenticationMechanism": {
                    "authType": "JWT",
                    "config": {"JWTTokenExpiry": "Unlimited"},
                },
            },
        )
        om.put(
            "/api/v1/bots",
            {"name": name, "botUser": name, "description": "HaltSQL read-only catalog fetch"},
        )
        log(f"created bot {name} (DataConsumer)")
    return bot_jwt(om, name)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--om-url", default="http://127.0.0.1:8595")
    p.add_argument("--pg-host", default="127.0.0.1")
    p.add_argument("--ingest-pg-host", default=None)
    p.add_argument("--pg-port", type=int, default=5417)
    p.add_argument("--pg-user", default="postgres")
    p.add_argument("--pg-password", default=os.environ.get("PGPASSWORD", "haltlab"))
    p.add_argument("--src-db", required=True)
    p.add_argument("--service", default="haltsql_lab_pg")
    p.add_argument("--metadata-bin", default="metadata")
    p.add_argument("--token-out", required=True)
    p.add_argument("--skip-ingest", action="store_true")
    args = p.parse_args()

    om = Om(args.om_url)
    wait_ready(om)
    login_admin(om)
    create_source_db(args)
    if not args.skip_ingest:
        ingest(args, om)
    ensure_classification(
        om,
        "DataDomain",
        "Business domain of a data asset (not a sensitivity label).",
        [("Finance", "Finance domain"), ("Sales", "Sales domain")],
    )
    ensure_glossary(om)
    apply_labels(om, args)
    ensure_lake(om, args)
    token = ensure_reader_bot(om)
    fd = os.open(args.token_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token)
    log(f"reader bot JWT written to {args.token_out}")
    json.dump(EXPECTED, sys.stdout, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    main()
