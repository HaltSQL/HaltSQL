#!/usr/bin/env python3
"""Seed a live DataHub instance the way a governance team would.

1. Creates a source database (from lab/schemas/saas_shared.sql) and a small decoy
   database in the lab Postgres.
2. Logs in to the DataHub frontend as the default `datahub` user and creates a Personal
   Access Token, written to --token-out: that is the credential `haltsql schema fetch`
   and the ingestion use (metadata service authentication is on).
3. Creates tags (PII, Sensitive, Gold) and glossary terms (PersonalInformation, Revenue,
   with opaque UUID ids as the UI creates them, so names must be resolved).
4. Ingests both databases with DataHub's real Postgres source (`datahub ingest`, from
   the acryl-datahub package matching the server), with transformers that put tags and
   a glossary term into the ingested schemaMetadata aspect.
5. Labels columns through GraphQL (addTag / addTerm / updateDescription on schemaField
   sub-resources), which land in editableSchemaMetadata, plus labels that must NOT count
   as PII (Gold tag, a non-PII term, a column description, a dataset-level tag).

Prints the expected PII manifest entries (schema.table.column -> labels) as JSON on
stdout, so run.sh can compare them with what HaltSQL fetches.

Every step is idempotent: re-running against the same instance converges.

Usage (see run.sh):
  python seed.py --gms-url http://127.0.0.1:8596 --frontend-url http://127.0.0.1:9596 \
      --pg-host 127.0.0.1 --pg-port 5417 --src-db dh_src_1234 --decoy-db dh_decoy_1234 \
      --platform-instance haltsql_lab --token-out /tmp/tok --datahub-bin venv/bin/datahub
"""

import argparse
import http.cookiejar
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

TAGS = {
    "PII": "Personally identifiable information",
    "Sensitive": "Restricted data: secrets, credentials, government ids",
    "Gold": "Certified, production-quality data set",  # decoy: not a PII label
}
# Opaque ids, as terms created in the DataHub UI get: the urn carries no name, so the
# importer has to read the term's name from the fetched document.
TERM_IDS = {
    "PersonalInformation": "3f9b2c4e-8a71-4d2b-9c55-0e6a1d7b2f10",
    "Revenue": "b7e4d1a0-2c3f-4e5d-8f90-1a2b3c4d5e6f",  # decoy: not a PII term
}
TERM_DESCRIPTIONS = {
    "PersonalInformation": "Information that identifies a natural person",
    "Revenue": "Money recognised from sales",
}

# Ingestion transformers (schemaMetadata aspect): field-path regex -> labels.
INGEST_TAGS = {
    "^card_token$": ["urn:li:tag:Sensitive"],
    "^card_last4$": ["urn:li:tag:PII"],
    "^description$": ["urn:li:tag:Gold"],  # order_items.description: decoy
}
INGEST_TERMS = {"^ip$": ["PersonalInformation"]}

# GraphQL labels (editableSchemaMetadata aspect): (table, column) -> labels.
EDIT_TAGS = {
    ("customers", "email"): ["PII"],
    ("customers", "phone"): ["PII"],
    ("customers", "ssn"): ["PII", "Sensitive"],
    ("users", "email"): ["PII"],
    ("users", "password_hash"): ["Sensitive"],
    ("payments", "card_token"): ["PII"],  # also Sensitive from ingestion: both count
    ("orders", "note"): ["Gold"],  # decoy
}
EDIT_TERMS = {
    ("users", "full_name"): ["PersonalInformation"],  # its only label
    ("invoices", "amount_cents"): ["Revenue"],  # decoy
}
EDIT_DESCRIPTIONS = {  # decoy: descriptions are not labels
    ("orgs", "name"): "Legal name; may contain the owner's personal email address."
}
DATASET_TAGS = {"customers": ["Gold"]}  # decoy: a dataset-level tag flags no column

EXPECTED = {
    "app.customers.email": ["PII"],
    "app.customers.phone": ["PII"],
    "app.customers.ssn": ["PII", "Sensitive"],
    "app.users.email": ["PII"],
    "app.users.password_hash": ["Sensitive"],
    "app.users.full_name": ["PersonalInformation"],
    "app.payments.card_token": ["PII", "Sensitive"],
    "app.payments.card_last4": ["PII"],
    "app.audit_events.ip": ["PersonalInformation"],
}

# Decoy database: same platform instance, same schema name, a tagged email column. A
# --database filter must exclude it.
DECOY_SQL = """
CREATE SCHEMA IF NOT EXISTS app;
CREATE TABLE IF NOT EXISTS app.leads (id bigint PRIMARY KEY, email text, source text);
"""
DECOY_TAGS = {("leads", "email"): ["PII"]}


def log(msg):
    print(f"[seed] {msg}", file=sys.stderr, flush=True)


def dataset_urn(instance, db, table):
    name = ".".join(x for x in (instance, db, "app", table) if x)
    return f"urn:li:dataset:(urn:li:dataPlatform:postgres,{name},PROD)"


# ------------------------------------------------------------------ Postgres


def create_databases(a):
    import psycopg2

    c = psycopg2.connect(host=a.pg_host, port=a.pg_port, user=a.pg_user,
                         password=os.environ["PGPASSWORD"], dbname="postgres")
    c.autocommit = True
    cur = c.cursor()
    for db, sql in ((a.src_db, open(SCHEMA_SQL).read()), (a.decoy_db, DECOY_SQL)):
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (db,))
        if cur.fetchone():
            log(f"database {db} exists")
            continue
        cur.execute(f'CREATE DATABASE "{db}"')
        d = psycopg2.connect(host=a.pg_host, port=a.pg_port, user=a.pg_user,
                             password=os.environ["PGPASSWORD"], dbname=db)
        d.autocommit = True
        d.cursor().execute(sql)
        d.close()
        log(f"created database {db}")
    c.close()


# ------------------------------------------------------------------ DataHub HTTP


class DataHub:
    def __init__(self, gms, frontend):
        self.gms = gms.rstrip("/")
        self.frontend = frontend.rstrip("/")
        self.token = None
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _post(self, url, body, headers):
        req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **headers})
        with self.opener.open(req, timeout=120) as r:
            raw = r.read()
            return json.loads(raw) if raw else None

    def login(self, user, password):
        self._post(f"{self.frontend}/logIn", {"username": user, "password": password}, {})

    def gql(self, query, variables=None, via_frontend=False):
        if via_frontend:
            url, headers = f"{self.frontend}/api/v2/graphql", {}
        else:
            url, headers = f"{self.gms}/api/graphql", {"Authorization": f"Bearer {self.token}"}
        r = self._post(url, {"query": query, "variables": variables or {}}, headers)
        if r.get("errors"):
            raise RuntimeError(json.dumps(r["errors"])[:2000])
        return r["data"]


def wait_ready(dh):
    for _ in range(120):
        try:
            with urllib.request.urlopen(f"{dh.gms}/health", timeout=5) as r:
                if r.status == 200:
                    return
        except Exception:
            pass
        time.sleep(5)
    raise SystemExit("GMS not healthy")


def create_token(dh, a):
    for _ in range(60):
        try:
            dh.login(a.user, a.password)
            break
        except Exception as e:  # frontend still starting
            last = e
            time.sleep(5)
    else:
        raise SystemExit(f"login failed: {last}")
    data = dh.gql(
        """mutation($input: CreateAccessTokenInput!) {
             createAccessToken(input: $input) { accessToken metadata { id } } }""",
        {"input": {"type": "PERSONAL", "actorUrn": f"urn:li:corpuser:{a.user}",
                   "duration": "ONE_MONTH", "name": "haltsql-live-validation",
                   "description": "haltsql schema fetch --from datahub"}},
        via_frontend=True)
    dh.token = data["createAccessToken"]["accessToken"]
    fd = os.open(a.token_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(dh.token)
    log(f"personal access token written to {a.token_out}")


def ignore_exists(fn):
    try:
        fn()
    except RuntimeError as e:
        if "already exists" not in str(e).lower():
            raise


def create_labels(dh):
    for tid, desc in TAGS.items():
        ignore_exists(lambda: dh.gql(
            "mutation($i: CreateTagInput!) { createTag(input: $i) }",
            {"i": {"id": tid, "name": tid, "description": desc}}))
    for name, tid in TERM_IDS.items():
        ignore_exists(lambda: dh.gql(
            "mutation($i: CreateGlossaryEntityInput!) { createGlossaryTerm(input: $i) }",
            {"i": {"id": tid, "name": name, "description": TERM_DESCRIPTIONS[name]}}))
    log(f"tags {sorted(TAGS)}, glossary terms {sorted(TERM_IDS)}")


def term_urn(name):
    return f"urn:li:glossaryTerm:{TERM_IDS[name]}"


# ------------------------------------------------------------------ ingestion


def ingest(dh, a, db, transform):
    recipe = {
        "source": {
            "type": "postgres",
            "config": {
                "host_port": f"{a.pg_host}:{a.pg_port}",
                "database": db,
                "username": a.pg_user,
                "password": os.environ["PGPASSWORD"],
                "platform_instance": a.platform_instance,
                "schema_pattern": {"allow": ["^app$"]},
                "include_views": False,
                "profiling": {"enabled": False},
            },
        },
        "sink": {"type": "datahub-rest", "config": {"server": dh.gms, "token": dh.token}},
    }
    if transform:
        recipe["transformers"] = [
            {"type": "pattern_add_dataset_schema_tags",
             "config": {"tag_pattern": {"rules": INGEST_TAGS}}},
            {"type": "pattern_add_dataset_schema_terms",
             "config": {"term_pattern": {"rules": {
                 k: [term_urn(t) for t in v] for k, v in INGEST_TERMS.items()}}}},
        ]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(recipe, f)
        path = f.name
    try:
        os.chmod(path, 0o600)
        log(f"ingesting {db} (datahub ingest, postgres source)")
        r = subprocess.run([a.datahub_bin, "ingest", "-c", path, "--strict-warnings"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stdout[-6000:])
            raise SystemExit(f"ingestion of {db} failed")
    finally:
        os.unlink(path)


# ------------------------------------------------------------------ GraphQL labels


def field_mutation(dh, kind, urn, field, label):
    if kind == "tag":
        q = "mutation($i: TagAssociationInput!) { addTag(input: $i) }"
        i = {"tagUrn": f"urn:li:tag:{label}"}
    else:
        q = "mutation($i: TermAssociationInput!) { addTerm(input: $i) }"
        i = {"termUrn": term_urn(label)}
    i.update({"resourceUrn": urn, "subResourceType": "DATASET_FIELD", "subResource": field})
    dh.gql(q, {"i": i})


def label_columns(dh, a):
    inst, src = a.platform_instance, a.src_db
    for (t, col), tags in EDIT_TAGS.items():
        for tag in tags:
            field_mutation(dh, "tag", dataset_urn(inst, src, t), col, tag)
    for (t, col), terms in EDIT_TERMS.items():
        for term in terms:
            field_mutation(dh, "term", dataset_urn(inst, src, t), col, term)
    for (t, col), desc in EDIT_DESCRIPTIONS.items():
        dh.gql("mutation($i: DescriptionUpdateInput!) { updateDescription(input: $i) }",
               {"i": {"description": desc, "resourceUrn": dataset_urn(inst, src, t),
                      "subResourceType": "DATASET_FIELD", "subResource": col}})
    for t, tags in DATASET_TAGS.items():
        for tag in tags:
            dh.gql("mutation($i: TagAssociationInput!) { addTag(input: $i) }",
                   {"i": {"tagUrn": f"urn:li:tag:{tag}",
                          "resourceUrn": dataset_urn(inst, src, t)}})
    for (t, col), tags in DECOY_TAGS.items():
        for tag in tags:
            field_mutation(dh, "tag", dataset_urn(inst, a.decoy_db, t), col, tag)
    log("column labels applied through GraphQL")


def wait_indexed(dh, a):
    """Search is eventually consistent: wait until both databases' datasets are listed."""
    q = """query($i: ScrollAcrossEntitiesInput!) {
             scrollAcrossEntities(input: $i) { searchResults { entity { urn } } } }"""
    want = {dataset_urn(a.platform_instance, a.src_db, t) for t in (
        "audit_events", "currencies", "customers", "invoices", "order_items",
        "orders", "orgs", "payments", "users")}
    want.add(dataset_urn(a.platform_instance, a.decoy_db, "leads"))
    for _ in range(60):
        d = dh.gql(q, {"i": {"types": ["DATASET"], "query": "*", "count": 100,
                             "orFilters": [{"and": [{"field": "platform", "values": [
                                 "urn:li:dataPlatform:postgres"]}]}]}})
        got = {r["entity"]["urn"] for r in d["scrollAcrossEntities"]["searchResults"]}
        if want <= got:
            return
        time.sleep(3)
    raise SystemExit(f"datasets not indexed: {sorted(want - got)}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--gms-url", required=True)
    p.add_argument("--frontend-url", required=True)
    p.add_argument("--pg-host", default="127.0.0.1")
    p.add_argument("--pg-port", type=int, default=5417)
    p.add_argument("--pg-user", default="postgres")
    p.add_argument("--src-db", required=True)
    p.add_argument("--decoy-db", required=True)
    p.add_argument("--platform-instance", default="haltsql_lab")
    p.add_argument("--user", default="datahub")
    p.add_argument("--password", default="datahub")
    p.add_argument("--datahub-bin", required=True)
    p.add_argument("--token-out", required=True)
    a = p.parse_args()

    create_databases(a)
    dh = DataHub(a.gms_url, a.frontend_url)
    wait_ready(dh)
    create_token(dh, a)
    create_labels(dh)
    ingest(dh, a, a.src_db, transform=True)
    ingest(dh, a, a.decoy_db, transform=False)
    label_columns(dh, a)
    wait_indexed(dh, a)
    json.dump(EXPECTED, sys.stdout, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    main()
