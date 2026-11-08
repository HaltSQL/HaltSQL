"""Scenario: identity from a real IdP (Keycloak) selects the policy and the tenant.

A dedicated Keycloak realm (created through the admin API, deleted after the
test) issues real tokens: a group-membership mapper puts the user's groups in
`groups`, and a user-attribute mapper puts the user's tenant in the nested
claim `haltsql.tenant`. haltsql-server discovers the realm, fetches its JWKS,
and maps

* group `support` -> policy `support-bot` (app.tickets only),
* group `finance` -> policy `finance-analyst` (app.invoices only),
* any other group -> 401 (no default),

with `context_claims: {tenant_id: haltsql.tenant}`, so the tenant comes only
from the signed token. Allowed queries are run in real Postgres with the
verdict's bind_params, so the rows each caller can see are checked on the
database itself.

Ports: 17060.
"""

from __future__ import annotations

from pathlib import Path

import requests

from conftest import (
    KEYCLOAK_URL,
    Keycloak,
    KeycloakAdmin,
    Postgres,
    Processes,
    new_token,
    pg_exec_exact,
    read_jsonl,
    reason_codes,
    sha256_hex,
    unique_name,
)

SERVER_PORT = 17060
CLIENT_ID = "haltsql-agent"

SUPPORT_POLICY = """apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: support-bot }
search_path: [app]
statements: { allow: [select] }
require_limit: { max: 100 }
tenancy: { mode: bound, keys: { tenant: "${ctx.tenant_id}" } }
tables:
  app.tickets: { columns: [id, tenant_id, subject, status], tenant_column: tenant_id }
mode: enforce
"""

FINANCE_POLICY = """apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: finance-analyst }
search_path: [app]
statements: { allow: [select] }
require_limit: { max: 100 }
tenancy: { mode: bound, keys: { tenant: "${ctx.tenant_id}" } }
tables:
  app.invoices: { columns: [id, tenant_id, amount_cents], tenant_column: tenant_id }
mode: enforce
"""

TICKETS_SQL = "SELECT id, subject FROM app.tickets WHERE tenant_id = $1 ORDER BY id LIMIT 10"
INVOICES_SQL = "SELECT id, amount_cents FROM app.invoices WHERE tenant_id = $1 ORDER BY id LIMIT 10"


def seed(pg: Postgres, db: str) -> None:
    with pg.connect(db) as c:
        c.execute("CREATE SCHEMA app")
        c.execute("CREATE TABLE app.tickets (id int PRIMARY KEY, tenant_id text NOT NULL,"
                  " subject text, status text)")
        c.execute("CREATE TABLE app.invoices (id int PRIMARY KEY, tenant_id text NOT NULL,"
                  " amount_cents int)")
        c.execute("INSERT INTO app.tickets VALUES (1,'acme','printer','open'),"
                  " (2,'acme','vpn','closed'), (3,'globex','login','open')")
        c.execute("INSERT INTO app.invoices VALUES (10,'acme',500), (11,'globex',700),"
                  " (12,'globex',900)")


def setup_realm(kc: KeycloakAdmin, realm: str, secret: str, password: str) -> None:
    kc.create_realm(realm)
    for g in ("support", "finance", "contractors"):
        kc.create_group(realm, g)
    kc.create_client(realm, CLIENT_ID, secret, [
        {"name": "audience-haltsql", "protocol": "openid-connect",
         "protocolMapper": "oidc-audience-mapper",
         "config": {"included.custom.audience": "haltsql", "access.token.claim": "true",
                    "id.token.claim": "false"}},
        {"name": "groups", "protocol": "openid-connect",
         "protocolMapper": "oidc-group-membership-mapper",
         "config": {"claim.name": "groups", "full.path": "false",
                    "access.token.claim": "true", "id.token.claim": "false"}},
        {"name": "tenant", "protocol": "openid-connect",
         "protocolMapper": "oidc-usermodel-attribute-mapper",
         "config": {"user.attribute": "tenant", "claim.name": "haltsql.tenant",
                    "jsonType.label": "String", "access.token.claim": "true",
                    "id.token.claim": "false"}},
    ])
    kc.create_user(realm, "alice", password, groups=["support"], attributes={"tenant": ["acme"]})
    kc.create_user(realm, "erin", password, groups=["support"], attributes={"tenant": ["globex"]})
    kc.create_user(realm, "carol", password, groups=["finance"], attributes={"tenant": ["globex"]})
    kc.create_user(realm, "dave", password, groups=["contractors"], attributes={"tenant": ["acme"]})
    kc.create_user(realm, "frank", password, groups=["support"])  # no tenant attribute
    # in no group: Keycloak leaves the groups claim out
    kc.create_user(realm, "gina", password, attributes={"tenant": ["acme"]})


def server_config(*, issuer: str, ops_token: str, audit: Path, work: Path) -> str:
    (work / "support.yaml").write_text(SUPPORT_POLICY)
    (work / "finance.yaml").write_text(FINANCE_POLICY)
    return f"""apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:{SERVER_PORT}
  auth:
    tokens:
      - {{ name: ops, token_sha256: {sha256_hex(ops_token)}, policy: support-bot }}
    oidc:
      - name: keycloak
        issuer: {issuer}
        audiences: [haltsql]
        allow_insecure_http: true
        algorithms: [RS256]
        policy_from_groups:
          claim: groups
          map:
            - {{ group: support, policy: support-bot }}
            - {{ group: finance, policy: finance-analyst }}
        context_claims: {{ tenant_id: haltsql.tenant }}
  admin: {{ enabled: true, callers: [token:ops] }}
policies:
  - path: {work / "support.yaml"}
  - path: {work / "finance.yaml"}
audit:
  sinks:
    - {{ type: file, path: {audit} }}
"""


def post_verify(server, token: str, body: dict) -> requests.Response:
    return requests.post(server.base + "/v1/verify", json=body,
                         headers={"Authorization": f"Bearer {token}"}, timeout=10)


def test_identity_groups_select_policy_and_tenant(
        keycloak: Keycloak, keycloak_admin: KeycloakAdmin, postgres: Postgres,
        pg_database: str, processes: Processes, tmp_path: Path) -> None:
    realm = unique_name("identity-opa-shadow")
    secret = new_token()
    password = new_token()
    issuer = f"{KEYCLOAK_URL}/realms/{realm}"
    seed(postgres, pg_database)
    try:
        setup_realm(keycloak_admin, realm, secret, password)

        def token(user: str) -> str:
            return keycloak_admin.password_token(realm, CLIENT_ID, secret, user, password)

        tokens = {u: token(u) for u in ("alice", "erin", "carol", "dave", "frank", "gina")}

        # ---- what Keycloak put in the tokens ----
        claims = {u: Keycloak.claims(t) for u, t in tokens.items()}
        for u, c in claims.items():
            assert c["iss"] == issuer, (u, c["iss"])
            assert "haltsql" in (c["aud"] if isinstance(c["aud"], list) else [c["aud"]])
        assert claims["alice"]["groups"] == ["support"]
        assert claims["alice"]["haltsql"] == {"tenant": "acme"}
        assert claims["erin"]["groups"] == ["support"]
        assert claims["erin"]["haltsql"] == {"tenant": "globex"}
        assert claims["carol"]["groups"] == ["finance"]
        assert claims["carol"]["haltsql"] == {"tenant": "globex"}
        assert claims["dave"]["groups"] == ["contractors"]
        assert claims["frank"]["groups"] == ["support"]
        assert "haltsql" not in claims["frank"]
        assert "groups" not in claims["gina"]

        ops = new_token()
        audit = tmp_path / "audit.jsonl"
        work = tmp_path / "cfg"
        work.mkdir()
        server = processes.server(
            server_config(issuer=issuer, ops_token=ops, audit=audit, work=work), SERVER_PORT)
        db = postgres.connect(pg_database)

        # ---- group support -> support-bot; the tenant comes from the token ----
        v = server.verify(TICKETS_SQL, tokens["alice"])
        assert v["allowed"] is True, v
        assert v["policy"]["name"] == "support-bot"
        assert v["bind_params"] == [{"param": 1, "value": "acme"}]
        assert pg_exec_exact(db, TICKETS_SQL, v["bind_params"]) == [("1", "printer"), ("2", "vpn")]

        v = server.verify(TICKETS_SQL, tokens["erin"])
        assert v["allowed"] is True and v["policy"]["name"] == "support-bot", v
        assert v["bind_params"] == [{"param": 1, "value": "globex"}]
        assert pg_exec_exact(db, TICKETS_SQL, v["bind_params"]) == [("3", "login")]

        # support-bot has no invoices; the caller cannot pick another policy.
        v = server.verify(INVOICES_SQL, tokens["alice"])
        assert v["allowed"] is False and reason_codes(v)[0] == "E_TABLE_DENIED", v
        r = post_verify(server, tokens["alice"],
                        {"sql": INVOICES_SQL, "context": {}, "policy": "finance-analyst"})
        assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN", r.text

        # ---- group finance -> finance-analyst ----
        v = server.verify(INVOICES_SQL, tokens["carol"])
        assert v["allowed"] is True and v["policy"]["name"] == "finance-analyst", v
        assert v["bind_params"] == [{"param": 1, "value": "globex"}]
        assert pg_exec_exact(db, INVOICES_SQL, v["bind_params"]) == [("11", "700"), ("12", "900")]
        v = server.verify(TICKETS_SQL, tokens["carol"])
        assert v["allowed"] is False and reason_codes(v)[0] == "E_TABLE_DENIED", v
        assert v["policy"]["name"] == "finance-analyst"

        # ---- an unknown group, no groups claim, no tenant claim: 401 ----
        for user in ("dave", "gina", "frank"):
            r = post_verify(server, tokens[user], {"sql": TICKETS_SQL, "context": {}})
            assert r.status_code == 401, (user, r.status_code, r.text)
            assert r.json()["error"]["code"] == "UNAUTHORIZED", r.text
            assert tokens[user] not in r.text
        log = server.log()
        assert "no_group_policy" in log, log  # dave
        assert log.count("missing_claim") >= 2, log  # gina (groups), frank (tenant)
        assert "contractors" not in log, "the rejection must not echo the token's groups"
        for t in tokens.values():
            assert t not in log, "a token was logged"

        # ---- a query for another tenant is denied ----
        other = "SELECT id, subject FROM app.tickets WHERE tenant_id = 'globex' LIMIT 10"
        v = server.verify(other, tokens["alice"])
        assert v["allowed"] is False and "E_TENANT_MISMATCH" in reason_codes(v), v
        assert v["bind_params"] == []
        v = server.verify("SELECT id, subject FROM app.tickets LIMIT 10", tokens["alice"])
        assert v["allowed"] is False and reason_codes(v) == ["E_TENANT_MISSING"], v
        # The body cannot override the token's tenant ...
        r = post_verify(server, tokens["alice"],
                        {"sql": TICKETS_SQL, "context": {"tenant_id": "globex"}})
        assert r.status_code == 403 and r.json()["error"]["code"] == "CONTEXT_NOT_ALLOWED", r.text
        # ... repeating the same value is accepted and changes nothing.
        r = post_verify(server, tokens["alice"],
                        {"sql": TICKETS_SQL, "context": {"tenant_id": "acme"}})
        assert r.status_code == 200, r.text
        assert r.json()["bind_params"] == [{"param": 1, "value": "acme"}]
        # The escape attempt really would have leaked: globex has rows.
        with postgres.connect(pg_database) as c2:
            assert c2.execute("SELECT count(*) FROM app.tickets WHERE tenant_id = 'globex'"
                              ).fetchone()[0] == 1
        db.close()

        # ---- metrics and audit: what the server recorded ----
        metrics = server.get("/metrics").text
        rejected = [line for line in metrics.splitlines()
                    if line.startswith("haltsql_auth_total{") and 'method="oidc"' in line
                    and 'result="rejected"' in line]
        assert rejected and float(rejected[0].rsplit(" ", 1)[1]) == 3, metrics
        records = read_jsonl(audit)
        # One record per answered verify (200): 2 + 1 + 1 + 1 + 2 + 1 (same-value context).
        assert len(records) == 8, records
        subs = {claims[u]["sub"]: u for u in claims}
        for rec in records:
            assert rec["caller_type"] == "oidc", rec
            assert rec["caller"] == "oidc:keycloak", rec
            assert rec["subject"] in subs, rec
            assert "sql" not in rec, "raw SQL is not logged without audit.log_raw_sql"
        by_user = [(subs[r["subject"]], r["policy"], r["allowed"]) for r in records]
        assert by_user == [
            ("alice", "support-bot", True),
            ("erin", "support-bot", True),
            ("alice", "support-bot", False),
            ("carol", "finance-analyst", True),
            ("carol", "finance-analyst", False),
            ("alice", "support-bot", False),
            ("alice", "support-bot", False),
            ("alice", "support-bot", True),
        ], by_user
        assert records[0]["sql_sha256"] == sha256_hex(TICKETS_SQL)
        assert "E_TENANT_MISMATCH" in records[5]["codes"]
        assert records[6]["codes"] == ["E_TENANT_MISSING"]
        raw = audit.read_text()
        # The admin report (ops static token) groups the same verdicts by policy.
        r = server.get("/v1/admin/report", ops)
        assert r.status_code == 200, r.text
        summary = r.json()["summary"]
        assert summary["totals"]["total"] == 8
        by_policy = {p["policy"]: p["total"] for p in summary["by_policy"]}
        assert by_policy == {"support-bot": 6, "finance-analyst": 2}, summary["by_policy"]
        assert [c["caller"] for c in summary["by_caller"]] == ["oidc:keycloak"]
        # An OIDC token is not an admin caller here.
        assert server.get("/v1/admin/report", tokens["alice"]).status_code == 403
        for t in tokens.values():
            assert t not in raw
    finally:
        keycloak_admin.delete_realm(realm)
