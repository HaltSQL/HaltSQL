"""End-to-end check of haltsql-console against real verifiers and every integration.

    make -C lab up                     # the lab Postgres on 127.0.0.1:5417
    dune build ./bin/server/main.exe ./bin/proxy/main.exe ./bin/console/main.exe ./bin/haltsql/main.exe
    clients/python/.venv/bin/python lab/console/run_e2e.py [--suite-audit DIR]

What it does, all on loopback:
  1. creates a scratch database with the saas schema (same SETUP as the integration tests);
  2. starts haltsql-server (one static token per agent, admin API on, hash-chained audit
     file with raw SQL, Prometheus metrics) and haltsql-proxy in front of the database;
  3. sends traffic through every framework adapter (each in its own virtualenv), the Python
     SDK, the MCP tools and the proxy (psycopg), including a burst of cross-tenant probes;
  4. starts haltsql-console reading the server's and the proxy's audit files (plus, with
     --suite-audit, the per-suite audit files written by lab/console/server-wrapper.sh
     while the integration test suites ran) and polling the server's admin API;
  5. checks every console endpoint: records per caller, decision trails, chain of custody
     (and the same files with `haltsql audit verify`), overview, signals (cross-tenant must
     fire), cases, agents, fleet, policies, shadow report, playground, data, evidence
     packs, activity and permissions.

Virtualenvs: integrations/<name>/.venv, else $E2E_VENV_DIR/venv-<name>. A missing
virtualenv is a failure unless the adapter is listed in E2E_SKIP (comma-separated).
"""

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BUILD = os.path.join(ROOT, "_build", "default", "bin")
SERVER = os.environ.get("HALTSQL_SERVER_BIN", os.path.join(BUILD, "server", "main.exe"))
PROXY = os.environ.get("HALTSQL_PROXY_BIN", os.path.join(BUILD, "proxy", "main.exe"))
CONSOLE = os.environ.get("HALTSQL_CONSOLE_BIN", os.path.join(BUILD, "console", "main.exe"))
CLI = os.environ.get("HALTSQL_CLI_BIN", os.path.join(BUILD, "haltsql", "main.exe"))
POLICY = os.path.join(ROOT, "test", "fixtures", "policies", "saas.yaml")
SRC_ROOT = os.environ.get("E2E_SOURCE_ROOT", ROOT)  # where integrations/ and their venvs live

ADAPTERS = ["sdk", "langchain", "llamaindex", "vanna", "crewai", "langgraph", "openai_agents", "google_adk",
            "semantic_kernel", "mcp"]
FAILURES = []


def check(cond, msg):
    print(("  ok    " if cond else "  FAIL  ") + msg)
    if not cond:
        FAILURES.append(msg)
    return cond


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http(url, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.1)
    raise SystemExit(f"{url} did not become ready")


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def venv_python(name):
    pkg = "clients/mcp" if name == "mcp" else ("clients/python" if name == "sdk" else f"integrations/{name}")
    for d in (os.path.join(SRC_ROOT, pkg, ".venv"), os.path.join(os.environ.get("E2E_VENV_DIR", "/nonexistent"), f"venv-{name}")):
        py = os.path.join(d, "bin", "python")
        if os.path.exists(py):
            return py
    return None


class Console:
    def __init__(self, url):
        self.url = url

    def call(self, method, path, token, body=None, reason=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("authorization", "Bearer " + token)
        if data is not None:
            req.add_header("content-type", "application/json")
        if reason:
            req.add_header("x-haltsql-reason", reason)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                ctype = r.headers.get("content-type", "")
                return r.status, (json.loads(raw) if "json" in ctype else raw)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw

    def get(self, path, token, **kw):
        return self.call("GET", path, token, **kw)

    def post(self, path, token, body=None, **kw):
        return self.call("POST", path, token, body if body is not None else {}, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite-audit", help="directory of per-suite audit files from server-wrapper.sh")
    ap.add_argument("--keep", action="store_true", help="keep processes running at the end (Ctrl-C to stop)")
    args = ap.parse_args()
    skip = set(filter(None, os.environ.get("E2E_SKIP", "").split(",")))

    for b in (SERVER, PROXY, CONSOLE, CLI):
        if not os.path.exists(b):
            raise SystemExit(f"missing binary {b}: build it first")

    # The saas schema exactly as the integration tests create it.
    spec = importlib.util.spec_from_file_location("crewai_conftest", os.path.join(SRC_ROOT, "integrations", "crewai", "tests", "conftest.py"))
    conftest = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(conftest)
    from haltsql.testing import temporary_database

    work = tempfile.mkdtemp(prefix="haltsql-console-e2e-")
    procs = []
    print(f"work dir {work}")
    try:
        with temporary_database("haltsql_console_e2e", conftest.SETUP) as dsn:
            if dsn is None:
                raise SystemExit("the lab Postgres on 127.0.0.1:5417 is not available (make -C lab up)")
            run(args, skip, work, procs, dsn)
    finally:
        if args.keep and not FAILURES:
            print("processes kept running; Ctrl-C to stop")
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                pass
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed:")
        for f in FAILURES:
            print("  - " + f)
        sys.exit(1)
    print("all checks passed")
    shutil.rmtree(work, ignore_errors=True)


def run(args, skip, work, procs, dsn):
    dsn_parts = dict(p.split("=", 1) for p in dsn.split() if "=" in p)
    tokens = {a: "tok-" + a + "-" + os.urandom(6).hex() for a in ADAPTERS}
    admin_token = "tok-console-admin-" + os.urandom(6).hex()

    # ---- haltsql-server ----
    sport = free_port()
    server_audit = os.path.join(work, "haltsql-1.jsonl")
    server_cfg = {
        "apiVersion": "haltsql.dev/v1",
        "kind": "Config",
        "server": {
            "listen": f"127.0.0.1:{sport}",
            "auth": {
                "allow_unauthenticated": False,
                "tokens": [{"name": f"{a}-agent", "token_sha256": sha(t), "policy": "saas"} for a, t in tokens.items()]
                + [{"name": "console", "token_sha256": sha(admin_token), "policy": "saas"}],
            },
            "admin": {"enabled": True, "callers": ["token:console"]},
        },
        "policies": [{"path": POLICY}],
        "audit": {"sinks": [{"type": "file", "path": server_audit}], "log_raw_sql": True},
        "telemetry": {"metrics": {"prometheus": True}},
        "logging": {"level": "error"},
    }
    server_cfg_path = os.path.join(work, "server.json")
    json.dump(server_cfg, open(server_cfg_path, "w"))
    procs.append(subprocess.Popen([SERVER, "--config", server_cfg_path], stdout=subprocess.DEVNULL))
    server_url = f"http://127.0.0.1:{sport}"
    wait_http(server_url + "/readyz")
    print(f"haltsql-server on {server_url}")

    # ---- haltsql-proxy in front of the scratch database ----
    pport = free_port()
    proxy_audit = os.path.join(work, "proxy-orders.jsonl")
    proxy_password = "pw-" + os.urandom(6).hex()
    verifier = subprocess.run([PROXY, "scram-verifier"], input=proxy_password + "\n", capture_output=True, text=True, check=True).stdout.strip()
    proxy_cfg = {
        "apiVersion": "haltsql.dev/v1",
        "kind": "ProxyConfig",
        "listen": f"127.0.0.1:{pport}",
        "tls": None,
        "upstream": {"host": dsn_parts.get("host", "127.0.0.1"), "port": int(dsn_parts.get("port", 5417)),
                     "database": dsn_parts["dbname"], "user": dsn_parts.get("user", "postgres")}
        | ({"password": dsn_parts["password"]} if dsn_parts.get("password") else {}),
        "policies": [{"path": POLICY}],
        "auth": {"method": "scram", "users": [{"name": "orders-proxy-agent", "scram_verifier": verifier, "policy": "saas", "context": {"tenant_id": "acme"}}]},
        "audit": {"sinks": [{"type": "file", "path": proxy_audit}], "log_raw_sql": True},
        "logging": {"level": "error"},
    }
    proxy_cfg.pop("tls")
    proxy_cfg_path = os.path.join(work, "proxy.json")
    json.dump(proxy_cfg, open(proxy_cfg_path, "w"))
    procs.append(subprocess.Popen([PROXY, "run", "--config", proxy_cfg_path], stdout=subprocess.DEVNULL))
    time.sleep(1.0)

    # ---- traffic through every adapter ----
    print("\ntraffic")
    driver = os.path.join(os.path.dirname(__file__), "drive_adapter.py")
    mcp_driver = os.path.join(os.path.dirname(__file__), "drive_mcp.py")
    for a in ADAPTERS:
        py = venv_python(a)
        if py is None:
            check(a in skip, f"{a}: virtualenv found" + (" (skipped by E2E_SKIP)" if a in skip else ""))
            continue
        cmd = [py, mcp_driver, server_url, tokens[a], dsn] if a == "mcp" else [py, driver, a, server_url, tokens[a], dsn]
        if a == "sdk":
            cmd += ["--cross-tenant", "37"]  # the support-bot style burst
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        out = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else p.stderr[-400:]
        check(p.returncode == 0, f"{a}: {out}")

    # Proxy: allowed and denied statements over the wire protocol.
    import psycopg

    try:
        with psycopg.connect(host="127.0.0.1", port=pport, dbname=dsn_parts["dbname"], user="orders-proxy-agent",
                             password=proxy_password, sslmode="disable", connect_timeout=5, autocommit=True) as c:
            # Bound tenancy: the tenant is a bind parameter the proxy checks against the context.
            for _ in range(3):
                c.execute("SELECT o.id FROM app.orders o WHERE o.tenant_id = %s LIMIT 5", ("acme",)).fetchall()
            try:
                c.execute("SELECT c.email FROM app.customers c WHERE c.tenant_id = %s LIMIT 5", ("acme",))
                pii_denied = False
            except psycopg.Error:
                pii_denied = True
            check(pii_denied, "proxy: PII column denied over the wire protocol")
            # The proxy overwrites tenancy bind parameters with the session's tenant, so a
            # client asking for another tenant still only sees its own rows.
            rows = c.execute("SELECT o.tenant_id FROM app.orders o WHERE o.tenant_id = %s LIMIT 50", ("globex",)).fetchall()
            check(all(r[0] == "acme" for r in rows), f"proxy: tenancy parameter rewritten to the session tenant ({len(rows)} rows, all acme)")
    except Exception as e:  # noqa: BLE001
        check(False, f"proxy: {e}")

    # ---- haltsql-console ----
    cport = free_port()
    sources = [{"verifier": "haltsql-1", "file": server_audit}, {"verifier": "proxy-orders", "file": proxy_audit}]
    if args.suite_audit:
        sources.append({"verifier": "auto", "file": args.suite_audit})
    console_tokens = {r: "tok-" + r + "-" + os.urandom(6).hex() for r in ("admin", "analyst", "owner", "audit", "dev")}
    console_cfg = {
        "listen": f"127.0.0.1:{cport}",
        "environment": {"org": "Acme Corp", "name": "e2e", "region": "local"},
        "state_dir": os.path.join(work, "console-state"),
        "auth": {"tokens": [{"name": r, "sha256": sha(t), "role": r} for r, t in console_tokens.items()]},
        "verifiers": [
            {"name": "haltsql-1", "url": server_url, "kind": "server", "location": "loopback", "token": admin_token},
            {"name": "proxy-orders", "url": f"tcp://127.0.0.1:{pport}", "kind": "proxy", "location": "in front of the scratch db"},
        ],
        "fleet": {"poll_seconds": 2},
        "audit": {"sources": sources, "poll_seconds": 1},
        "policies": {"files": [POLICY]},
        "catalogs": [{"kind": "file", "path": os.path.join(work, "pii.json")}],
        "data": {"exceptions": [{"column": "app.customers.name", "policy": "saas", "owner": "Lee Park", "ticket": "SEC-88", "expires": "2099-01-01"}]},
        "agents": [{"name": f"{a}-agent", "via": "sidecar", "stack": a, "callers": [f"{a}-agent"], "policy": "saas"} for a in ADAPTERS if a != "mcp"]
        + [{"name": "mcp-agent", "via": "mcp", "stack": "haltsql-mcp", "callers": ["mcp-agent"], "policy": "saas"},
           {"name": "orders-proxy", "via": "proxy", "stack": "psycopg", "callers": ["orders-proxy-agent"], "policy": "saas"},
           {"name": "billing-reconciler", "via": "in_process", "stack": "Python package", "policy": "saas"}],
        "signals": {"cross_tenant": {"window_minutes": 10, "min_records": 10}},
    }
    # A HaltSQL PII manifest: tag two columns the policy can and cannot read.
    json.dump({"tables": {
        "app.customers": {"columns": {"name": {"classifications": ["PII"], "source": "dbt"},
                                      "email": {"classifications": ["PII", "contact"], "source": "dbt"}}},
        "app.orders": {"columns": {"total_cents": {"classifications": ["financial"], "source": "unity"}}}}},
        open(os.path.join(work, "pii.json"), "w"))
    console_cfg_path = os.path.join(work, "console.json")
    json.dump(console_cfg, open(console_cfg_path, "w"))
    procs.append(subprocess.Popen([CONSOLE, "--config", console_cfg_path], stdout=subprocess.DEVNULL, stderr=open(os.path.join(work, "console.log"), "w")))
    wait_http(f"http://127.0.0.1:{cport}/healthz")
    print(f"haltsql-console on http://127.0.0.1:{cport}")
    time.sleep(5)  # ingest, fleet, policies, data and signal loops
    verify_console(Console(f"http://127.0.0.1:{cport}"), console_tokens, args, work, server_audit, proxy_audit, skip)


def verify_console(c, tok, args, work, server_audit, proxy_audit, skip):
    A, AN, OW, AU, DEV = tok["admin"], tok["analyst"], tok["owner"], tok["audit"], tok["dev"]

    print("\nidentity and access")
    s, me = c.get("/api/v1/me", AN)
    check(s == 200 and me.get("role") == "analyst", "GET /me as analyst")
    s, _ = c.get("/api/v1/me", "nope")
    check(s == 401, "unknown token is 401")
    s, r = c.get("/api/v1/access/roles", A)
    check(s == 200 and len(r.get("permissions", [])) >= 10, "GET /access/roles")
    s, r = c.get("/api/v1/integrations", A)
    check(s == 200 and r.get("groups"), "GET /integrations")

    print("\nrecords")
    s, q = c.get("/api/v1/queries?limit=500", AN)
    check(s == 200 and q.get("total", 0) > 0, f"GET /queries: {q.get('total')} records")
    callers = {r["caller"] for r in q.get("records", [])}
    for a in ADAPTERS:
        if a in skip:
            continue
        check(f"{a}-agent" in callers, f"records from the {a} adapter")
    s, qp = c.get("/api/v1/queries?verifier=proxy-orders", AN)
    check(s == 200 and qp.get("total", 0) >= 5, f"proxy records ingested: {qp.get('total')}")
    check(all("sql" not in r for r in q.get("records", [])), "search never returns SQL")
    if args.suite_audit:
        s, qa = c.get("/api/v1/queries?limit=500&caller=anonymous", AN)
        vs = {r["verifier"] for r in qa.get("records", [])} if s == 200 else set()
        suites = {os.path.splitext(f)[0] for f in os.listdir(args.suite_audit) if f.endswith(".jsonl")}
        check(suites <= vs, f"integration test-suite audit files ingested ({len(suites & vs)}/{len(suites)})")
    s, den = c.get("/api/v1/queries?outcome=denied&code=E_TENANT_MISMATCH&verifier=haltsql-1", AN)
    rid = den["records"][0]["request_id"] if s == 200 and den.get("records") else None
    check(rid is not None, f"cross-tenant denials searchable: {den.get('total') if s == 200 else s}")
    if rid:
        s, rec = c.get(f"/api/v1/records/{rid}", AN)
        stages = {t["stage"]: t["state"] for t in rec.get("trail", [])} if s == 200 else {}
        check(stages.get("tenancy") == "denied" and stages.get("opa") in ("not_run", "skipped"), f"decision trail stops at tenancy: {stages}")
        check(rec.get("custody", {}).get("chain_state") == "intact", "chain of custody intact")
        s, _ = c.get(f"/api/v1/records/{rid}/sql", AN)
        check(s == 403, "raw SQL without a reason is refused")
        s, sq = c.get(f"/api/v1/records/{rid}/sql", AN, reason="e2e triage")
        check(s == 200 and "globex" in sq.get("sql", "") or "'" in sq.get("sql", ""), "raw SQL with a reason")
        s, _ = c.get(f"/api/v1/records/{rid}/sql", A, reason="x")
        check(s == 403, "admin cannot see raw SQL")
        s, vc = c.post(f"/api/v1/records/{rid}/verify-chain", AN)
        check(s == 200 and vc.get("chain_state") == "intact", "verify-chain")
    for f in (server_audit, proxy_audit):
        p = subprocess.run([CLI, "audit", "verify", f], capture_output=True, text=True)
        check(p.returncode == 0, f"haltsql audit verify {os.path.basename(f)} agrees: {(p.stdout or p.stderr).strip()[:120]}")

    print("\noverview and signals")
    s, ov = c.get("/api/v1/overview?range=1h", AN)
    t = ov.get("totals", {}) if s == 200 else {}
    check(s == 200 and t.get("checked", 0) > 0 and t.get("denied", 0) > 0, f"overview totals {t}")
    check(s == 200 and ov.get("series"), "overview series")
    check(s == 200 and any(p.get("state") != "unknown" for p in ov.get("posture", [])), "posture checks evaluated")
    sig = None
    for _ in range(40):  # detectors run every 30 s
        s, sl = c.get("/api/v1/signals?status=all", AN)
        sig = next((x for x in sl.get("signals", []) if x.get("kind") == "cross_tenant"), None) if s == 200 else None
        if sig:
            break
        time.sleep(1)
    check(sig is not None and sig.get("severity") == "high", f"cross-tenant signal fired: {sig and sig.get('title')}")
    if sig:
        s, sd = c.get(f"/api/v1/signals/{sig['id']}", AN)
        check(s == 200 and sd.get("shapes"), "signal detail with query shapes")
        s, case = c.post("/api/v1/cases", AN, {"title": "e2e: cross-tenant probes", "signal_id": sig["id"]})
        check(s == 201 and case.get("id", "").startswith("CASE-"), f"case opened: {case.get('id')}")
        s, _ = c.post("/api/v1/cases", DEV, {"title": "dev cannot"})
        check(s == 403, "dev cannot open cases")
        s, _ = c.post("/api/v1/callers/sdk-agent/pause", AN, {"minutes": 60}, reason="e2e")
        check(s == 501, "pause returns 501 until verifiers support deny lists")

    print("\nbuild")
    s, ag = c.get("/api/v1/agents?range=7d", DEV)
    names = {a["name"] for a in ag.get("agents", [])} if s == 200 else set()
    check(s == 200 and {"langchain-agent", "orders-proxy", "billing-reconciler"} <= names, f"agents: {len(names)}")
    s, pol = c.get("/api/v1/policies", DEV)
    check(s == 200 and any(p["name"] == "saas" for p in pol.get("policies", [])), "policies loaded")
    s, rep = c.get("/api/v1/policies/saas/report", OW)
    check(s == 200 and "never" in rep, "shadow report")
    good = "SELECT o.id FROM app.orders o WHERE o.tenant_id = $1 LIMIT 5"
    s, pg = c.post("/api/v1/playground/check", DEV, {"sql": good, "context": {"tenant_id": "acme"}, "targets": [{"policy": "saas"}]})
    check(s == 200 and pg["results"][0]["allowed"] is True, "playground allows a good query")
    draft = open(POLICY).read().replace("columns: [id, tenant_id, name, country, plan, created_at, metadata]",
                                        "columns: [id, tenant_id, name, country, plan, created_at, metadata, email]")
    draft = draft.replace("catalog: ../catalogs/saas.json", "catalog: " + os.path.join(ROOT, "test", "fixtures", "catalogs", "saas.json"))
    pii = "SELECT c.email FROM app.customers c WHERE c.tenant_id = $1 LIMIT 5"
    s, pg = c.post("/api/v1/playground/check", DEV, {"sql": pii, "context": {"tenant_id": "acme"}, "targets": [{"policy": "saas"}, {"policy": "saas", "draft": draft}]})
    res = [r["allowed"] for r in pg.get("results", [])] if s == 200 else []
    check(res == [False, True], f"playground live denies, draft allows: {res if res else pg}")
    s, _ = c.post("/api/v1/playground/check", AU, {"sql": good})
    check(s == 403, "audit role cannot use the playground")

    print("\noperate")
    s, fl = c.get("/api/v1/fleet", A)
    states = {v["name"]: v["state"] for v in fl.get("verifiers", [])} if s == 200 else {}
    check(states.get("haltsql-1") == "ready", f"fleet: haltsql-1 {states.get('haltsql-1')}")
    check(states.get("proxy-orders") == "ready", f"fleet: proxy-orders {states.get('proxy-orders')}")
    s, _ = c.post("/api/v1/fleet/haltsql-1/restart", A, reason="e2e")
    check(s == 503, "restart without Kubernetes is 503 NOT_CONFIGURED")

    print("\ncomply")
    s, dc = c.get("/api/v1/data/columns?show=all", AU)
    cols = {x["column"]: x for x in dc.get("columns", [])} if s == 200 else {}
    check(cols.get("app.customers.name", {}).get("status") == "exception", "tagged column allowed by an exception")
    check(cols.get("app.customers.email", {}).get("status") == "blocked", "PII column blocked by every policy")
    check(cols.get("app.orders.total_cents", {}).get("status") == "needs_review", "tagged column allowed without an exception needs review")
    s, ctl = c.get("/api/v1/evidence/controls?framework=soc2", AU)
    check(s == 200 and ctl.get("controls") and ctl.get("disclaimer"), "SOC 2 control mapping with disclaimer")
    now = time.time()
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 3600))
    until = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 60))
    s, pk = c.post("/api/v1/evidence/packs", AU, {"framework": "soc2", "since": since, "until": until})
    check(s == 202, f"evidence pack accepted: {pk}")
    if s == 202:
        for _ in range(60):
            s, pl = c.get("/api/v1/evidence/packs", AU)
            meta = next((p for p in pl.get("packs", []) if p["id"] == pk["id"]), {})
            if meta.get("state") in ("ready", "failed"):
                break
            time.sleep(1)
        check(meta.get("state") == "ready", f"evidence pack built: {meta.get('state')}")
        s, blob = c.get(f"/api/v1/evidence/packs/{pk['id']}/download", AU)
        if check(s == 200 and isinstance(blob, bytes), "evidence pack download"):
            path = os.path.join(work, "pack.tar.gz")
            open(path, "wb").write(blob)
            with tarfile.open(path) as tf:
                names = tf.getnames()
                chains = json.load(tf.extractfile(next(n for n in names if n.endswith("chains.json"))))
            check(any(n.endswith("manifest.json") for n in names), f"pack has manifest ({len(names)} files)")
            check("broken" not in json.dumps(chains), "pack chain report: every chain verifies")
    s, _ = c.post("/api/v1/evidence/packs", DEV, {"framework": "soc2"})
    check(s == 403, "dev cannot build evidence packs")

    s, act = c.get("/api/v1/activity?limit=500", A)
    acts = {e["action"] for e in act.get("entries", [])} if s == 200 else set()
    check({"record.view_sql", "caller.pause_requested", "playground.check"} <= acts, f"activity log records sensitive actions: {sorted(acts)}")


if __name__ == "__main__":
    main()
