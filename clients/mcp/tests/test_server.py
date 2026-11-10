"""The MCP layer: in-process client, streamable HTTP with bearer tokens, stdio,
and (with the lab Postgres) real query execution."""

import json
import os
import socket
import sys
import threading
import time

import pytest

from haltsql import AsyncHaltSQLClient, AsyncLocalVerifier
from haltsql.testing import FakeVerifier
from haltsql_mcp import (
    ConfigError,
    HaltSQLTools,
    Settings,
    StaticTokenVerifier,
    build_server,
    hash_token,
    load_tokens_file,
)
from haltsql_mcp.server import session_context_provider, settings_from_args

from conftest import SAAS_POLICY, decide, haltsql_bin

mcp = pytest.importorskip("mcp")
try:
    from mcp import Client  # mcp >= 2
except ImportError:  # pragma: no cover
    Client = None

needs_client = pytest.mark.skipif(Client is None, reason="tests use the mcp>=2 Client API")

OK = "SELECT id, total_cents, created_at FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 50"
BAD = "SELECT id FROM orders LIMIT 5"


def payload(result):
    assert result.is_error is False, result.content
    sc = result.structured_content
    return sc["result"] if sc and "result" in sc else json.loads(result.content[0].text)


async def never_connect():
    raise AssertionError("must not connect")


@needs_client
async def test_tools_listed_with_no_tenant_arguments():
    t = HaltSQLTools(FakeVerifier(decide), lambda: {"tenant_id": "acme"})
    async with Client(build_server(t)) as c:
        tools = {x.name: x for x in (await c.list_tools()).tools}
    assert set(tools) == {"query", "explain_denial", "list_tables", "describe_policy"}
    assert list(tools["query"].input_schema["properties"]) == ["sql"]
    assert list(tools["explain_denial"].input_schema["properties"]) == ["sql"]
    assert tools["list_tables"].input_schema["properties"] == {}
    assert all(x.annotations.read_only_hint for x in tools.values())


@needs_client
async def test_extra_tenant_argument_is_ignored():
    fv = FakeVerifier(decide)
    t = HaltSQLTools(fv, lambda: {"tenant_id": "acme"}, connect=never_connect)
    async with Client(build_server(t)) as c:
        r = await c.call_tool("query", {"sql": BAD, "tenant_id": "globex", "context": {"tenant_id": "x"}})
    assert payload(r)["allowed"] is False
    assert fv.calls == [(BAD, {"tenant_id": "acme"})]


@needs_client
async def test_tool_failure_is_an_error_result():
    t = HaltSQLTools(FakeVerifier(decide), lambda: {"tenant_id": "a"})
    async with Client(build_server(t)) as c:
        r = await c.call_tool("query", {"sql": OK})
    assert r.is_error is True
    assert "no database is configured" in r.content[0].text


# ---- config -------------------------------------------------------------------


def test_tokens_file_validation(tmp_path):
    good = {"tokens": [{"name": "a", "token_sha256": hash_token("tok-a"), "context": {"tenant_id": "acme"}}]}
    p = tmp_path / "t.json"
    p.write_text(json.dumps(good))
    [e] = load_tokens_file(str(p))
    assert e.name == "a" and e.context == {"tenant_id": "acme"} and e.matches(hash_token("tok-a"))
    bad_cases = [
        {"tokens": []},
        {"tokens": [{"name": "a", "token_sha256": "tok-a", "context": {}}]},
        {"tokens": [{"name": "a", "token_sha256": hash_token("x"), "context": {"t": True}}]},
        {"tokens": [{"name": "a", "token_sha256": hash_token("x")}, {"name": "a", "token_sha256": hash_token("y")}]},
        {"tokens": [{"name": "a", "token_sha256": hash_token("x"), "extra": 1}]},
        {"tokens": [], "more": 1},
    ]
    for bad in bad_cases:
        p.write_text(json.dumps(bad))
        with pytest.raises(ConfigError):
            load_tokens_file(str(p))


def test_settings_validation(tmp_path):
    with pytest.raises(ConfigError, match="tokens file"):
        settings_from_args(["--transport", "http"], env={})
    with pytest.raises(ConfigError, match="loopback"):
        settings_from_args(["--transport", "http", "--insecure-static-context", "--host", "0.0.0.0"], env={})
    with pytest.raises(ConfigError, match="row cap"):
        settings_from_args(["--row-cap", "0"], env={})
    with pytest.raises(ConfigError, match="custom setting"):
        settings_from_args([], env={"HALTSQL_MCP_SET_CONFIG": '{"search_path": "tenant_id"}'})
    with pytest.raises(ConfigError, match="context"):
        settings_from_args([], env={"HALTSQL_MCP_CONTEXT": '{"tenant_id": 1.5}'})
    with pytest.raises(ConfigError, match="not valid JSON"):
        settings_from_args([], env={"HALTSQL_MCP_CONTEXT": "{"})
    s = settings_from_args(["--row-cap", "50"], env={
        "HALTSQL_MCP_CONTEXT": '{"tenant_id": "acme"}', "HALTSQL_TOKEN": "t", "HALTSQL_MCP_POLICY_FILE": SAAS_POLICY})
    assert s.row_cap == 50 and s.context == {"tenant_id": "acme"} and s.describe_file == SAAS_POLICY
    assert "'t'" not in repr(s)  # token not in repr


def test_settings_positional_dsn():
    """`haltsql-mcp postgresql://...` works like @modelcontextprotocol/server-postgres."""
    dsn = "postgresql://agent_ro@localhost/app"
    s = settings_from_args([dsn], env={})
    assert s.database_url == dsn
    s = settings_from_args(["--row-cap", "10", dsn], env={"DATABASE_URL": "postgresql://other/db"})
    assert s.database_url == dsn and s.row_cap == 10
    assert settings_from_args(["--database-url", dsn, dsn], env={}).database_url == dsn
    with pytest.raises(ConfigError, match="once"):
        settings_from_args(["--database-url", "postgresql://other/db", dsn], env={})
    assert dsn not in repr(settings_from_args([dsn], env={}))


def test_settings_tls_to_sidecar(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    s = settings_from_args([], env={"HALTSQL_CA_FILE": str(ca)})
    assert s.haltsql_ca_file == str(ca)
    with pytest.raises(ConfigError, match="file not found"):
        settings_from_args([], env={"HALTSQL_CA_FILE": str(tmp_path / "missing.pem")})
    with pytest.raises(ConfigError, match="HALTSQL_CLIENT_CERT"):
        settings_from_args([], env={"HALTSQL_CLIENT_KEY": str(ca)})
    s = settings_from_args([], env={"HALTSQL_CLIENT_CERT": str(ca), "HALTSQL_CLIENT_KEY": str(ca)})
    assert s.haltsql_client_key == str(ca) and "haltsql_client_key" not in repr(s)


def test_main_exits_2_on_config_error(capsys):
    from haltsql_mcp import main

    assert main(["--transport", "http"]) == 2
    assert "tokens file" in capsys.readouterr().err


async def test_static_token_verifier():
    v = StaticTokenVerifier([
        *load_entries({"a": ("tok-a", {"tenant_id": "acme"}), "b": ("tok-b", {"tenant_id": "globex"})})
    ])
    at = await v.verify_token("tok-b")
    assert at.client_id == "b" and "tok-b" not in at.token
    assert await v.verify_token("tok-c") is None
    assert await v.verify_token("") is None


def load_entries(spec):
    from haltsql_mcp import TokenEntry

    return [TokenEntry(name=n, token_sha256=hash_token(t), context=c) for n, (t, c) in spec.items()]


# ---- streamable HTTP end to end ----------------------------------------------


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def http_server(fake_sidecar):
    uvicorn = pytest.importorskip("uvicorn")
    verifier = StaticTokenVerifier(load_entries({
        "agent-acme": ("tok-acme", {"tenant_id": "acme"}),
        "agent-globex": ("tok-globex", {"tenant_id": "globex"}),
    }))
    client = AsyncHaltSQLClient(fake_sidecar.url, "sidecar-token")
    tools = HaltSQLTools(client, session_context_provider(verifier), policy_file=SAAS_POLICY,
                         policies_lister=client.policies)
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    server = build_server(tools, token_verifier=verifier, public_url=url)
    app = server.streamable_http_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="on")
    srv = uvicorn.Server(config)
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    deadline = time.time() + 10
    while not srv.started:
        if time.time() > deadline:
            pytest.fail("uvicorn did not start")
        time.sleep(0.02)
    yield url
    srv.should_exit = True
    th.join(5)


def _http_client(url, token):
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared._httpx_utils import create_mcp_http_client

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return Client(streamable_http_client(url + "/mcp", http_client=create_mcp_http_client(headers=headers)))


@needs_client
async def test_http_requires_valid_token(http_server):
    import httpx

    async with httpx.AsyncClient() as h:
        r = await h.post(http_server + "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                         headers={"Accept": "application/json, text/event-stream"})
        assert r.status_code == 401
        r = await h.post(http_server + "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                         headers={"Accept": "application/json, text/event-stream",
                                  "Authorization": "Bearer wrong"})
        assert r.status_code == 401


@needs_client
async def test_http_token_selects_tenant(http_server, fake_sidecar):
    async with _http_client(http_server, "tok-acme") as c:
        out = payload(await c.call_tool("explain_denial", {"sql": OK}))
        assert out["allowed"] is True
    async with _http_client(http_server, "tok-globex") as c:
        out = payload(await c.call_tool("explain_denial", {"sql": BAD, "tenant_id": "acme"}))
        assert out["allowed"] is False
        dp = payload(await c.call_tool("describe_policy", {}))
        assert dp["policies"][0]["name"] == "saas"
    verify_bodies = [r.body for r in fake_sidecar.requests if r.path == "/v1/verify"]
    assert [b["context"] for b in verify_bodies] == [{"tenant_id": "acme"}, {"tenant_id": "globex"}]
    assert all(r.headers["authorization"] == "Bearer sidecar-token"
               for r in fake_sidecar.requests if r.path.startswith("/v1/"))


# ---- lab Postgres ---------------------------------------------------------------


@pytest.mark.integration
@needs_client
async def test_query_executes_on_postgres(pg_dsn, fake_sidecar):
    import psycopg

    client = AsyncHaltSQLClient(fake_sidecar.url, "sidecar-token")

    async def connect():
        return await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True)

    t = HaltSQLTools(client, lambda: {"tenant_id": "acme"}, connect=connect, row_cap=4,
                     statement_timeout_ms=1000, set_config={"app.tenant_id": "tenant_id"})
    async with Client(build_server(t)) as c:
        out = payload(await c.call_tool("query", {"sql": OK}))
        assert out["columns"] == ["id", "total_cents", "created_at"]
        assert out["rows"] == [[1, "1.50", "2026-01-02T03:04:05+00:00"],
                               [2, "3.00", "2026-01-02T03:04:05+00:00"],
                               [3, "4.50", "2026-01-02T03:04:05+00:00"],
                               [4, "6.00", "2026-01-02T03:04:05+00:00"]]
        assert out["truncated"] is True and out["row_count"] == 4
        # set_config applied transaction-locally
        out = payload(await c.call_tool(
            "query", {"sql": "SELECT current_setting('app.tenant_id') AS t FROM orders WHERE tenant_id = $1 LIMIT 1"}))
        assert out["rows"] == [["acme"]]
        # read-only transaction
        r = await c.call_tool("query", {"sql": "UPDATE orders SET status = 'x' WHERE tenant_id = $1"})
        assert r.is_error and "25006" in r.content[0].text
        # statement_timeout
        r = await c.call_tool("query", {"sql": "SELECT pg_sleep(3) FROM orders WHERE tenant_id = $1 LIMIT 1"})
        assert r.is_error and "57014" in r.content[0].text
        # denied: nothing runs
        out = payload(await c.call_tool("query", {"sql": BAD}))
        assert out == {"allowed": False, "executed": False,
                       "reasons": [{"code": "E_TENANT_MISSING", "message": "E_TENANT_MISSING (fake)",
                                    "rule": "fake", "hint": "fix E_TENANT_MISSING"}],
                       "message": "HaltSQL denied the query. Fix it using the reasons and hints, then retry."}
    await client.aclose()


@pytest.mark.integration
@needs_client
async def test_query_with_real_cli_policy(pg_dsn):
    import psycopg

    b = haltsql_bin()
    if b is None:
        pytest.skip("haltsql CLI not built")

    async def connect():
        return await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True)

    t = HaltSQLTools(AsyncLocalVerifier(SAAS_POLICY, binary=b), lambda: {"tenant_id": "globex"},
                     connect=connect, policy_file=SAAS_POLICY)
    async with Client(build_server(t)) as c:
        out = payload(await c.call_tool(
            "query", {"sql": "SELECT o.id FROM orders o WHERE o.tenant_id = $1 ORDER BY o.id LIMIT 100"}))
        assert out["rows"] == [[7], [8], [9], [10]]
        out = payload(await c.call_tool(
            "query", {"sql": "SELECT o.id FROM orders o WHERE o.tenant_id = 'acme' LIMIT 100"}))
        assert out["allowed"] is False
        assert out["reasons"][0]["code"] in ("E_TENANT_MISSING", "E_TENANT_MISMATCH", "E_TENANT_LITERAL")
        out = payload(await c.call_tool("explain_denial", {"sql": "SELECT email FROM customers LIMIT 1"}))
        assert {"E_COLUMN_DENIED", "E_TENANT_MISSING"} <= {r["code"] for r in out["reasons"]}


@pytest.mark.integration
@needs_client
async def test_stdio_end_to_end(pg_dsn, fake_sidecar):
    from mcp import StdioServerParameters

    env = dict(os.environ)
    env.update({
        "HALTSQL_URL": fake_sidecar.url,
        "HALTSQL_TOKEN": "sidecar-token",
        "HALTSQL_MCP_DATABASE_URL": pg_dsn,
        "HALTSQL_MCP_CONTEXT": json.dumps({"tenant_id": "globex"}),
        "HALTSQL_MCP_POLICY_FILE": SAAS_POLICY,
    })
    params = StdioServerParameters(command=sys.executable, args=["-m", "haltsql_mcp"], env=env)
    async with Client(params) as c:
        out = payload(await c.call_tool("query", {"sql": "SELECT id FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 10"}))
        assert out["rows"] == [[7], [8], [9], [10]]
        lt = payload(await c.call_tool("list_tables", {}))
        assert any(x["table"] == "app.orders" for x in lt["tables"])


def test_config_file(tmp_path):
    """One config file covers everything; relative paths resolve next to it; env and flags override it."""
    import shutil

    shutil.copy(SAAS_POLICY, tmp_path / "policy.yaml")
    cfg = tmp_path / "haltsql-mcp.yaml"
    cfg.write_text(
        "database_url: postgresql://agent_ro@localhost/app\n"
        "policy: policy.yaml\n"
        "context: {tenant_id: acme}\n"
        "row_cap: 50\n"
        "set_config: {app.tenant_id: tenant_id}\n"
    )
    s = settings_from_args(["--config", str(cfg)], env={})
    assert s.local_policy_file == str(tmp_path / "policy.yaml")
    assert s.describe_file == str(tmp_path / "policy.yaml")
    assert s.database_url == "postgresql://agent_ro@localhost/app"
    assert s.context == {"tenant_id": "acme"} and s.row_cap == 50
    assert s.set_config == {"app.tenant_id": "tenant_id"}
    # HALTSQL_MCP_CONFIG works too; env overrides the file, flags override env.
    s = settings_from_args(["--row-cap", "7"], env={
        "HALTSQL_MCP_CONFIG": str(cfg), "HALTSQL_MCP_ROW_CAP": "9",
        "HALTSQL_MCP_CONTEXT": '{"tenant_id": "globex"}'})
    assert s.row_cap == 7 and s.context == {"tenant_id": "globex"}
    assert s.local_policy_file == str(tmp_path / "policy.yaml")


def test_config_file_central_server(tmp_path):
    (tmp_path / "token").write_text("s3cret\n")
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({
        "server": {"url": "https://haltsql.internal:8443", "token_file": "token",
                   "policy": "saas-analytics", "timeout": 3},
        "database_url": "postgresql://agent_ro@db/app",
        "policy_file": SAAS_POLICY,
    }))
    s = settings_from_args(["--config", str(cfg)], env={})
    assert s.haltsql_url == "https://haltsql.internal:8443" and s.haltsql_token == "s3cret"
    assert s.haltsql_policy == "saas-analytics" and s.haltsql_timeout == 3.0
    assert s.local_policy_file is None and "s3cret" not in repr(s)
    assert settings_from_args(["--config", str(cfg)], env={"HALTSQL_TOKEN": "env"}).haltsql_token == "env"


def test_config_file_errors(tmp_path):
    cfg = tmp_path / "c.yaml"
    cases = [
        ("row_cpa: 5\n", "unknown key"),
        ("server: {token: abc}\n", "token_file"),
        ("server: {urll: x}\n", "unknown key server.urll"),
        (f"policy: {SAAS_POLICY}\nserver: {{url: http://x}}\n", "not both"),
        ("row_cap: '5'\n", "integer"),
        ("context: [1]\n", "mapping"),
        ("- a\n", "must be a mapping"),
        ("policy: missing.yaml\n", "file not found"),
        ("server: {token_file: nope}\n", "cannot read"),
    ]
    for text, msg in cases:
        cfg.write_text(text)
        with pytest.raises(ConfigError, match=msg):
            settings_from_args(["--config", str(cfg)], env={})
    with pytest.raises(ConfigError, match="cannot read config file"):
        settings_from_args(["--config", str(tmp_path / "absent.yaml")], env={})
    empty = tmp_path / "empty.yaml"
    empty.write_text("")
    assert settings_from_args(["--config", str(empty)], env={}).row_cap == 200


# ---- tokens, sessions and wiring: exact comparisons and fail-closed defaults ----


def _two_tenants():
    return StaticTokenVerifier(load_entries({
        "a": ("tok-a", {"tenant_id": "acme"}), "b": ("tok-b", {"tenant_id": "globex"})}))


def test_token_entry_compares_the_whole_digest():
    from haltsql_mcp import TokenEntry

    h = hash_token("tok-a")
    e = TokenEntry(name="a", token_sha256=h, context={})
    assert e.matches(h)
    last = "0" if h[63] != "0" else "1"
    for other in (h[:16] + "0" * 48, h[:63] + last, h[:1], h[:16], h.upper(), "", h + "00", "tok-a"):
        assert other == h or not e.matches(other), other
    # The digest is of the exact token: no trimming, no case folding.
    for variant in ("tok-a ", " tok-a", "tok-a\n", "TOK-A"):
        assert hash_token(variant) != h


async def test_static_token_verifier_is_exact():
    from haltsql_mcp import TokenEntry

    v = _two_tenants()
    h = hash_token("tok-a")
    for t in ("tok-a ", " tok-a", "tok-a\n", "TOK-A", "tok-", h, "sha256:" + h):
        assert await v.verify_token(t) is None, t
    assert (await v.verify_token("tok-a")).client_id == "a"
    # An entry whose stored digest only shares a prefix with the presented token's digest.
    hx = hash_token("tok-x")
    near = StaticTokenVerifier([TokenEntry(name="x", token_sha256=hx[:16] + "0" * 48, context={})])
    assert await near.verify_token("tok-x") is None


def test_session_context_provider_requires_a_known_authenticated_client(monkeypatch):
    from types import SimpleNamespace

    import haltsql_mcp.server as srv

    provider = session_context_provider(_two_tenants())
    # Outside an authenticated MCP request the SDK has no access token.
    with pytest.raises(PermissionError, match="not authenticated"):
        provider()
    current = {"tok": None}
    monkeypatch.setattr(srv, "_get_access_token", lambda: current["tok"])
    with pytest.raises(PermissionError, match="not authenticated"):
        provider()
    for client_id in ("c", "", None, "A"):
        current["tok"] = SimpleNamespace(client_id=client_id)
        with pytest.raises(PermissionError, match="unknown client"):
            provider()
    current["tok"] = SimpleNamespace(client_id="b")
    ctx = provider()
    assert ctx == {"tenant_id": "globex"}
    # What one request does to its context never reaches the next one.
    ctx["tenant_id"] = "acme"
    ctx["role"] = "admin"
    assert provider() == {"tenant_id": "globex"}


async def test_unauthenticated_session_cannot_use_any_tool():
    from haltsql_mcp.core import ToolFailure

    fv = FakeVerifier(decide)
    t = HaltSQLTools(fv, session_context_provider(_two_tenants()), connect=never_connect,
                     policy_file=SAAS_POLICY)
    for call in (t.query(OK), t.explain_denial(OK), t.list_tables(), t.describe_policy()):
        with pytest.raises(ToolFailure, match="not authenticated"):
            await call
    assert fv.calls == []


def test_static_context_provider_returns_copies():
    from haltsql_mcp.server import static_context_provider

    source = {"tenant_id": "acme"}
    provider = static_context_provider(source)
    source["tenant_id"] = "globex"
    got = provider()
    got["tenant_id"] = "evil"
    assert provider() == {"tenant_id": "acme"}


def test_tokens_file_rejects_ambiguous_or_malformed_entries(tmp_path):
    ok = {"name": "a", "token_sha256": hash_token("tok-a"), "context": {"tenant_id": "acme"}}
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"tokens": [ok]}))
    assert [e.name for e in load_tokens_file(str(p))] == ["a"]
    cases = [
        ({"tokens": [ok], "more": 1}, "no other keys"),
        # one token under two names would make the tenant depend on file order
        ({"tokens": [ok, {**ok, "name": "b", "context": {"tenant_id": "globex"}}]}, "duplicate name or token"),
        ({"tokens": [ok, {**ok, "token_sha256": hash_token("tok-b")}]}, "duplicate name or token"),
        ({"tokens": [{**ok, "name": ""}]}, "name must be a non-empty string"),
        # an upper-case digest would be accepted and then never match
        ({"tokens": [{**ok, "token_sha256": hash_token("tok-a").upper()}]}, "lower-case hex"),
        ({"tokens": [{**ok, "token": "tok-a"}]}, "expected keys"),
        ({"tokens": [{"name": "a", "token": "tok-a", "context": {}}]}, "expected keys"),
        # a context that is present but not an object is a mistake, not "no context"
        *[({"tokens": [{**ok, "context": c}]}, "context must be an object") for c in (None, "", [], 0, False, "acme")],
    ]
    for bad, msg in cases:
        p.write_text(json.dumps(bad))
        with pytest.raises(ConfigError, match=msg):
            load_tokens_file(str(p))


def test_settings_bounds_and_transport_rules(tmp_path):
    tokens = tmp_path / "t.json"
    tokens.write_text(json.dumps({"tokens": [
        {"name": "a", "token_sha256": hash_token("tok-a"), "context": {"tenant_id": "acme"}}]}))
    assert settings_from_args(["--row-cap", "10000"], env={}).row_cap == 10000
    with pytest.raises(ConfigError, match="row cap"):
        settings_from_args(["--row-cap", "10001"], env={})
    assert settings_from_args(["--statement-timeout-ms", "600000"], env={}).statement_timeout_ms == 600000
    for bad in ("0", "-5", "600001"):
        with pytest.raises(ConfigError, match="statement timeout"):
            settings_from_args([f"--statement-timeout-ms={bad}"], env={})
    # A tokens file on stdio would be silently ignored (one static context for everyone).
    with pytest.raises(ConfigError, match="only applies to the HTTP transport"):
        settings_from_args(["--tokens-file", str(tokens)], env={})
    insecure = ["--transport", "http", "--insecure-static-context", "--host"]
    for host in ("example.com", "db.internal", "10.0.0.5", "::", "localhost.example.com"):
        with pytest.raises(ConfigError, match="loopback"):
            settings_from_args([*insecure, host], env={})
    for host in ("localhost", "127.0.0.1", "::1"):
        assert settings_from_args([*insecure, host], env={}).host == host
    s = settings_from_args(["--transport", "http", "--tokens-file", str(tokens), "--host", "0.0.0.0"], env={})
    assert s.tokens_file == str(tokens)


def test_config_file_empty_token_file(tmp_path):
    (tmp_path / "token").write_text(" \n")
    cfg = tmp_path / "c.yaml"
    cfg.write_text("server: {url: 'http://127.0.0.1:8080', token_file: token}\n")
    with pytest.raises(ConfigError, match="is empty"):
        settings_from_args(["--config", str(cfg)], env={})


async def test_build_tools_local_policy_does_not_use_the_sidecar():
    from haltsql_mcp.server import build_tools

    b = haltsql_bin()
    if b is None:
        pytest.skip("haltsql CLI not built")
    s = settings_from_args(["--local-policy", SAAS_POLICY, "--haltsql-url", f"http://127.0.0.1:{_free_port()}"],
                           env={"HALTSQL_BIN": b})
    t = build_tools(s, lambda: {"tenant_id": "acme"})
    out = await t.explain_denial("SELECT id FROM orders LIMIT 5")
    assert out["allowed"] is False and "E_TENANT_MISSING" in [r["code"] for r in out["reasons"]]
    assert (await t.explain_denial("SELECT id FROM orders WHERE tenant_id = $1 LIMIT 5"))["allowed"] is True


async def test_build_tools_applies_the_sidecar_timeout(fake_sidecar):
    from haltsql_mcp.core import ToolFailure
    from haltsql_mcp.server import build_tools

    s = settings_from_args([], env={"HALTSQL_URL": fake_sidecar.url, "HALTSQL_TOKEN": "sidecar-token",
                                    "HALTSQL_TIMEOUT": "0.2"})
    t = build_tools(s, lambda: {"tenant_id": "acme"})
    try:
        for _ in range(3):
            fake_sidecar.push(200, decide(OK, {"tenant_id": "acme"}, None), delay=3.0)
        t0 = time.monotonic()
        with pytest.raises(ToolFailure, match="verification is unavailable; the query was not executed"):
            await t.explain_denial(OK)
        assert time.monotonic() - t0 < 2.5  # 3 attempts of 0.2 s, not of the 2 s default
    finally:
        await t.verifier.aclose()


async def test_build_tools_verifies_the_sidecar_certificate(tmp_path):
    """An https sidecar with an unknown certificate is refused unless its CA is configured."""
    import shutil
    import ssl
    import subprocess
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from haltsql_mcp.core import ToolFailure
    from haltsql_mcp.server import build_tools

    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", str(key), "-out", str(cert), "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        capture_output=True,
    )
    if r.returncode != 0:
        pytest.skip("openssl could not create a test certificate")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
            out = json.dumps(decide(body["sql"], body.get("context") or {}, None)).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(cert), str(key))
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"https://127.0.0.1:{srv.server_address[1]}"
    try:
        untrusted = build_tools(settings_from_args([], env={"HALTSQL_URL": url}), lambda: {"tenant_id": "acme"})
        with pytest.raises(ToolFailure, match="verification is unavailable"):
            await untrusted.explain_denial(OK)
        await untrusted.verifier.aclose()
        trusted = build_tools(settings_from_args([], env={"HALTSQL_URL": url, "HALTSQL_CA_FILE": str(cert)}),
                              lambda: {"tenant_id": "acme"})
        assert (await trusted.explain_denial(OK))["allowed"] is True
        await trusted.verifier.aclose()
    finally:
        srv.shutdown()
        srv.server_close()


@needs_client
async def test_http_main_authenticates_with_the_tokens_file(tmp_path, fake_sidecar):
    """`haltsql-mcp --transport http --tokens-file ...` as a real process: no request
    gets in without one of the file's tokens, and the token (not the static
    context) selects the tenant."""
    import subprocess

    import httpx

    pytest.importorskip("uvicorn")
    tokens = tmp_path / "tokens.json"
    tokens.write_text(json.dumps({"tokens": [
        {"name": "agent-acme", "token_sha256": hash_token("tok-acme"), "context": {"tenant_id": "acme"}},
        {"name": "agent-globex", "token_sha256": hash_token("tok-globex"), "context": {"tenant_id": "globex"}},
    ]}))
    port = _free_port()
    env = dict(os.environ)
    env.update({
        "HALTSQL_URL": fake_sidecar.url,
        "HALTSQL_TOKEN": "sidecar-token",
        "HALTSQL_POLICY": "saas",
        "HALTSQL_MCP_CONTEXT": json.dumps({"tenant_id": "static"}),
    })
    proc = subprocess.Popen(
        [sys.executable, "-m", "haltsql_mcp", "--transport", "http", "--port", str(port),
         "--tokens-file", str(tokens)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 20
        while True:
            if proc.poll() is not None:
                pytest.fail(f"haltsql-mcp exited early: {proc.stderr.read().decode()[:500]}")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                if time.time() > deadline:
                    pytest.fail("haltsql-mcp did not start listening")
                time.sleep(0.05)
        accept = {"Accept": "application/json, text/event-stream"}
        async with httpx.AsyncClient() as h:
            for auth in ({}, {"Authorization": "Bearer wrong"},
                         {"Authorization": "Bearer " + hash_token("tok-acme")},
                         {"Authorization": "Bearer sidecar-token"}):
                r = await h.post(url + "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                                 headers={**accept, **auth})
                assert r.status_code == 401, auth
        async with _http_client(url, "tok-globex") as c:
            assert payload(await c.call_tool("explain_denial", {"sql": OK}))["allowed"] is True
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
    bodies = [r.body for r in fake_sidecar.requests if r.path == "/v1/verify"]
    assert [b["context"] for b in bodies] == [{"tenant_id": "globex"}]
    assert bodies[0]["policy"] == "saas"


@pytest.mark.integration
@needs_client
async def test_stdio_limits_from_environment(pg_dsn, fake_sidecar):
    """Row cap, statement timeout and set_config configured through the environment
    reach the transaction of a real `python -m haltsql_mcp` process."""
    from mcp import StdioServerParameters

    env = dict(os.environ)
    env.update({
        "HALTSQL_URL": fake_sidecar.url,
        "HALTSQL_TOKEN": "sidecar-token",
        "HALTSQL_POLICY": "saas",
        "HALTSQL_MCP_DATABASE_URL": pg_dsn,
        "HALTSQL_MCP_CONTEXT": json.dumps({"tenant_id": "acme"}),
        "HALTSQL_MCP_ROW_CAP": "2",
        "HALTSQL_MCP_STATEMENT_TIMEOUT_MS": "200",
        "HALTSQL_MCP_SET_CONFIG": json.dumps({"app.tenant_id": "tenant_id"}),
    })
    params = StdioServerParameters(command=sys.executable, args=["-m", "haltsql_mcp"], env=env)
    async with Client(params) as c:
        out = payload(await c.call_tool("query", {"sql": "SELECT id FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 10"}))
        assert out["rows"] == [[1], [2]] and out["truncated"] is True and out["row_cap"] == 2
        out = payload(await c.call_tool("query", {"sql": (
            "SELECT current_setting('app.tenant_id'), current_setting('statement_timeout'), "
            "current_setting('transaction_read_only') FROM orders WHERE tenant_id = $1 LIMIT 1")}))
        assert out["rows"] == [["acme", "200ms", "on"]]
        r = await c.call_tool("query", {"sql": "SELECT pg_sleep(3) FROM orders WHERE tenant_id = $1 LIMIT 1"})
        assert r.is_error and "57014" in r.content[0].text
    bodies = [r.body for r in fake_sidecar.requests if r.path == "/v1/verify"]
    assert len(bodies) == 3 and all(b["policy"] == "saas" for b in bodies)
