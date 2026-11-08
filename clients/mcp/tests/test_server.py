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
