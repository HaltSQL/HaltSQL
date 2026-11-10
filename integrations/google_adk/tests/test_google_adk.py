"""haltsql-google-adk with real ADK objects: an InMemoryRunner, a real session
in its InMemorySessionService, a real InvocationContext / ToolContext and
ADK's own function-call handler (the code that runs callbacks, plugins and
tools after a model turn). The model is never called: the function-call event
is built the way a model response would carry it. Verification uses the real
haltsql CLI / haltsql-server; queries run on the lab Postgres."""

from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List, Optional

import pytest

from conftest import CROSS_TENANT_SQL, OK_SQL, ROOT, TENANT_HINT, acme_rows, assert_denied_cross_tenant

pytest.importorskip("google.adk", reason="google-adk is not installed (pip install -e integrations/google_adk)")

from google.adk.events import Event  # noqa: E402
from google.adk.flows.llm_flows.functions import handle_function_calls_async  # noqa: E402
from google.adk.runners import InMemoryRunner  # noqa: E402
from google.adk.tools import FunctionTool, ToolContext  # noqa: E402
from google.genai import types  # noqa: E402

from haltsql_google_adk import (  # noqa: E402
    HaltSQLGuardPlugin,
    HaltSQLQueryTool,
    HaltSQLToolRunner,
    build_sql_agent,
    haltsql_before_tool_callback,
)

LITERAL_POLICY = os.path.join(ROOT, "test", "fixtures", "policies", "saas_literal.yaml")
APP = "haltsql_adk_test"


async def _session(runner: InMemoryRunner, state: Optional[Dict[str, Any]], user: str = "u1") -> Any:
    return await runner.session_service.create_session(app_name=APP, user_id=user, state=state)


async def _call_tools(runner: InMemoryRunner, session: Any, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Hand ADK one model-style function call and return the function response."""
    ic = runner._new_invocation_context(session)
    event = Event(
        invocation_id=ic.invocation_id,
        author=runner.agent.name,
        content=types.Content(role="model", parts=[
            types.Part(function_call=types.FunctionCall(id="call_1", name=name, args=args))]),
    )
    tools = {t.name: t for t in await runner.agent.canonical_tools()}
    out = await handle_function_calls_async(ic, event, tools)
    assert out is not None
    parts = [p for p in out.content.parts if p.function_response]
    assert len(parts) == 1
    return dict(parts[0].function_response.response)


def test_declaration_and_validation():
    class V:
        def verify(self, sql, context=None):
            raise AssertionError

    tool = HaltSQLQueryTool(HaltSQLToolRunner(V(), lambda: None))
    decl = tool._get_declaration()
    assert decl.name == "haltsql_query"
    assert list(decl.parameters.properties) == ["query"] and decl.parameters.required == ["query"]
    with pytest.raises(TypeError):
        HaltSQLQueryTool(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        haltsql_before_tool_callback(object())
    with pytest.raises(ValueError):
        haltsql_before_tool_callback(V(), tools={})
    agent = build_sql_agent(HaltSQLToolRunner(V(), lambda: None))
    assert agent.name == "sql_analyst" and [t.name for t in agent.tools] == ["haltsql_query"]


@pytest.mark.integration
def test_tool_with_real_tool_context(local_verifier, connections):
    agent = build_sql_agent(HaltSQLToolRunner(local_verifier, connections))
    runner = InMemoryRunner(agent=agent, app_name=APP)

    async def run() -> None:
        session = await _session(runner, {"haltsql_context": {"tenant_id": "acme"}})
        tc = ToolContext(runner._new_invocation_context(session), function_call_id="call_1")
        tool = agent.tools[0]
        ok = await tool.run_async(args={"query": OK_SQL}, tool_context=tc)
        assert ok["status"] == "ok" and ok["rows"] == acme_rows()
        denied = await tool.run_async(args={"query": CROSS_TENANT_SQL}, tool_context=tc)
        assert_denied_cross_tenant(denied)
        bad = await tool.run_async(args={"query": OK_SQL, "tenant_id": "globex"}, tool_context=tc)
        assert bad["status"] == "error" and bad["executed"] is False

    asyncio.run(run())
    assert connections.opened == 1


@pytest.mark.integration
def test_function_call_flow_and_session_state(server_verifier, connections):
    agent = build_sql_agent(HaltSQLToolRunner(server_verifier, connections))
    runner = InMemoryRunner(agent=agent, app_name=APP)

    async def run() -> None:
        globex = await _session(runner, {"haltsql_context": {"tenant_id": "globex"}}, "u2")
        out = await _call_tools(runner, globex, "haltsql_query", {"query": OK_SQL})
        assert out["rows"] == [[2, "open"], [4, "paid"]]
        out = await _call_tools(runner, globex, "haltsql_query", {"query": CROSS_TENANT_SQL})
        assert_denied_cross_tenant(out)
        assert TENANT_HINT in out["message"]
        # No context in session state: refused before verification.
        empty = await _session(runner, None, "u3")
        out = await _call_tools(runner, empty, "haltsql_query", {"query": OK_SQL})
        assert out["status"] == "error" and "No trusted HaltSQL context" in out["message"]
        # A non-mapping value (e.g. written by output_key) is refused too.
        junk = await _session(runner, {"haltsql_context": "acme"}, "u4")
        out = await _call_tools(runner, junk, "haltsql_query", {"query": OK_SQL})
        assert out["status"] == "error" and out["executed"] is False

    asyncio.run(run())
    assert connections.opened == 1


def _execute_sql_tool(pg_dsn: str, executed: List[str]) -> FunctionTool:
    import psycopg

    def execute_sql(sql: str) -> dict:
        """Run SQL on the database (an existing tool that knows nothing about HaltSQL)."""
        executed.append(sql)
        with psycopg.connect(pg_dsn) as c:
            return {"rows": [list(r) for r in c.execute(sql).fetchall()]}

    return FunctionTool(execute_sql)


@pytest.mark.integration
@pytest.mark.parametrize("style", ["callback", "plugin"])
def test_guard_wraps_existing_sql_tool(style, haltsql_cli, pg_dsn):
    from google.adk.agents import LlmAgent
    from haltsql import LocalVerifier

    executed: List[str] = []
    verifier = LocalVerifier(LITERAL_POLICY, binary=haltsql_cli)
    sql_tool = _execute_sql_tool(pg_dsn, executed)
    if style == "callback":
        agent = LlmAgent(name="db_agent", model="gemini-2.5-flash", tools=[sql_tool],
                         before_tool_callback=haltsql_before_tool_callback(verifier))
        runner = InMemoryRunner(agent=agent, app_name=APP)
    else:
        agent = LlmAgent(name="db_agent", model="gemini-2.5-flash", tools=[sql_tool])
        runner = InMemoryRunner(agent=agent, app_name=APP, plugins=[HaltSQLGuardPlugin(verifier)])
    ok = "SELECT id FROM orders WHERE tenant_id = 'acme' ORDER BY id LIMIT 5"
    bad = "SELECT id FROM orders WHERE tenant_id = 'globex' LIMIT 5"

    async def run() -> None:
        acme = await _session(runner, {"haltsql_context": {"tenant_id": "acme"}})
        assert await _call_tools(runner, acme, "execute_sql", {"sql": ok}) == {"rows": [[1], [3]]}
        out = await _call_tools(runner, acme, "execute_sql", {"sql": bad})
        assert out["status"] == "denied" and out["reasons"][0]["code"] == "E_TENANT_MISMATCH"
        nobody = await _session(runner, None, "u9")
        out = await _call_tools(runner, nobody, "execute_sql", {"sql": ok})
        assert "No trusted HaltSQL context" in out["message"]

    asyncio.run(run())
    assert executed == [ok]  # denied / context-less SQL never reached the tool


@pytest.mark.integration
def test_guard_refuses_bound_tenancy_for_foreign_tool(local_verifier, pg_dsn):
    from google.adk.agents import LlmAgent

    executed: List[str] = []
    agent = LlmAgent(name="db_agent", model="gemini-2.5-flash", tools=[_execute_sql_tool(pg_dsn, executed)],
                     before_tool_callback=haltsql_before_tool_callback(local_verifier))
    runner = InMemoryRunner(agent=agent, app_name=APP)

    async def run() -> None:
        s = await _session(runner, {"haltsql_context": {"tenant_id": "acme"}})
        out = await _call_tools(runner, s, "execute_sql", {"sql": OK_SQL})
        assert out["status"] == "error" and "haltsql_query" in out["message"]

    asyncio.run(run())
    assert executed == []


@pytest.mark.integration
def test_guard_refuses_whatever_it_cannot_check(haltsql_cli, pg_dsn):
    from google.adk.agents import LlmAgent
    from haltsql import LocalVerifier

    executed: List[str] = []
    verifier = LocalVerifier(LITERAL_POLICY, binary=haltsql_cli)
    sql_tool = _execute_sql_tool(pg_dsn, executed)
    agent = LlmAgent(name="db_agent", model="gemini-2.5-flash", tools=[sql_tool],
                     before_tool_callback=haltsql_before_tool_callback(verifier))
    runner = InMemoryRunner(agent=agent, app_name=APP)
    # Guarding the tool under the wrong argument name: the SQL cannot be found, so nothing may run.
    misnamed = LlmAgent(name="db_agent", model="gemini-2.5-flash", tools=[sql_tool],
                        before_tool_callback=haltsql_before_tool_callback(verifier, tools={"execute_sql": "statement"}))
    misnamed_runner = InMemoryRunner(agent=misnamed, app_name=APP)
    ok = "SELECT id FROM orders WHERE tenant_id = 'acme' ORDER BY id LIMIT 5"
    globex = "SELECT id FROM orders WHERE tenant_id = 'globex' ORDER BY id LIMIT 5"

    async def run() -> None:
        for n, junk in enumerate(("acme", {"tenant_id": 1.5}, ["tenant_id", "acme"])):
            s = await _session(runner, {"haltsql_context": junk}, f"junk{n}")
            out = await _call_tools(runner, s, "execute_sql", {"sql": ok})
            assert out["status"] == "error" and out["executed"] is False, junk
        acme = await _session(misnamed_runner, {"haltsql_context": {"tenant_id": "acme"}}, "u1")
        out = await _call_tools(misnamed_runner, acme, "execute_sql", {"sql": ok})
        assert out["status"] == "error" and out["executed"] is False

        # The tenant comes from session state: a context among the guarded tool's
        # own (model-written) arguments changes nothing.
        check = haltsql_before_tool_callback(verifier)
        acme = await _session(runner, {"haltsql_context": {"tenant_id": "acme"}}, "u2")
        tc = ToolContext(runner._new_invocation_context(acme), function_call_id="call_1")
        forged = {"sql": globex, "haltsql_context": {"tenant_id": "globex"}, "tenant_id": "globex"}
        out = await check(sql_tool, forged, tc)
        assert out["status"] == "denied" and out["reasons"][0]["code"] == "E_TENANT_MISMATCH"
        assert await check(sql_tool, {"sql": ok}, tc) is None
        for args in ({}, {"sql": None}, {"sql": 5}, {"sql": ""}, None):
            out = await check(sql_tool, args, tc)
            assert out is not None and out["status"] == "error" and out["executed"] is False, args

    asyncio.run(run())
    assert executed == []
