"""haltsql-openai-agents against the real openai-agents SDK objects, the real
haltsql CLI / haltsql-server and the lab Postgres. No model is called: tool
calls go through the SDK's own function-tool executor (approvals, guardrails,
hooks) with a ResponseFunctionToolCall, as the Runner would after a model turn."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

import pytest

from conftest import CROSS_TENANT_SQL, OK_SQL, ROOT, TENANT_HINT, acme_rows, assert_denied_cross_tenant

agents = pytest.importorskip("agents", reason="openai-agents is not installed (pip install -e integrations/openai_agents)")

from agents import Agent, RunConfig, RunContextWrapper, RunHooks, function_tool  # noqa: E402
from agents.tool_context import ToolContext  # noqa: E402
from openai.types.responses import ResponseFunctionToolCall  # noqa: E402

from haltsql_openai_agents import (  # noqa: E402
    TOOL_NAME,
    HaltSQLToolRunner,
    haltsql_query_tool,
    haltsql_tool_input_guardrail,
)

LITERAL_POLICY = os.path.join(ROOT, "test", "fixtures", "policies", "saas_literal.yaml")


@dataclass
class AppContext:
    """What the application passes as Runner.run(..., context=...)."""

    user_id: str
    haltsql_context: Dict[str, Any] = field(default_factory=dict)


async def _execute_via_sdk(agent: Any, tool: Any, app_ctx: Any, args: Dict[str, Any]) -> List[Any]:
    """Run one tool call through the SDK's function-tool executor."""
    from agents.run_internal.agent_bindings import bind_public_agent
    from agents.run_internal.run_steps import ToolRunFunction
    from agents.run_internal.tool_execution import execute_function_tool_calls

    call = ResponseFunctionToolCall(type="function_call", call_id="call_1", name=tool.name,
                                    arguments=json.dumps(args))
    results, in_guard, _out_guard = await execute_function_tool_calls(
        bindings=bind_public_agent(agent),
        tool_runs=[ToolRunFunction(tool_call=call, function_tool=tool)],
        hooks=RunHooks(),
        context_wrapper=RunContextWrapper(context=app_ctx),
        config=RunConfig(tracing_disabled=True),
    )
    return [results, in_guard]


def _tool_ctx(app_ctx: Any, args: Dict[str, Any], name: str = TOOL_NAME) -> ToolContext:
    return ToolContext(context=app_ctx, tool_name=name, tool_call_id="call_1", tool_arguments=json.dumps(args))


def test_tool_schema_has_only_the_query():
    def connect():
        raise AssertionError("not used")

    class V:
        def verify(self, sql, context=None):
            raise AssertionError("not used")

    tool = haltsql_query_tool(HaltSQLToolRunner(V(), connect))
    assert tool.name == "haltsql_query"
    assert tool.params_json_schema["properties"].keys() == {"query"}
    assert tool.params_json_schema["additionalProperties"] is False
    assert tool.strict_json_schema is True


@pytest.mark.integration
def test_allowed_and_denied_through_sdk_executor(local_verifier, connections):
    tool = haltsql_query_tool(HaltSQLToolRunner(local_verifier, connections))
    agent = Agent(name="analyst", instructions="Answer with SQL.", tools=[tool])
    app = AppContext(user_id="u1", haltsql_context={"tenant_id": "acme"})

    results, _ = asyncio.run(_execute_via_sdk(agent, tool, app, {"query": OK_SQL}))
    out = json.loads(results[0].output)
    assert out["status"] == "ok" and out["rows"] == acme_rows()
    assert connections.opened == 1

    results, _ = asyncio.run(_execute_via_sdk(agent, tool, app, {"query": CROSS_TENANT_SQL}))
    denied = json.loads(results[0].output)
    assert_denied_cross_tenant(denied)
    assert TENANT_HINT in results[0].output
    assert connections.opened == 1  # the denied query never reached the database


@pytest.mark.integration
def test_tenant_comes_from_run_context_not_arguments(local_verifier, connections):
    tool = haltsql_query_tool(HaltSQLToolRunner(local_verifier, connections))
    globex = AppContext(user_id="u2", haltsql_context={"tenant_id": "globex"})
    out = json.loads(asyncio.run(tool.on_invoke_tool(_tool_ctx(globex, {"query": OK_SQL}),
                                                     json.dumps({"query": OK_SQL}))))
    assert out["rows"] == [[2, "open"], [4, "paid"]]
    # Extra model-supplied arguments (e.g. a tenant) are refused, not used.
    raw = json.dumps({"query": OK_SQL, "tenant_id": "acme"})
    out = json.loads(asyncio.run(tool.on_invoke_tool(_tool_ctx(globex, {}), raw)))
    assert out["status"] == "error" and out["executed"] is False
    # No context in the run: refused before verification.
    out = json.loads(asyncio.run(tool.on_invoke_tool(_tool_ctx(None, {}), json.dumps({"query": OK_SQL}))))
    assert out["status"] == "error" and "No trusted HaltSQL context" in out["message"]
    out = json.loads(asyncio.run(tool.on_invoke_tool(_tool_ctx(AppContext("u3", {}), {}),
                                                     json.dumps({"query": OK_SQL}))))
    assert out["status"] == "denied"  # empty context: the policy has no tenant to bind
    assert connections.opened == 1


@pytest.mark.integration
def test_custom_context_from(server_verifier, connections):
    tool = haltsql_query_tool(HaltSQLToolRunner(server_verifier, connections),
                              context_from=lambda app: {"tenant_id": app["tenant"]})
    out = json.loads(asyncio.run(tool.on_invoke_tool(_tool_ctx({"tenant": "acme"}, {}),
                                                     json.dumps({"query": OK_SQL}))))
    assert out["rows"] == acme_rows()


@pytest.mark.integration
def test_tool_input_guardrail_on_existing_sql_tool(haltsql_cli, pg_dsn):
    import psycopg
    from haltsql import LocalVerifier

    executed: List[str] = []
    guard = haltsql_tool_input_guardrail(LocalVerifier(LITERAL_POLICY, binary=haltsql_cli), sql_arg="sql")

    @function_tool(tool_input_guardrails=[guard])
    def run_sql(sql: str) -> str:
        """Run SQL (an existing tool that knows nothing about HaltSQL)."""
        executed.append(sql)
        with psycopg.connect(pg_dsn) as c:
            return json.dumps(c.execute(sql).fetchall())

    agent = Agent(name="analyst", tools=[run_sql])
    app = AppContext(user_id="u1", haltsql_context={"tenant_id": "acme"})
    ok = "SELECT id FROM orders WHERE tenant_id = 'acme' ORDER BY id LIMIT 5"
    results, guards = asyncio.run(_execute_via_sdk(agent, run_sql, app, {"sql": ok}))
    assert json.loads(results[0].output) == [[1], [3]]
    assert guards[0].output.behavior["type"] == "allow"

    bad = "SELECT id FROM orders WHERE tenant_id = 'globex' LIMIT 5"
    results, guards = asyncio.run(_execute_via_sdk(agent, run_sql, app, {"sql": bad}))
    assert guards[0].output.behavior["type"] == "reject_content"
    rejected = json.loads(results[0].output)
    assert rejected["status"] == "denied" and rejected["reasons"][0]["code"] == "E_TENANT_MISMATCH"
    assert executed == [ok]  # the denied SQL never reached the tool

    # No context in the run: rejected too.
    results, _ = asyncio.run(_execute_via_sdk(agent, run_sql, AppContext("u2"), {"sql": ok}))
    assert json.loads(results[0].output)["status"] == "denied"  # {} context: tenant missing
    results, _ = asyncio.run(_execute_via_sdk(agent, run_sql, None, {"sql": ok}))
    assert "No trusted" in json.loads(results[0].output)["message"]
    assert executed == [ok]


@pytest.mark.integration
def test_guardrail_refuses_bound_tenancy_for_foreign_tool(local_verifier):
    guard = haltsql_tool_input_guardrail(local_verifier)

    @function_tool(tool_input_guardrails=[guard])
    def run_sql(query: str) -> str:
        """Never reached."""
        raise AssertionError("must not run")

    agent = Agent(name="a", tools=[run_sql])
    app = AppContext(user_id="u1", haltsql_context={"tenant_id": "acme"})
    results, _ = asyncio.run(_execute_via_sdk(agent, run_sql, app, {"query": OK_SQL}))
    out = json.loads(results[0].output)
    assert out["status"] == "error" and "haltsql_query" in out["message"]
