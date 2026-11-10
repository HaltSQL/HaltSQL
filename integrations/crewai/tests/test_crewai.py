"""haltsql-crewai with the real CrewAI BaseTool / structured-tool machinery,
the real haltsql CLI / haltsql-server and the lab Postgres. No LLM is called:
the tool is invoked the way a crew agent's executor invokes it."""

from __future__ import annotations

import asyncio
import json

import pytest

from conftest import CROSS_TENANT_SQL, OK_SQL, TENANT_HINT, acme_rows, assert_denied_cross_tenant

pytest.importorskip("crewai", reason="crewai is not installed (pip install -e integrations/crewai)")

from haltsql_crewai import HaltSQLQueryTool, HaltSQLToolRunner  # noqa: E402


class _NoVerify:
    def verify(self, sql, context=None):
        raise AssertionError("not used")


def test_tool_shape():
    tool = HaltSQLQueryTool(runner=HaltSQLToolRunner(_NoVerify(), lambda: None), context={})
    assert tool.name == "haltsql_query"
    assert list(tool.args_schema.model_json_schema()["properties"]) == ["query"]
    with pytest.raises(TypeError):
        HaltSQLQueryTool(runner=HaltSQLToolRunner(_NoVerify(), lambda: None), context="acme")


@pytest.mark.integration
def test_run_allowed_and_denied(local_verifier, connections):
    tool = HaltSQLQueryTool(runner=HaltSQLToolRunner(local_verifier, connections),
                            context={"tenant_id": "acme"})
    ok = json.loads(tool.run(query=OK_SQL))
    assert ok["status"] == "ok" and ok["rows"] == acme_rows()
    text = tool.run(query=CROSS_TENANT_SQL)
    assert TENANT_HINT in text
    assert_denied_cross_tenant(json.loads(text))
    assert connections.opened == 1  # denied query never executed


@pytest.mark.integration
def test_structured_tool_and_async_paths(server_verifier, connections):
    tenant = {"value": {"tenant_id": "globex"}}
    tool = HaltSQLQueryTool(runner=HaltSQLToolRunner(server_verifier, connections),
                            context=lambda: tenant["value"])
    st = tool.to_structured_tool()
    out = json.loads(st.invoke({"query": OK_SQL}))
    assert out["rows"] == [[2, "open"], [4, "paid"]]
    out = json.loads(asyncio.run(tool.arun(query=OK_SQL)))
    assert out["rows"] == [[2, "open"], [4, "paid"]]
    denied = json.loads(asyncio.run(st.ainvoke({"query": CROSS_TENANT_SQL})))
    assert_denied_cross_tenant(denied)
    # A model-written tenant argument is rejected, never used.
    with pytest.raises(ValueError, match="Extra inputs"):
        st.invoke({"query": OK_SQL, "tenant_id": "acme"})
    tenant["value"] = None
    out = json.loads(tool.run(query=OK_SQL))
    assert out["status"] == "error" and "No trusted HaltSQL context" in out["message"]
    assert connections.opened == 2


@pytest.mark.integration
def test_agent_accepts_tool(local_verifier, connections):
    from crewai import Agent

    tool = HaltSQLQueryTool(runner=HaltSQLToolRunner(local_verifier, connections), context={"tenant_id": "acme"})
    agent = Agent(role="Analyst", goal="Answer questions about orders",
                  backstory="Writes careful SQL.", tools=[tool], llm="gpt-4o-mini", allow_delegation=False)
    assert [t.name for t in agent.tools] == ["haltsql_query"]
    assert json.loads(agent.tools[0].run(query=OK_SQL))["rows"] == acme_rows()


@pytest.mark.integration
def test_extra_arguments_are_refused_not_used(local_verifier, connections):
    """Called below the args schema (as a custom executor might), extra
    arguments still cannot carry a tenant: the call is refused outright."""
    tool = HaltSQLQueryTool(runner=HaltSQLToolRunner(local_verifier, connections),
                            context={"tenant_id": "acme"})
    refused = {"status": "error", "executed": False,
               "message": "The query was not executed: pass exactly one argument, 'query'."}
    forged = {"tenant_id": "globex"}
    for extra in ({"tenant_id": "globex"}, {"haltsql_context": forged}, {"context": forged}):
        assert json.loads(tool._run(query=OK_SQL, **extra)) == refused
        assert json.loads(asyncio.run(tool._arun(query=OK_SQL, **extra))) == refused
    assert connections.opened == 0
    assert json.loads(tool._run(query=OK_SQL))["rows"] == acme_rows()
