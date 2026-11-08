"""haltsql-semantic-kernel with a real Kernel, the real haltsql CLI /
haltsql-server and the lab Postgres. No model is called: function calls go
through Kernel.invoke and Kernel.invoke_function_call (the path SK's automatic
function calling uses) with a FunctionCallContent like a model would send."""

from __future__ import annotations

import asyncio
import contextvars
import json
from typing import Any, Dict, Optional

import pytest

from conftest import CROSS_TENANT_SQL, OK_SQL, TENANT_HINT, acme_rows, assert_denied_cross_tenant

pytest.importorskip("semantic_kernel", reason="semantic-kernel is not installed (pip install -e integrations/semantic_kernel)")

from semantic_kernel import Kernel  # noqa: E402
from semantic_kernel.contents import ChatHistory, FunctionCallContent, FunctionResultContent  # noqa: E402
from semantic_kernel.functions import KernelArguments  # noqa: E402

from haltsql_semantic_kernel import PLUGIN_NAME, HaltSQLPlugin, HaltSQLToolRunner  # noqa: E402

current_ctx: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar("ctx", default=None)


def _kernel(verifier: Any, connections: Any) -> Kernel:
    k = Kernel()
    k.add_plugin(HaltSQLPlugin(HaltSQLToolRunner(verifier, connections), context=current_ctx.get),
                 plugin_name=PLUGIN_NAME)
    return k


async def _invoke(k: Kernel, sql: str) -> Dict[str, Any]:
    res = await k.invoke(plugin_name=PLUGIN_NAME, function_name="query", arguments=KernelArguments(query=sql))
    return json.loads(str(res.value))


async def _function_call(k: Kernel, args: Dict[str, Any]) -> str:
    history = ChatHistory()
    call = FunctionCallContent(id="call_1", name=f"{PLUGIN_NAME}-query", arguments=json.dumps(args))
    await k.invoke_function_call(function_call=call, chat_history=history)
    results = [i for m in history.messages for i in m.items if isinstance(i, FunctionResultContent)]
    assert len(results) == 1
    return str(results[0].result)


def test_plugin_metadata():
    class V:
        def verify(self, sql, context=None):
            raise AssertionError

    k = Kernel()
    k.add_plugin(HaltSQLPlugin(HaltSQLToolRunner(V(), lambda: None), context={}), plugin_name=PLUGIN_NAME)
    fn = k.get_function(PLUGIN_NAME, "query")
    assert fn.fully_qualified_name == "haltsql-query"
    assert [p.name for p in fn.metadata.parameters] == ["query"]
    assert fn.metadata.parameters[0].is_required
    with pytest.raises(TypeError):
        HaltSQLPlugin(object(), {})  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        HaltSQLPlugin(HaltSQLToolRunner(V(), lambda: None), "acme")  # type: ignore[arg-type]


@pytest.mark.integration
def test_kernel_invoke_allowed_and_denied(local_verifier, connections):
    k = _kernel(local_verifier, connections)

    async def run() -> None:
        current_ctx.set({"tenant_id": "acme"})
        ok = await _invoke(k, OK_SQL)
        assert ok["status"] == "ok" and ok["rows"] == acme_rows()
        denied = await _invoke(k, CROSS_TENANT_SQL)
        assert_denied_cross_tenant(denied)

    asyncio.run(run())
    assert connections.opened == 1  # the denied query never ran


@pytest.mark.integration
def test_function_call_path_uses_trusted_context_only(server_verifier, connections):
    k = _kernel(server_verifier, connections)

    async def run() -> None:
        current_ctx.set({"tenant_id": "globex"})
        # A model-written tenant argument is refused by SK before the function runs.
        text = await _function_call(k, {"query": OK_SQL, "tenant_id": "acme"})
        assert "unexpected argument" in text and "tenant_id" in text
        out = json.loads(await _function_call(k, {"query": OK_SQL}))
        assert out["rows"] == [[2, "open"], [4, "paid"]]
        text = await _function_call(k, {"query": CROSS_TENANT_SQL})
        assert TENANT_HINT in text and json.loads(text)["status"] == "denied"
        current_ctx.set(None)
        out = json.loads(await _function_call(k, {"query": OK_SQL}))
        assert out["status"] == "error" and "No trusted HaltSQL context" in out["message"]

    asyncio.run(run())
    assert connections.opened == 1
