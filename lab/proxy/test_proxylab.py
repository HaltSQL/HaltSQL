"""Unit tests for the proxy-mode lab helpers (no database needed).

    cd lab && .venv/bin/python -m pytest proxy/test_proxylab.py
"""

from proxy.runner import context_key, decoy_params, param_count


def test_param_count():
    assert param_count("SELECT 1") == 0
    assert param_count("SELECT * FROM t WHERE a = $1 AND b = $12 OR c = $3") == 12


def test_decoy_params_send_another_tenant():
    verdict = {"bind_params": [{"param": 1, "value": "acme"}]}
    sql = "SELECT id FROM app.orders WHERE tenant_id = $1 AND id > $2 LIMIT 5"
    assert decoy_params(sql, verdict, {"tenant_id": "globex"}) == [b"globex", b"0"]


def test_decoy_params_list_values():
    verdict = {"bind_params": [{"param": 1, "value": ["a", "b"]}]}
    assert decoy_params("x = ANY($1)", verdict, {"tenant_ids": ["z"]}) == [b'{"z"}']
    assert decoy_params("x = ANY($1)", verdict, {"tenant_id": "z"}) == [b'{"z"}']


def test_context_key_is_order_independent():
    assert context_key({"b": 1, "a": "x"}) == context_key({"a": "x", "b": 1})
