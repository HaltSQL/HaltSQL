"""Local CLI mode and the real haltsql-server: error paths and API surface."""

import os
import stat

import pytest

from haltsql import (
    HaltSQLClient,
    HaltSQLRequestError,
    HaltSQLUnavailable,
    LocalVerifier,
    QueryDenied,
)

from conftest import POLICIES_DIR

SAAS = os.path.join(POLICIES_DIR, "saas.yaml")
SQL_OK = "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10"


def test_local_missing_binary_fails_closed(tmp_path):
    with pytest.raises(HaltSQLUnavailable, match="not found"):
        LocalVerifier(SAAS, binary=str(tmp_path / "nope"))
    with pytest.raises(HaltSQLUnavailable, match="not found on PATH"):
        LocalVerifier(SAAS, binary="haltsql-definitely-not-installed")


def test_local_missing_policy_file():
    with pytest.raises(ValueError):
        LocalVerifier("/nonexistent/policy.yaml", binary="/bin/sh")


def _script(tmp_path, body: str) -> str:
    p = tmp_path / "fake-haltsql"
    p.write_text("#!/bin/sh\ncat >/dev/null\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


def test_local_nonzero_exit_fails_closed(tmp_path):
    lv = LocalVerifier(SAAS, binary=_script(tmp_path, "echo 'policy broken' >&2\nexit 2\n"))
    with pytest.raises(HaltSQLUnavailable, match="status 2: policy broken"):
        lv.verify(SQL_OK, {"tenant_id": "a"})


def test_local_forged_allow_for_other_sql_fails_closed(tmp_path):
    line = ('{"id":0,"allowed":true,"reasons":[],"shadow_reasons":[],"policy":{"name":"x","version":"v"},'
            '"statement_kind":"select","tables":[],"columns":[],"bind_params":[],"fingerprint":null,'
            '"sql_sha256":"00","elapsed_us":0}')
    lv = LocalVerifier(SAAS, binary=_script(tmp_path, f"echo '{line}'\n"))
    with pytest.raises(HaltSQLUnavailable, match="different SQL"):
        lv.verify(SQL_OK, {"tenant_id": "a"})


def test_local_wrong_line_count_fails_closed(tmp_path):
    lv = LocalVerifier(SAAS, binary=_script(tmp_path, "exit 0\n"))
    with pytest.raises(HaltSQLUnavailable, match="0 result"):
        lv.verify(SQL_OK, {"tenant_id": "a"})


def test_local_timeout_fails_closed(tmp_path):
    lv = LocalVerifier(SAAS, binary=_script(tmp_path, "sleep 5\n"), timeout=0.3)
    with pytest.raises(HaltSQLUnavailable, match="timed out"):
        lv.verify(SQL_OK, {"tenant_id": "a"})


@pytest.mark.integration
def test_local_real_cli(haltsql_cli):
    lv = LocalVerifier(SAAS, binary=haltsql_cli)
    v = lv.check(SQL_OK, {"tenant_id": "acme"})
    assert v.bind_args() == ["acme"]
    with pytest.raises(QueryDenied) as ei:
        lv.check("SELECT id FROM orders LIMIT 1", {"tenant_id": "acme"})
    assert ei.value.verdict.codes == ["E_TENANT_MISSING"]
    vs = lv.verify_many([(SQL_OK, {"tenant_id": "x"}), ("SELEC", {"tenant_id": "x"})])
    assert [v.allowed for v in vs] == [True, False]
    assert vs[1].codes == ["E_PARSE"]


@pytest.mark.integration
def test_local_policy_load_error(haltsql_cli, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("apiVersion: haltsql.dev/v1\nkind: Policy\nbogus: 1\n")
    lv = LocalVerifier(str(bad), binary=haltsql_cli)
    with pytest.raises(HaltSQLUnavailable, match="status 2"):
        lv.verify(SQL_OK, {"tenant_id": "a"})


@pytest.mark.integration
def test_real_server_api(real_server):
    with HaltSQLClient(real_server) as c:
        assert c.healthz() == {"status": "ok"}
        ready = c.readyz()
        assert ready["status"] == "ready" and ready["policies"] >= 5
        names = {p.name for p in c.policies()}
        assert {"saas", "hierarchical", "composite"} <= names
        v = c.check(SQL_OK, {"tenant_id": "acme"}, policy="saas", request_id="py-req-1")
        assert v.bind_args() == ["acme"]
        assert v.request_id == "py-req-1"
        with pytest.raises(HaltSQLRequestError) as ei:
            c.verify(SQL_OK, {"tenant_id": "acme"}, policy="no-such-policy")
        assert ei.value.status == 404 and ei.value.code == "POLICY_NOT_FOUND"
