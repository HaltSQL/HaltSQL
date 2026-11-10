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


# ---- protocol violations of the CLI child fail closed ---------------------------


def _verdict_line(sql: str, rid: int = 0, **kw) -> str:
    import json

    from haltsql.testing import make_verdict_dict

    return json.dumps({"id": rid, **make_verdict_dict(sql, allowed=True, bind=["a"], **kw)})


def _echo(tmp_path, *lines: str) -> str:
    """A fake CLI that prints these lines whatever it is asked."""
    out = tmp_path / "out.jsonl"
    out.write_text("".join(line + "\n" for line in lines))
    return _script(tmp_path, f"cat '{out}'\n")


def test_local_accepts_only_one_well_formed_line_per_request(tmp_path):
    good = _verdict_line(SQL_OK)
    assert LocalVerifier(SAAS, binary=_echo(tmp_path, good)).verify(SQL_OK, {"tenant_id": "a"}).allowed
    cases = [
        ((good, good), "2 result"),                               # an extra line
        ((good, _verdict_line(SQL_OK, 1)), "2 result"),
        ((_verdict_line(SQL_OK, 7),), "out of order"),            # the id of another request
        ((_verdict_line(SQL_OK).replace('"id": 0, ', ""),), "out of order"),
        (("[]",), "out of order"),                                # not an object
        (("null",), "out of order"),
        (("this is not json",), "non-JSON"),
        ((good[: len(good) // 2],), "non-JSON"),                  # truncated output
        ((good.replace('"allowed": true', '"allowed": "yes"'),), "malformed verdict"),
        (('{"id": 0}',), "malformed verdict"),
    ]
    for lines, match in cases:
        lv = LocalVerifier(SAAS, binary=_echo(tmp_path, *lines))
        with pytest.raises(HaltSQLUnavailable, match=match):
            lv.verify(SQL_OK, {"tenant_id": "a"})
        with pytest.raises(HaltSQLUnavailable, match=match):
            lv.check(SQL_OK, {"tenant_id": "a"})


def test_local_nonzero_exit_with_a_valid_allow_on_stdout_fails_closed(tmp_path):
    out = tmp_path / "out.jsonl"
    out.write_text(_verdict_line(SQL_OK) + "\n")
    lv = LocalVerifier(SAAS, binary=_script(tmp_path, f"cat '{out}'\nexit 3\n"))
    with pytest.raises(HaltSQLUnavailable, match="status 3"):
        lv.verify(SQL_OK, {"tenant_id": "a"})


def test_local_engine_results_must_be_objects():
    from haltsql.local import _to_verdict

    for data in ([], None, "allowed", 1, True):
        with pytest.raises(HaltSQLUnavailable, match="non-object"):
            _to_verdict(data, SQL_OK, verify_sql_hash=True, source="haltsql CLI")
    with pytest.raises(HaltSQLRequestError, match="rejected the request: boom"):
        _to_verdict({"id": 0, "error": "boom"}, SQL_OK, verify_sql_hash=True, source="haltsql CLI")


def test_local_invalid_input_is_rejected_before_the_cli_runs(tmp_path):
    marker = tmp_path / "ran"
    lv = LocalVerifier(SAAS, binary=_script(tmp_path, f"touch '{marker}'\n"))
    for ctx in ({"tenant_id": 1.5}, {"tenant_id": None}, {"": "a"}, ["tenant_id"]):
        with pytest.raises(ValueError):
            lv.verify(SQL_OK, ctx)
    for sql in (None, 5, b"SELECT 1"):
        with pytest.raises(TypeError):
            lv.verify(sql, {"tenant_id": "a"})
    assert not marker.exists()


def test_local_explicit_binary_is_never_replaced_by_path_lookup(tmp_path, monkeypatch):
    """A wrong explicit path (or HALTSQL_BIN) must not silently pick up some
    other `haltsql` that happens to be on PATH."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    other = bindir / "haltsql"
    other.write_text("#!/bin/sh\nexit 0\n")
    other.chmod(other.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    with pytest.raises(HaltSQLUnavailable, match="not found or not executable"):
        LocalVerifier(SAAS, binary=str(tmp_path / "nope"))
    monkeypatch.setenv("HALTSQL_BIN", str(tmp_path / "also-nope"))
    with pytest.raises(HaltSQLUnavailable, match="not found or not executable"):
        LocalVerifier(SAAS)
    not_exec = tmp_path / "not-executable"
    not_exec.write_text("#!/bin/sh\nexit 0\n")
    with pytest.raises(HaltSQLUnavailable, match="not found or not executable"):
        LocalVerifier(SAAS, binary=str(not_exec))


async def test_async_local_fails_closed(tmp_path):
    import time

    from haltsql import AsyncLocalVerifier

    good = _verdict_line(SQL_OK)
    assert (await AsyncLocalVerifier(SAAS, binary=_echo(tmp_path, good)).verify(SQL_OK, {"tenant_id": "a"})).allowed
    for lines, match in (((good, good), "2 result"), ((), "0 result"), ((_verdict_line(SQL_OK, 3),), "out of order"),
                         (("garbage",), "non-JSON"), ((_verdict_line("SELECT 2"),), "different SQL")):
        with pytest.raises(HaltSQLUnavailable, match=match):
            await AsyncLocalVerifier(SAAS, binary=_echo(tmp_path, *lines)).verify(SQL_OK, {"tenant_id": "a"})
    failing = AsyncLocalVerifier(SAAS, binary=_script(tmp_path, "echo 'policy broken' >&2\nexit 2\n"))
    with pytest.raises(HaltSQLUnavailable, match="status 2: policy broken"):
        await failing.verify(SQL_OK, {"tenant_id": "a"})

    # A hung child is killed, not left running.
    pidfile = tmp_path / "pid"
    hung = AsyncLocalVerifier(SAAS, binary=_script(tmp_path, f"echo $$ > '{pidfile}'\nexec sleep 30\n"),
                              timeout=0.5)
    t0 = time.monotonic()
    with pytest.raises(HaltSQLUnavailable, match="timed out after 0.5s"):
        await hung.verify(SQL_OK, {"tenant_id": "a"})
    assert time.monotonic() - t0 < 5
    pid = int(pidfile.read_text())
    deadline = time.monotonic() + 5
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        assert time.monotonic() < deadline, "the timed-out CLI child is still running"
        time.sleep(0.05)


@pytest.mark.integration
async def test_async_local_real_cli(haltsql_cli):
    from haltsql import AsyncLocalVerifier

    lv = AsyncLocalVerifier(SAAS, binary=haltsql_cli)
    assert (await lv.check(SQL_OK, {"tenant_id": "acme"})).bind_args() == ["acme"]
    with pytest.raises(QueryDenied) as ei:
        await lv.check("SELECT id FROM orders LIMIT 1", {"tenant_id": "acme"})
    assert ei.value.verdict.codes == ["E_TENANT_MISSING"]
    vs = await lv.verify_many([(SQL_OK, {"tenant_id": "x"}), ("SELEC", {"tenant_id": "x"})])
    assert [v.allowed for v in vs] == [True, False]
