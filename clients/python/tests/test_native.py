"""NativeVerifier: the bundled engine in-process (libhaltsql via ctypes) and as a
long-lived CLI child. Uses the real engine: $HALTSQL_LIB / $HALTSQL_BIN or the dune
build output; skips without it unless HALTSQL_REQUIRE_NATIVE=1."""

from __future__ import annotations

import asyncio
import gc
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List

import pytest

import haltsql
from haltsql import (
    AsyncNativeVerifier,
    HaltSQLRequestError,
    HaltSQLUnavailable,
    LocalVerifier,
    NativeVerifier,
    QueryDenied,
    Verdict,
    native,
)

from conftest import POLICIES_DIR, ROOT, load_vectors

pytestmark = pytest.mark.native

VECTORS = load_vectors()
IDS = [v["name"] for v in VECTORS]
BACKENDS = ["library", "process"]
SAAS = os.path.join(POLICIES_DIR, "saas.yaml")
SAAS_JSON = os.path.join(POLICIES_DIR, "saas.json")
SQL_OK = "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10"
CTX = {"tenant_id": "acme"}


# ----------------------------------------------------------------------------- helpers


def project(verdict: Dict[str, Any], path: str) -> Any:
    """Value of a vector `compare` path: "allowed", "policy.name", "reasons[].code"."""
    cur: Any = verdict
    for part in path.split("."):
        if part.endswith("[]"):
            cur = cur.get(part[:-2], [])
            continue
        if isinstance(cur, list):
            cur = [x.get(part) for x in cur]
        else:
            cur = cur.get(part)
    return cur


def comparable_by(vec: Dict[str, Any], got: Verdict) -> Dict[str, Any]:
    raw = got.to_dict()
    return {p: project(raw, p) for p in vec["compare"]}


def expected_by(vec: Dict[str, Any]) -> Dict[str, Any]:
    return {p: project(vec["verdict"], p) for p in vec["compare"]}


def without_elapsed(v: Verdict) -> Dict[str, Any]:
    d = dict(v.to_dict())
    d.pop("elapsed_us", None)
    return d


def vec_policy(vec: Dict[str, Any]) -> str:
    return os.path.join(ROOT, vec["policy_file"])


@pytest.fixture(params=BACKENDS)
def backend(request, native_env):
    return request.param


@pytest.fixture
def saas(backend):
    with NativeVerifier(SAAS, backend=backend) as v:
        yield v


# ----------------------------------------------------------------------------- vectors


@pytest.mark.parametrize("vec", VECTORS, ids=IDS)
def test_vectors_conform(backend, vec):
    with NativeVerifier(vec_policy(vec), backend=backend) as v:
        assert v.backend == backend
        req = vec["request"]
        got = v.verify(req["sql"], req["context"])
    assert comparable_by(vec, got) == expected_by(vec)
    assert got.matches_sql(req["sql"])


def test_backends_and_local_cli_identical(native_env):
    by_policy: Dict[str, List[Dict[str, Any]]] = {}
    for vec in VECTORS:
        by_policy.setdefault(vec["policy_file"], []).append(vec)
    for policy_file, vecs in by_policy.items():
        path = os.path.join(ROOT, policy_file)
        items = [(v["request"]["sql"], v["request"]["context"]) for v in vecs]
        with NativeVerifier(path, backend="library") as lib, NativeVerifier(
            path, backend="process"
        ) as proc:
            a = [without_elapsed(x) for x in lib.verify_many(items)]
            b = [without_elapsed(x) for x in proc.verify_many(items)]
        c = [without_elapsed(x) for x in LocalVerifier(path, binary=native_env["bin"]).verify_many(items)]
        assert a == b == c, policy_file


def test_policy_info_matches_across_backends(native_env):
    infos = []
    for name in ("saas.yaml", "shadow.yaml"):
        p = os.path.join(POLICIES_DIR, name)
        with NativeVerifier(p, backend="library") as a, NativeVerifier(p, backend="process") as b:
            assert a.policy_info() == b.policy_info()
            infos.append(a.policy_info())
    assert infos[0]["name"] == "saas" and infos[0]["mode"] == "enforce"
    assert infos[0]["version"].startswith("sha256:")
    assert infos[1]["name"] == "shadow" and infos[1]["mode"] == "shadow"


# ----------------------------------------------------------------------------- policies


@pytest.mark.parametrize("fmt,path", [("yaml", SAAS), ("json", SAAS_JSON)])
def test_in_memory_policy_matches_file(backend, fmt, path):
    with open(path, encoding="utf-8") as f:
        doc = f.read()
    with NativeVerifier(
        policy=doc, policy_format=fmt, base_dir=POLICIES_DIR, backend=backend
    ) as mem, NativeVerifier(
        path, backend=backend
    ) as disk:
        assert mem.policy_info() == disk.policy_info()
        for sql in (SQL_OK, "SELECT id FROM orders LIMIT 1", "DELETE FROM orders"):
            assert without_elapsed(mem.verify(sql, CTX)) == without_elapsed(disk.verify(sql, CTX))
        assert mem.policy_file is None
        assert "in-memory " + fmt in repr(mem)


def test_in_memory_relative_catalog_resolves_against_base_dir(backend, monkeypatch):
    with open(SAAS, encoding="utf-8") as f:
        doc = f.read()
    assert "catalog: ../catalogs/saas.json" in doc
    # default base_dir: the current directory
    monkeypatch.chdir(POLICIES_DIR)
    with NativeVerifier(policy=doc, backend=backend) as v:
        assert v.policy_info()["name"] == "saas"
    monkeypatch.chdir(ROOT)
    with pytest.raises(ValueError, match="cannot load catalog snapshot"):
        NativeVerifier(policy=doc, backend=backend)


def test_process_in_memory_temp_file_removed_on_close(native_env):
    with open(SAAS, encoding="utf-8") as f:
        v = NativeVerifier(policy=f.read(), base_dir=POLICIES_DIR, backend="process")
    tmp = v._impl.policy_file
    assert os.path.isfile(tmp)
    assert stat.S_IMODE(os.stat(tmp).st_mode) == 0o600
    v.close()
    assert not os.path.exists(tmp)
    assert not os.path.exists(os.path.dirname(tmp))


@pytest.mark.parametrize("doc", ["tables: [", "kind: Policy\napiVersion: haltsql.dev/v1\n"])
def test_invalid_policy_raises_value_error(backend, doc):
    with pytest.raises(ValueError, match="cannot load policy"):
        NativeVerifier(policy=doc, backend=backend)


def test_invalid_policy_file_raises_value_error(backend, tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("tables: [\n")
    with pytest.raises(ValueError, match="YAML syntax error"):
        NativeVerifier(str(p), backend=backend)


def test_missing_policy_file(backend):
    with pytest.raises(ValueError, match="policy file not found"):
        NativeVerifier("/nonexistent/policy.yaml", backend=backend)


def test_argument_validation(native_env):
    with pytest.raises(ValueError, match="exactly one"):
        NativeVerifier()
    with pytest.raises(ValueError, match="exactly one"):
        NativeVerifier(SAAS, policy="x")
    with pytest.raises(ValueError, match="policy_format"):
        NativeVerifier(policy="x", policy_format="toml")
    with pytest.raises(TypeError):
        NativeVerifier(policy=b"bytes")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="backend"):
        NativeVerifier(SAAS, backend="gpu")
    with pytest.raises(ValueError, match="timeout"):
        NativeVerifier(SAAS, timeout=0)
    # "yml" is accepted as yaml
    with open(SAAS, encoding="utf-8") as f:
        NativeVerifier(
            policy=f.read(), policy_format="yml", base_dir=POLICIES_DIR, backend="library"
        ).close()


def test_library_load_string_rejects_bad_format(native_env):
    lib = native.load_library()
    with pytest.raises(ValueError, match="format"):
        lib.load_string("{}", "toml", None)


# ----------------------------------------------------------------------------- requests


def test_verify_check_verify_many(saas):
    v = saas.check(SQL_OK, CTX)
    assert v.allowed and v.bind_args() == ["acme"]
    with pytest.raises(QueryDenied) as ei:
        saas.check("SELECT id FROM orders LIMIT 1", CTX)
    assert ei.value.verdict.codes == ["E_TENANT_MISSING"]
    vs = saas.verify_many([(SQL_OK, CTX), ("SELEC", CTX)])
    assert [x.allowed for x in vs] == [True, False]
    assert vs[1].codes == ["E_PARSE"]
    assert saas.verify_many([]) == []


def test_library_results_are_validated(native_env, monkeypatch):
    """Whatever libhaltsql hands back is checked like any other engine's answer."""
    import json

    from haltsql.testing import make_verdict_dict

    with NativeVerifier(SAAS, backend="library") as v:
        assert v.verify(SQL_OK, CTX).allowed
        real = v._impl.lib.verify
        allow_other = json.dumps(make_verdict_dict("SELECT 1", allowed=True))
        cases = [
            (None, "no result"),
            ("this is not json", "non-JSON"),
            ("[]", "non-object"),
            ('{"allowed": true}', "malformed verdict"),
            (allow_other, "different SQL"),
        ]
        for raw, match in cases:
            monkeypatch.setattr(v._impl.lib, "verify", lambda *a, _raw=raw: _raw)
            with pytest.raises(HaltSQLUnavailable, match=match):
                v.verify(SQL_OK, CTX)
        monkeypatch.setattr(v._impl.lib, "verify", lambda *a: '{"error": "bad request"}')
        with pytest.raises(HaltSQLRequestError, match="bad request"):
            v.verify(SQL_OK, CTX)
        monkeypatch.setattr(v._impl.lib, "verify", real)
        assert v.verify(SQL_OK, CTX).allowed


@pytest.mark.parametrize(
    "ctx",
    [{"tenant_id": True}, {"tenant_id": 1.5}, {"": "x"}, {1: "x"}, ["tenant_id"], {"t": [None]}],
)
def test_invalid_context_rejected_before_engine(saas, ctx):
    with pytest.raises(ValueError):
        saas.verify(SQL_OK, ctx)


def test_verify_many_validates_everything_first(saas):
    with pytest.raises(ValueError):
        saas.verify_many([(SQL_OK, CTX), (SQL_OK, {"tenant_id": True})])
    with pytest.raises(TypeError):
        saas.verify_many([(SQL_OK, CTX), (b"SELECT 1", CTX)])  # type: ignore[list-item]


@pytest.mark.parametrize("sql", [b"SELECT 1", None, 42])
def test_non_str_sql(saas, sql):
    with pytest.raises(TypeError, match="sql must be a str"):
        saas.verify(sql)  # type: ignore[arg-type]


def test_nul_byte_is_denied_not_truncated(saas):
    prefix = SQL_OK
    assert saas.verify(prefix, CTX).allowed  # the truncated string alone would pass
    sql = prefix + "\x00; DROP TABLE x"
    v = saas.verify(sql, CTX)
    assert v.allowed is False
    assert v.codes == ["E_PARSE"]
    assert v.sql_sha256 == hashlib.sha256(sql.encode("utf-8")).hexdigest()
    assert v.sql_sha256 != hashlib.sha256(prefix.encode("utf-8")).hexdigest()


def test_nul_in_context_value(saas):
    v = saas.verify(SQL_OK, {"tenant_id": "ac\x00me"})
    if v.allowed:  # the bound value must be the full string, never a truncation
        assert v.bind_args() == ["ac\x00me"]


@pytest.mark.parametrize("sql", ["", "   ", "\n\t"])
def test_empty_sql_denied(saas, sql):
    v = saas.verify(sql, CTX)
    assert not v.allowed and v.codes == ["E_EMPTY"]


def test_oversized_sql_denied(saas):
    sql = "SELECT id FROM orders WHERE tenant_id = $1 AND status = '" + "x" * 17000 + "' LIMIT 10"
    assert len(sql.encode()) > 16384
    v = saas.verify(sql, CTX)
    assert not v.allowed and v.codes == ["E_LIMIT"]
    assert v.matches_sql(sql)


def test_unicode(saas):
    sql = "SELECT id FROM orders WHERE tenant_id = $1 AND status = 'héllo 😀 ✓' LIMIT 10"
    v = saas.verify(sql, {"tenant_id": "ünï-😀"})
    assert v.allowed and v.bind_args() == ["ünï-😀"]
    assert v.matches_sql(sql)


def test_lone_surrogate_sql_raises(saas):
    with pytest.raises(UnicodeEncodeError):
        saas.verify("SELECT '\ud800'", CTX)


# ----------------------------------------------------------------------------- concurrency

CASES = [
    (SQL_OK, {"tenant_id": "acme"}, True),
    ("SELECT id FROM orders LIMIT 1", {"tenant_id": "acme"}, False),
    ("SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50", {"tenant_id": "globex"}, True),
    ("DELETE FROM orders", {"tenant_id": "acme"}, False),
    ("SELEC", {"tenant_id": "acme"}, False),
]


def _check_case(v: NativeVerifier, i: int) -> None:
    sql, ctx, allowed = CASES[i % len(CASES)]
    got = v.verify(sql, ctx)
    assert got.allowed is allowed
    assert got.matches_sql(sql)
    if allowed:
        assert got.bind_args() == [ctx["tenant_id"]]


def test_threads_share_one_verifier(saas):
    n = 300 if saas.backend == "library" else 60

    def worker(t: int) -> int:
        for i in range(n):
            _check_case(saas, t + i)
        return n

    with ThreadPoolExecutor(16) as ex:
        assert sum(ex.map(worker, range(16))) == 16 * n


def test_threads_many_verifiers_with_load_and_close(native_env):
    errors: List[BaseException] = []

    def worker(t: int) -> None:
        try:
            for round_ in range(4):
                backend = "process" if (t + round_) % 4 == 0 else "library"
                with NativeVerifier(SAAS if t % 2 else SAAS_JSON, backend=backend) as v:
                    for i in range(40):
                        _check_case(v, t + i)
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(16)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(120)
    assert not errors, errors[:3]


def test_close_while_other_threads_verify(native_env):
    """close() racing with verify(): every call either returns a correct verdict or
    raises HaltSQLUnavailable; nothing crashes and nothing is wrongly allowed."""
    for _ in range(5):
        v = NativeVerifier(SAAS, backend="library")
        stop = threading.Event()
        bad: List[BaseException] = []

        def worker(t: int, v=v, stop=stop, bad=bad) -> None:
            i = 0
            while not stop.is_set():
                try:
                    _check_case(v, t + i)
                except HaltSQLUnavailable:
                    return
                except BaseException as e:  # noqa: BLE001
                    bad.append(e)
                    return
                i += 1

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
        for th in threads:
            th.start()
        time.sleep(0.02)
        v.close()
        stop.set()
        for th in threads:
            th.join(30)
        assert not bad, bad[:3]


# ----------------------------------------------------------------------------- async


async def test_async_api(backend):
    async with AsyncNativeVerifier(SAAS, backend=backend) as v:
        assert v.backend == backend
        ok = await v.check(SQL_OK, CTX)
        assert ok.bind_args() == ["acme"]
        with pytest.raises(QueryDenied):
            await v.check("SELECT id FROM orders LIMIT 1", CTX)
        many = await v.verify_many([(sql, ctx) for sql, ctx, _ in CASES])
        assert [m.allowed for m in many] == [a for _, _, a in CASES]
        assert (await v.policy_info())["name"] == "saas"
        results = await asyncio.gather(*(v.verify(*CASES[i % 5][:2]) for i in range(200)))
        assert [r.allowed for r in results] == [CASES[i % 5][2] for i in range(200)]
        with pytest.raises(TypeError):
            await v.verify(b"x")  # type: ignore[arg-type]
    assert v.closed
    with pytest.raises(HaltSQLUnavailable, match="closed"):
        await v.verify(SQL_OK, CTX)


# ----------------------------------------------------------------------------- lifecycle


def test_close_semantics(backend):
    v = NativeVerifier(SAAS, backend=backend)
    assert not v.closed
    v.close()
    v.close()  # idempotent
    assert v.closed and "closed" in repr(v)
    for call in (
        lambda: v.verify(SQL_OK, CTX),
        lambda: v.check(SQL_OK, CTX),
        lambda: v.verify_many([(SQL_OK, CTX)]),
        v.policy_info,
    ):
        with pytest.raises(HaltSQLUnavailable, match="closed"):
            call()


def test_context_manager_closes(backend):
    with NativeVerifier(SAAS, backend=backend) as v:
        assert v.verify(SQL_OK, CTX).allowed
    assert v.closed


def test_library_handle_freed_on_close_and_del(native_env):
    lib = native.load_library()
    v = NativeVerifier(SAAS, backend="library")
    h = v._impl._handle
    assert lib.policy_info(h)["name"] == "saas"
    v.close()
    assert lib.policy_info(h) is None
    # an unknown handle verifies to an error object, never a verdict
    raw = json.loads(lib.verify(h, b"SELECT 1", b""))
    assert "error" in raw

    v2 = NativeVerifier(SAAS, backend="library")
    h2 = v2._impl._handle
    assert h2 != h  # handles are never reused
    del v2
    gc.collect()
    assert lib.policy_info(h2) is None


def test_process_child_stopped_on_close(native_env):
    v = NativeVerifier(SAAS, backend="process")
    proc = v._impl._proc
    assert proc is not None and proc.poll() is None
    v.close()
    assert proc.poll() is not None


def test_repr_and_attributes(native_env):
    with NativeVerifier(SAAS, backend="library") as a, NativeVerifier(SAAS, backend="process") as b:
        assert repr(a) == f"NativeVerifier(policy_file={SAAS!r}, backend='library')"
        assert a.library_path == native_env["lib"] and a.binary is None
        assert b.binary == native_env["bin"] and b.library_path is None
        assert a.fallback_reason is None


def test_version(native_env):
    assert native.load_library().version() == haltsql.__version__


# ----------------------------------------------------------------------------- backends


def test_env_forces_process(native_env, monkeypatch):
    monkeypatch.setenv("HALTSQL_NATIVE", "0")
    with NativeVerifier(SAAS) as v:
        assert v.backend == "process"
    # an explicit backend argument wins over the environment
    with NativeVerifier(SAAS, backend="library") as v:
        assert v.backend == "library"


def test_env_forces_library(native_env, monkeypatch):
    monkeypatch.setenv("HALTSQL_NATIVE", "library")
    with NativeVerifier(SAAS) as v:
        assert v.backend == "library"
    monkeypatch.setenv("HALTSQL_LIB", "/nonexistent/libhaltsql.so")
    with pytest.raises(HaltSQLUnavailable, match="not found"):
        NativeVerifier(SAAS)


def test_env_bad_value(native_env, monkeypatch):
    monkeypatch.setenv("HALTSQL_NATIVE", "maybe")
    with pytest.raises(ValueError, match="HALTSQL_NATIVE"):
        NativeVerifier(SAAS)


def test_auto_prefers_library(native_env):
    with NativeVerifier(SAAS) as v:
        assert v.backend == "library"


@pytest.mark.parametrize("kind", ["missing", "not_a_library"])
def test_bad_lib_auto_falls_back_library_forced_raises(native_env, monkeypatch, tmp_path, kind):
    if kind == "missing":
        bad = str(tmp_path / "libhaltsql.so")
    else:
        p = tmp_path / "libhaltsql.so"
        p.write_bytes(b"this is not a shared library")
        bad = str(p)
    monkeypatch.setenv("HALTSQL_LIB", bad)
    with NativeVerifier(SAAS) as v:
        assert v.backend == "process"
        assert v.fallback_reason
        assert v.verify(SQL_OK, CTX).allowed
    with pytest.raises(HaltSQLUnavailable):
        NativeVerifier(SAAS, backend="library")


def test_wrong_library_symbol(native_env):
    import _ctypes  # a real shared library on disk that is not libhaltsql

    path = getattr(_ctypes, "__file__", None)
    if not path or not os.path.isfile(path):
        pytest.skip("_ctypes is built into this interpreter")
    with pytest.raises(HaltSQLUnavailable, match="not libhaltsql"):
        native.load_library(path)


def test_abi_mismatch(native_env, monkeypatch):
    monkeypatch.setattr(native, "ABI_VERSION", 999)
    monkeypatch.setattr(native, "_LIBS", {})
    with pytest.raises(HaltSQLUnavailable, match="ABI version 1"):
        NativeVerifier(SAAS, backend="library")
    with NativeVerifier(SAAS) as v:
        assert v.backend == "process"
        assert "ABI" in v.fallback_reason


def test_nothing_available(monkeypatch, tmp_path):
    monkeypatch.setenv("HALTSQL_LIB", str(tmp_path / "nope.so"))
    monkeypatch.setenv("HALTSQL_BIN", str(tmp_path / "nope"))
    monkeypatch.delenv("HALTSQL_NATIVE", raising=False)
    with pytest.raises(HaltSQLUnavailable, match="no HaltSQL engine available.*platform wheel"):
        NativeVerifier(SAAS)
    with pytest.raises(HaltSQLUnavailable, match="not found"):
        NativeVerifier(SAAS, backend="process")


def test_load_library_cached(native_env):
    assert native.load_library() is native.load_library(native_env["lib"])


# ----------------------------------------------------------------------------- fork


@pytest.mark.skipif(not hasattr(os, "fork"), reason="no fork()")
def test_fork_after_library_use_raises_in_child(native_env):
    v = NativeVerifier(SAAS, backend="library")
    assert v.verify(SQL_OK, CTX).allowed
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # multi-threaded fork warning
        pid = os.fork()
    if pid == 0:  # child: never return into pytest
        code = 1
        try:
            try:
                v.verify(SQL_OK, CTX)
                code = 2  # must not work
            except HaltSQLUnavailable as e:
                code = 3 if "fork" not in str(e) else 0
            if code == 0:
                try:
                    NativeVerifier(SAAS, backend="library")
                    code = 4
                except HaltSQLUnavailable:
                    pass
            if code == 0:
                # auto falls back to the process backend in the child
                with NativeVerifier(SAAS) as w:
                    if w.backend != "process" or not w.verify(SQL_OK, CTX).allowed:
                        code = 5
        except BaseException:  # noqa: BLE001
            code = 6
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, os.WEXITSTATUS(status)
    # the parent is unaffected, and close() in the parent still frees the handle
    assert v.verify(SQL_OK, CTX).allowed
    v.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="no fork()")
def test_fork_child_close_keeps_parent_temp_policy(native_env):
    """A forked child closing its copy of an in-memory-policy verifier must not delete
    the parent's temp policy file (the parent's engine respawns from it)."""
    with open(SAAS, encoding="utf-8") as f:
        v = NativeVerifier(policy=f.read(), base_dir=POLICIES_DIR, backend="process")
    tmp = v._impl.policy_file
    assert v.verify(SQL_OK, CTX).allowed
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        pid = os.fork()
    if pid == 0:
        try:
            v.close()
            code = 0
        except BaseException:  # noqa: BLE001
            code = 1
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    assert os.path.isfile(tmp), "child deleted the parent's temp policy file"
    # Force a respawn in the parent: it must still find its policy file.
    os.kill(v._impl.child_pid(), 9)
    v._impl._proc.wait()
    assert v.verify(SQL_OK, CTX).allowed
    v.close()
    assert not os.path.exists(tmp)


# ----------------------------------------------------------------------------- process backend resilience


def test_process_child_killed_between_requests_respawns(native_env):
    with NativeVerifier(SAAS, backend="process") as v:
        first = v._impl.child_pid()
        v._impl._proc.kill()
        v._impl._proc.wait()
        # documented: a child found dead before a request is sent is replaced transparently
        assert v.verify(SQL_OK, CTX).allowed
        second = v._impl.child_pid()
        assert second and second != first
        assert v.verify(SQL_OK, CTX).allowed


def test_process_child_killed_mid_request_raises_then_recovers(native_env):
    with NativeVerifier(SAAS, backend="process") as v:
        proc = v._impl._proc
        # Kill the child just after the request is written: the in-flight call must fail.
        real_write = v._impl._write

        def write_then_kill(p, data, deadline):
            real_write(p, data, deadline)
            os.kill(p.pid, signal.SIGKILL)

        v._impl._write = write_then_kill
        with pytest.raises(HaltSQLUnavailable, match="exited"):
            v.verify(SQL_OK, CTX)
        v._impl._write = real_write
        assert proc.poll() is not None
        assert v.verify(SQL_OK, CTX).allowed


FAKE = r'''
import hashlib, json, sys, time
argv = sys.argv[1:]
policy = argv[argv.index("--policy") + 1]
if "STARTUP_HANG" in policy:
    time.sleep(3600)
if "STARTUP_BAD" in policy:
    sys.stderr.write("haltsql: cannot load policy:\nfake: broken\n"); sys.exit(2)
if "STARTUP_CRASH" in policy:
    sys.stderr.write("segfault-ish\n"); sys.exit(139)
for line in sys.stdin:
    req = json.loads(line)
    sql, rid = req["sql"], req["id"]
    sha = hashlib.sha256(sql.encode("utf-8")).hexdigest()
    probe = sql == "\x00"
    denied = probe and "ALLOWS_PROBE" not in policy
    out = {"id": rid, "allowed": not denied,
           "reasons": [{"code": "E_PARSE", "message": "nul", "rule": "parse"}] if denied else [],
           "shadow_reasons": [], "policy": {"name": "fake", "version": "sha256:00"},
           "statement_kind": None if probe else "select", "tables": [], "columns": [],
           "bind_params": [], "fingerprint": None, "sql_sha256": sha, "elapsed_us": 1}
    if "HANG" in sql:
        time.sleep(3600)
    if "GARBAGE" in sql:
        sys.stdout.write("this is not json\n"); sys.stdout.flush(); continue
    if "WRONG_ID" in sql:
        out["id"] = rid + 1000
    if "WRONG_SHA" in sql:
        out["sql_sha256"] = "00" * 32
    if "MALFORMED" in sql:
        out["allowed"] = "yes"
    if "ERROR" in sql:
        out = {"id": rid, "error": "fake rejection"}
    if "DIE" in sql:
        sys.exit(3)
    if "TWO_LINES" in sql:
        # One write: both lines reach the pipe together even with PYTHONUNBUFFERED=1.
        sys.stdout.write(json.dumps(out) + "\n" + json.dumps(out) + "\n"); sys.stdout.flush(); continue
    if "LATE_LINE" in sql:
        sys.stdout.write(json.dumps(out) + "\n"); sys.stdout.flush(); time.sleep(0.2)
    if "PARTIAL" in sql:
        sys.stdout.write(json.dumps(out)[:20]); sys.stdout.flush(); time.sleep(3600)
    sys.stdout.write(json.dumps(out) + "\n"); sys.stdout.flush()
'''


@pytest.fixture
def fake_bin(tmp_path):
    p = tmp_path / "fake-haltsql"
    p.write_text(f"#!{sys.executable}\n" + FAKE)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


def _policy(tmp_path, name="policy.yaml") -> str:
    p = tmp_path / name
    p.write_text("# fake\n")
    return str(p)


def _fake(fake_bin, tmp_path, timeout=5.0) -> NativeVerifier:
    return NativeVerifier(_policy(tmp_path), backend="process", binary=fake_bin, timeout=timeout)


def test_fake_child_happy_path(fake_bin, tmp_path):
    with _fake(fake_bin, tmp_path) as v:
        assert v.policy_info() == {"name": "fake", "version": "sha256:00", "mode": "enforce"}
        assert v.verify("SELECT 1").allowed


@pytest.mark.parametrize(
    "sql,match",
    [
        ("GARBAGE", "non-JSON"),
        ("WRONG_ID", "different request"),
        ("WRONG_SHA", "different SQL"),
        ("MALFORMED", "malformed verdict"),
        ("DIE", "exited.*status 3"),
        ("TWO_LINES", "more than one line"),
    ],
)
def test_fake_child_misbehaves_fails_closed_and_recovers(fake_bin, tmp_path, sql, match):
    with _fake(fake_bin, tmp_path) as v:
        before = v._impl.child_pid()
        with pytest.raises(HaltSQLUnavailable, match=match):
            v.verify(sql)
        # a verdict that only fails the SHA check leaves a healthy child; everything
        # else means the child is untrustworthy and has been killed
        if sql != "WRONG_SHA" and sql != "MALFORMED":
            assert v._impl.child_pid() is None
        assert v.verify("SELECT 1").allowed
        if sql not in ("WRONG_SHA", "MALFORMED"):
            assert v._impl.child_pid() != before


def test_fake_child_late_extra_line_is_never_the_next_answer(fake_bin, tmp_path):
    """An extra line that arrives after the answer was read cannot be detected at
    once. It must not be taken as the answer to the next request: that request
    fails closed, the child is replaced, and the one after works."""
    with _fake(fake_bin, tmp_path) as v:
        assert v.verify("LATE_LINE").allowed
        before = v._impl.child_pid()
        with pytest.raises(HaltSQLUnavailable, match="different request|more than one line"):
            v.verify("SELECT 2")
        assert v._impl.child_pid() is None
        assert v.verify("SELECT 2").allowed
        assert v._impl.child_pid() != before


def test_fake_child_line_without_end_is_capped(fake_bin, tmp_path, monkeypatch):
    """Output that never ends its line is cut off at the cap, not buffered without limit."""
    monkeypatch.setattr(native, "_MAX_LINE", 8)
    with _fake(fake_bin, tmp_path, timeout=5.0) as v:
        t0 = time.monotonic()
        with pytest.raises(HaltSQLUnavailable, match="oversized line"):
            v.verify("PARTIAL")
        assert time.monotonic() - t0 < 3  # refused at the cap, well before the timeout


def test_fake_child_error_object(fake_bin, tmp_path):
    with _fake(fake_bin, tmp_path) as v:
        pid = v._impl.child_pid()
        with pytest.raises(HaltSQLRequestError) as ei:
            v.verify("ERROR")
        assert ei.value.status == 400 and ei.value.code == "BAD_REQUEST"
        assert v._impl.child_pid() == pid  # a well-formed rejection keeps the child
        assert v.verify("SELECT 1").allowed


@pytest.mark.parametrize("sql", ["HANG", "PARTIAL"])
def test_fake_child_timeout(fake_bin, tmp_path, sql):
    with _fake(fake_bin, tmp_path, timeout=0.5) as v:
        t0 = time.monotonic()
        with pytest.raises(HaltSQLUnavailable, match="timed out after 0.5s"):
            v.verify(sql)
        assert time.monotonic() - t0 < 3
        assert v.verify("SELECT 1").allowed  # respawned


def test_fake_child_hangs_at_startup(fake_bin, tmp_path):
    t0 = time.monotonic()
    with pytest.raises(HaltSQLUnavailable, match="timed out"):
        NativeVerifier(
            _policy(tmp_path, "STARTUP_HANG.yaml"), backend="process", binary=fake_bin, timeout=0.5
        )
    assert time.monotonic() - t0 < 3


def test_fake_child_bad_policy_is_value_error(fake_bin, tmp_path):
    with pytest.raises(ValueError, match="cannot load policy:\nfake: broken"):
        NativeVerifier(_policy(tmp_path, "STARTUP_BAD.yaml"), backend="process", binary=fake_bin)


def test_fake_child_that_allows_the_probe_is_refused(fake_bin, tmp_path):
    """An engine that allows SQL containing a NUL byte is not a HaltSQL engine."""
    with pytest.raises(HaltSQLUnavailable, match="allowed a SQL string containing a NUL byte"):
        NativeVerifier(_policy(tmp_path, "ALLOWS_PROBE.yaml"), backend="process", binary=fake_bin)


def test_fake_child_crash_at_startup(fake_bin, tmp_path):
    with pytest.raises(HaltSQLUnavailable, match="status 139: segfault-ish"):
        NativeVerifier(_policy(tmp_path, "STARTUP_CRASH.yaml"), backend="process", binary=fake_bin)


def test_huge_request_does_not_block_past_timeout(fake_bin, tmp_path):
    """A child that stops reading cannot wedge a large write past the timeout."""
    with _fake(fake_bin, tmp_path, timeout=0.5) as v:
        t0 = time.monotonic()
        with pytest.raises(HaltSQLUnavailable, match="timed out"):
            v.verify("HANG" + "x" * (4 * 1024 * 1024))
        assert time.monotonic() - t0 < 3


def test_lock_wait_is_bounded(fake_bin, tmp_path):
    """A caller waiting behind a stuck request gives up after `timeout`."""
    with _fake(fake_bin, tmp_path, timeout=0.5) as v:
        assert v._impl._lock.acquire()
        try:
            t0 = time.monotonic()
            with pytest.raises(HaltSQLUnavailable, match="busy"):
                v.verify("SELECT 1")
            assert 0.4 < time.monotonic() - t0 < 2
        finally:
            v._impl._lock.release()
        assert v.verify("SELECT 1").allowed


@pytest.mark.parametrize(
    "doc,expected",
    [
        ("catalog: ../c/s.json\nx: 1", 'catalog: "/base/../c/s.json"\nx: 1'),
        ('catalog: "c.json"  # note', 'catalog: "/base/c.json"'),
        ("catalog: 'c.json'", 'catalog: "/base/c.json"'),
        ("catalog: /abs.json", None),
        ("  catalog: nested.json", None),
        ("catalog: {tables: []}", None),
        ("catalog: a#b.json", None),
        ("catalog: x.json\ncatalog: y.json", None),
    ],
)
def test_absolutize_catalog_yaml(doc, expected):
    assert native._absolutize_catalog(doc, "yaml", "/base") == (doc if expected is None else expected)


def test_absolutize_catalog_json():
    assert json.loads(native._absolutize_catalog('{"catalog": "x.json"}', "json", "/b")) == {
        "catalog": "/b/x.json"
    }
    for doc in ('{"catalog": "/abs.json"}', '{"catalog": {"tables": []}}', "not json", "[]"):
        assert native._absolutize_catalog(doc, "json", "/b") == doc


# ----------------------------------------------------------------------------- bundled CLI resolution


def test_local_resolves_bundled_binary(monkeypatch, tmp_path):
    from haltsql import local

    fake_native = tmp_path / "_native"
    fake_native.mkdir()
    exe = fake_native / "haltsql"
    exe.write_text("#!/bin/sh\nexit 0\n")
    exe.chmod(0o755)
    monkeypatch.setattr(local, "NATIVE_DIR", str(fake_native))
    monkeypatch.delenv("HALTSQL_BIN", raising=False)
    assert local.bundled_binary() == str(exe)
    assert local._resolve_binary(None) == str(exe)
    # explicit and $HALTSQL_BIN still win
    assert local._resolve_binary("/bin/sh") == "/bin/sh"
    monkeypatch.setenv("HALTSQL_BIN", "/bin/sh")
    assert local._resolve_binary(None) == "/bin/sh"
    # not executable -> not bundled
    exe.chmod(0o644)
    assert local.bundled_binary() is None


def test_native_cli_without_bundle(monkeypatch, capsys):
    from haltsql import _native_cli

    monkeypatch.setattr(_native_cli, "bundled_binary", lambda: None)
    with pytest.raises(SystemExit) as ei:
        _native_cli.main(["version"])
    assert ei.value.code == 2
    assert "no bundled CLI" in capsys.readouterr().err


# ----------------------------------------------------------------------------- latency


def _avg_us(v: NativeVerifier, n: int) -> float:
    for _ in range(50):
        v.verify(SQL_OK, CTX)
    t0 = time.perf_counter()
    for _ in range(n):
        v.verify(SQL_OK, CTX)
    return (time.perf_counter() - t0) / n * 1e6


def test_library_latency_under_1ms(native_env):
    with NativeVerifier(SAAS, backend="library") as v:
        avg = _avg_us(v, 2000)
    print(f"\nlibrary backend: {avg:.1f} us/verify")
    assert avg < 1000, f"{avg:.1f} us per verify"


def test_process_latency_reported(native_env):
    with NativeVerifier(SAAS, backend="process") as v:
        avg = _avg_us(v, 1000)
    print(f"\nprocess backend: {avg:.1f} us/verify")
    assert avg < 20000  # generous: a regression to spawn-per-call would be ~10-50 ms


# ----------------------------------------------------------------------------- wheel

WHEEL_SCRIPT = r'''
import json, os, subprocess, sys
import haltsql
from haltsql import LocalVerifier, NativeVerifier
venv = sys.argv[1]
vec = json.loads(sys.argv[2])
policy = sys.argv[3]
assert os.path.realpath(haltsql.__file__).startswith(os.path.realpath(venv)), haltsql.__file__
for k in ("HALTSQL_LIB", "HALTSQL_BIN", "HALTSQL_NATIVE"):
    assert k not in os.environ, k
with NativeVerifier(policy) as v:
    assert v.backend == "library", (v.backend, v.fallback_reason)
    assert v.library_path.startswith(os.path.dirname(haltsql.__file__)), v.library_path
    got = v.verify(vec["request"]["sql"], vec["request"]["context"])
    assert got.to_dict()["sql_sha256"] == vec["verdict"]["sql_sha256"]
    assert got.allowed == vec["verdict"]["allowed"]
    assert got.codes == [r["code"] for r in vec["verdict"]["reasons"]]
with NativeVerifier(policy, backend="process") as p:
    assert p.binary.startswith(os.path.dirname(haltsql.__file__)), p.binary
    assert p.verify(vec["request"]["sql"], vec["request"]["context"]).allowed == got.allowed
lv = LocalVerifier(policy)
assert lv.binary == os.path.join(os.path.dirname(haltsql.__file__), "_native", "haltsql"), lv.binary
assert lv.verify(vec["request"]["sql"], vec["request"]["context"]).allowed == got.allowed
exe = os.path.join(venv, "Scripts" if os.name == "nt" else "bin", "haltsql")
out = subprocess.run([exe, "version"], capture_output=True, text=True, check=True).stdout
assert out.startswith("haltsql " + haltsql.__version__), out
print("WHEEL_OK", v.backend, out.splitlines()[0])
'''


@pytest.mark.wheel
def test_wheel_installs_and_runs_in_fresh_venv(tmp_path):
    wheel = os.environ.get("HALTSQL_WHEEL")
    if not wheel:
        pytest.skip("set HALTSQL_WHEEL=path/to/haltsql-*.whl to test a built wheel")
    assert os.path.isfile(wheel), wheel
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    py = str(venv / ("Scripts" if os.name == "nt" else "bin") / "python")
    # Offline install: the wheel without deps, then make httpx (the only dependency)
    # importable from the current environment, behind the venv's own site-packages.
    subprocess.run(
        [py, "-m", "pip", "install", "-q", "--no-index", "--no-deps", wheel], check=True
    )
    site = subprocess.run(
        [py, "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    import httpx  # noqa: F401  (just to locate it)

    deps_dir = os.path.dirname(os.path.dirname(httpx.__file__))
    with open(os.path.join(site, "zz_test_deps.pth"), "w") as f:
        f.write(deps_dir + "\n")
    vec = next(v for v in VECTORS if v["name"] == "saas_allow_bound_simple")
    env = {k: v for k, v in os.environ.items() if not k.startswith("HALTSQL_")}
    env["PATH"] = os.path.dirname(py) + os.pathsep + env.get("PATH", "")
    script = tmp_path / "check_wheel.py"
    script.write_text(WHEEL_SCRIPT)
    proc = subprocess.run(
        [py, "-I", str(script), str(venv), json.dumps(vec), vec_policy(vec)],
        capture_output=True, text=True, env=env, cwd=str(tmp_path),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "WHEEL_OK library" in proc.stdout


# ----------------------------------------------------------------------------- guard integration


async def test_guard_accepts_native_verifiers(native_env):
    from haltsql import guard

    with NativeVerifier(SAAS) as v:
        assert guard.authorize(SQL_OK, CTX, verifier=v).bind_args() == ["acme"]
        with pytest.raises(QueryDenied):
            guard.authorize("SELECT id FROM orders LIMIT 1", CTX, verifier=v)
    async with AsyncNativeVerifier(SAAS) as av:
        assert (await guard.authorize_async(SQL_OK, CTX, verifier=av)).allowed
