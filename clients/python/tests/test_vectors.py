"""Shared test vectors (clients/testvectors): parse them, and replay them
against the local CLI and a real haltsql-server when those are built."""

import os

import pytest

from haltsql import AsyncLocalVerifier, HaltSQLClient, LocalVerifier, Verdict

from conftest import ROOT, load_vectors

VECTORS = load_vectors()
IDS = [v["name"] for v in VECTORS]


def comparable(v: Verdict):
    return {
        "allowed": v.allowed,
        "reason_codes": v.codes,
        "shadow_codes": [r.code for r in v.shadow_reasons],
        "policy": (v.policy.name, v.policy.version),
        "statement_kind": v.statement_kind,
        "tables": list(v.tables),
        "columns": list(v.columns),
        "bind_params": [b.to_dict() for b in v.bind_params],
        "fingerprint": v.fingerprint,
        "sql_sha256": v.sql_sha256,
    }


def test_there_are_vectors():
    assert len(VECTORS) >= 20
    assert any(v["verdict"]["allowed"] for v in VECTORS)
    assert any(not v["verdict"]["allowed"] for v in VECTORS)


@pytest.mark.parametrize("vec", VECTORS, ids=IDS)
def test_vector_parses_and_is_self_consistent(vec):
    v = Verdict.from_dict(vec["verdict"])
    assert v.matches_sql(vec["request"]["sql"])
    assert v.policy.name == vec["request"]["policy"]
    if v.allowed:
        # bind_args never fails on a real allowed verdict
        assert len(v.bind_args()) == len(v.bind_params)
    else:
        assert v.reasons and v.bind_params == ()


@pytest.mark.integration
@pytest.mark.parametrize("vec", VECTORS, ids=IDS)
def test_vector_local_cli(haltsql_cli, vec):
    lv = LocalVerifier(os.path.join(ROOT, vec["policy_file"]), binary=haltsql_cli)
    got = lv.verify(vec["request"]["sql"], vec["request"]["context"])
    assert comparable(got) == comparable(Verdict.from_dict(vec["verdict"]))


@pytest.mark.integration
async def test_vectors_async_local_cli_batch(haltsql_cli):
    by_policy = {}
    for vec in VECTORS:
        by_policy.setdefault(vec["policy_file"], []).append(vec)
    for policy_file, vecs in by_policy.items():
        lv = AsyncLocalVerifier(os.path.join(ROOT, policy_file), binary=haltsql_cli)
        got = await lv.verify_many([(v["request"]["sql"], v["request"]["context"]) for v in vecs])
        assert [comparable(g) for g in got] == [comparable(Verdict.from_dict(v["verdict"])) for v in vecs]


@pytest.mark.integration
@pytest.mark.parametrize("vec", VECTORS, ids=IDS)
def test_vector_real_server(real_server, vec):
    with HaltSQLClient(real_server) as c:
        req = vec["request"]
        got = c.verify(req["sql"], req["context"], policy=req["policy"])
    assert comparable(got) == comparable(Verdict.from_dict(vec["verdict"]))
    assert got.request_id
