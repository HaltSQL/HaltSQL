"""Scenario: one haltsql-server writes its audit trail to a file, Kafka and
OpenSearch at the same time, and `haltsql audit verify` proves each copy.

After real traffic (allowed and denied verifies), every sink holds exactly
one record per request, each sink keeps its own hash chain, and:

* the file sink verifies with `haltsql audit verify` (anchored with
  --expect-head on the last hash the server wrote);
* the Kafka records, consumed from the real broker in offset order, verify
  with `haltsql audit verify` and with test/siem/verify_chain.py;
* the OpenSearch documents (their `event.original`, the exact bytes that were
  hashed) verify with `haltsql audit verify` and with verify_chain.py.

Tampering is detected on every copy: one record modified and one record
deleted in the exports, and on the real services a forged record appended to
the Kafka topic, records deleted from its head (DeleteRecords), and one
OpenSearch document rewritten and another deleted.

Ports: 17070. Resources: Kafka topic and OpenSearch index named
audit-proxy-agents-*.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import requests

from conftest import (
    OPENSEARCH_URL,
    REPO,
    Cli,
    Kafka,
    OpenSearch,
    Processes,
    new_token,
    reason_codes,
    render_policy,
    sha256_hex,
    unique_name,
    wait_until,
)

SERVER_PORT = 17070
GENESIS = "0" * 64
VERIFY_CHAIN = REPO / "test" / "siem" / "verify_chain.py"


def audit_verify(cli: Cli, *inputs: str | Path, extra: tuple[str, ...] = ()) -> tuple[int, dict[str, Any]]:
    """`haltsql audit verify --json INPUT...`: (exit code, report)."""
    p = cli.run("audit", "verify", "--json", *extra, *inputs, check=False)
    assert p.returncode in (0, 1), f"audit verify exited {p.returncode}: {p.stdout}\n{p.stderr}"
    return p.returncode, json.loads(p.stdout)


def problem_kinds(report: dict[str, Any]) -> set[str]:
    return {pr["kind"] for i in report["inputs"] for pr in i["problems"] if pr["severity"] == "error"}


def verify_chain_py(mode: str, path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-I", str(VERIFY_CHAIN), mode, str(path)],
                          capture_output=True, text=True, timeout=60)


def write_lines(path: Path, lines: list[str]) -> Path:
    path.write_text("".join(line + "\n" for line in lines))
    return path


def chain_order(docs: list[dict[str, Any]]) -> list[str]:
    """The `event.original` lines of OpenSearch documents in chain order:
    follow prev_hash from genesis; documents that do not link (the chain was
    cut) are appended in timestamp order, so the verifier sees the break."""
    by_prev: dict[str, list[dict[str, Any]]] = {}
    for d in docs:
        by_prev.setdefault(d["prev_hash"], []).append(d)
    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    cur = GENESIS
    while len(by_prev.get(cur, [])) == 1:
        d = by_prev[cur][0]
        if id(d) in seen:
            break
        seen.add(id(d))
        out.append(d)
        cur = d["hash"]
    rest = sorted((d for d in docs if id(d) not in seen), key=lambda d: (d["ts"], d["hash"]))
    return [d["event"]["original"] for d in out + rest]


def export_opensearch(index: str) -> list[dict[str, Any]]:
    """Every document of INDEX with its _id (the raw _search hits)."""
    requests.post(f"{OPENSEARCH_URL}/{index}/_refresh", timeout=10)
    r = requests.post(f"{OPENSEARCH_URL}/{index}/_search",
                      json={"size": 10000, "query": {"match_all": {}}}, timeout=10)
    assert r.status_code == 200, r.text
    return r.json()["hits"]["hits"]


def server_config(*, policy: Path, token: str, audit: Path, topic: str, index: str) -> str:
    return f"""apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:{SERVER_PORT}
  auth:
    tokens:
      - {{ name: agent, token_sha256: {sha256_hex(token)}, policy: shop }}
policies:
  - path: {policy}
audit:
  sinks:
    - {{ type: file, path: {audit} }}
    - type: kafka
      brokers: [localhost:17002]
      topic: {topic}
      client_id: audit-proxy-agents
      acks: all
      batch: {{ max_records: 4, flush_interval_ms: 100 }}
    - type: elasticsearch
      url: {OPENSEARCH_URL}
      index: {index}
      batch: {{ max_records: 5, flush_interval_ms: 100 }}
"""


def test_audit_to_file_kafka_and_opensearch(cli: Cli, kafka: Kafka, opensearch_client: OpenSearch,
                                           processes: Processes, tmp_path: Path) -> None:
    topic = kafka.create_topic(unique_name("audit-proxy-agents-audit"))
    index = unique_name("audit-proxy-agents-audit")
    try:
        _scenario(cli, kafka, opensearch_client, processes, tmp_path, topic, index)
    finally:
        kafka.delete_topic(topic)
        opensearch_client.delete_index(index)


def _scenario(cli: Cli, kafka: Kafka, os_client: OpenSearch, processes: Processes,
              tmp_path: Path, topic: str, index: str) -> None:
    policy = tmp_path / "shop.yaml"
    policy.write_text(render_policy("shop", ["id", "total_cents"]))
    audit = tmp_path / "audit.jsonl"
    token = new_token()
    server = processes.server(
        server_config(policy=policy, token=token, audit=audit, topic=topic, index=index),
        SERVER_PORT)

    # ---- traffic: every statement is distinct, so its sql_sha256 names it ----
    sent: list[tuple[str, bool]] = []
    for i in range(14):
        if i % 3 == 2:
            sql, allowed = f"SELECT status FROM app.orders WHERE id = {1000 + i}", False
        else:
            sql, allowed = f"SELECT id, total_cents FROM app.orders WHERE id = {1000 + i} LIMIT 1", True
        v = server.verify(sql, token)
        assert v["allowed"] is allowed, v
        assert v["sql_sha256"] == sha256_hex(sql)
        if not allowed:
            assert reason_codes(v) == ["E_COLUMN_DENIED"]
        sent.append((sql, allowed))
    n = len(sent)
    expected = [(sha256_hex(sql), allowed) for sql, allowed in sent]

    # ---- the file sink ----
    file_lines = wait_until("all records in the file sink",
                            lambda: (ls := audit.read_text().splitlines()) and len(ls) >= n and ls)
    assert len(file_lines) == n
    file_recs = [json.loads(line) for line in file_lines]

    # ---- Kafka: what the broker stored, in offset order ----
    msgs = kafka.consume(topic, min_messages=n, timeout=60)
    assert len(msgs) == n, f"{len(msgs)} Kafka messages, expected {n}"
    assert len({m.partition for m in msgs}) == 1
    assert [m.offset for m in msgs] == list(range(n))
    keys = {m.key for m in msgs}
    assert len(keys) == 1, keys
    (key,) = keys
    assert key.decode().startswith("haltsql/"), key
    kafka_lines = [m.value.decode() for m in msgs]
    kafka_recs = [json.loads(v) for v in kafka_lines]

    # ---- OpenSearch: one document per record, _id = hash ----
    os_client.wait_for(index, n, timeout=60)
    hits = export_opensearch(index)
    assert len(hits) == n
    for h in hits:
        assert h["_id"] == h["_source"]["hash"]
        original = json.loads(h["_source"]["event"]["original"])
        assert {k: v for k, v in h["_source"].items() if k != "event"} == original
    os_lines = chain_order([h["_source"] for h in hits])
    os_recs = [json.loads(line) for line in os_lines]

    # Every sink saw every request, in order, with the verdict the client got;
    # no raw SQL anywhere (audit.log_raw_sql is off).
    for name, recs in (("file", file_recs), ("kafka", kafka_recs), ("opensearch", os_recs)):
        assert [(r["sql_sha256"], r["allowed"]) for r in recs] == expected, name
        assert all(r["policy"] == "shop" and r["caller"] == "agent" for r in recs), name
        assert [r["codes"] for r in recs] == [[] if a else ["E_COLUMN_DENIED"] for _, a in expected]
        assert recs[0]["prev_hash"] == GENESIS, name
        for r in recs:
            assert "sql" not in r and "app.orders" not in json.dumps(r), name
    # One request id per request, the same in all three sinks.
    assert ([r["request_id"] for r in file_recs] == [r["request_id"] for r in kafka_recs]
            == [r["request_id"] for r in os_recs])
    assert len({r["request_id"] for r in file_recs}) == n
    # Each sink seals its own chain (Elasticsearch adds @timestamp before sealing).
    assert [r["hash"] for r in file_recs] == [r["hash"] for r in kafka_recs]
    assert all("@timestamp" in r for r in os_recs)
    assert {r["hash"] for r in os_recs}.isdisjoint({r["hash"] for r in file_recs})

    assert "app.orders" not in server.log()  # nor in the operational log

    # ---- haltsql audit verify passes on all three copies ----
    code, rep = audit_verify(cli, audit, extra=("--expect-head", file_recs[-1]["hash"]))
    assert code == 0 and rep["ok"] is True and rep["records"] == n, rep
    assert rep["inputs"][0]["chains"] == 1

    kafka_file = write_lines(tmp_path / "kafka.jsonl", kafka_lines)
    code, rep = audit_verify(cli, kafka_file, extra=("--expect-head", kafka_recs[-1]["hash"]))
    assert code == 0 and rep["ok"] is True and rep["records"] == n, rep
    tsv = tmp_path / "kafka.tsv"
    tsv.write_text("".join(f"{key.decode()}\t{v}\n" for v in kafka_lines))
    p = verify_chain_py("kafka", tsv)
    assert p.returncode == 0 and f"OK: {n} records in 1 chain(s)" in p.stdout, p.stdout + p.stderr

    os_file = write_lines(tmp_path / "opensearch.jsonl", os_lines)
    code, rep = audit_verify(cli, os_file)
    assert code == 0 and rep["ok"] is True and rep["records"] == n, rep
    es_export = tmp_path / "opensearch.json"
    es_export.write_text(json.dumps(hits))
    p = verify_chain_py("es", es_export)
    assert p.returncode == 0 and f"OK: {n} records in 1 chain(s)" in p.stdout, p.stdout + p.stderr

    # ---- tampering with the exported copies ----
    victim = 5  # 0-based; line 6
    for name, lines in (("file", file_lines), ("kafka", kafka_lines), ("opensearch", os_lines)):
        modified = list(lines)
        assert '"allowed":false' in modified[victim]
        modified[victim] = modified[victim].replace('"allowed":false', '"allowed":true', 1)
        code, rep = audit_verify(cli, write_lines(tmp_path / f"{name}-modified.jsonl", modified))
        assert code == 1 and rep["ok"] is False, (name, rep)
        assert rep["first_broken"]["kind"] == "bad_hash" and rep["first_broken"]["line"] == victim + 1, rep

        deleted = lines[:victim] + lines[victim + 1:]
        code, rep = audit_verify(cli, write_lines(tmp_path / f"{name}-deleted.jsonl", deleted))
        assert code == 1 and rep["ok"] is False, (name, rep)
        assert rep["first_broken"]["kind"] == "broken_link" and rep["first_broken"]["line"] == victim + 1, rep

    # The original file was not touched by any of this and still verifies.
    assert audit_verify(cli, audit)[0] == 0

    # ---- tampering on the real services ----
    _tamper_kafka(cli, kafka, topic, key, kafka_lines, victim, tmp_path)
    _tamper_opensearch(cli, index, hits, victim, tmp_path)


def _tamper_kafka(cli: Cli, kafka: Kafka, topic: str, key: bytes, lines: list[str],
                  victim: int, tmp_path: Path) -> None:
    from kafka import KafkaProducer
    from kafka.structs import TopicPartition

    n = len(lines)
    # A forged copy of a record (verdict flipped) appended with the chain's key.
    forged = lines[victim].replace('"allowed":false', '"allowed":true', 1)
    prod = KafkaProducer(bootstrap_servers=kafka.bootstrap, acks="all")
    try:
        prod.send(topic, key=key, value=forged.encode()).get(timeout=30)
    finally:
        prod.close()
    msgs = kafka.consume(topic, min_messages=n + 1, timeout=60)
    assert len(msgs) == n + 1
    code, rep = audit_verify(cli, write_lines(tmp_path / "kafka-forged.jsonl",
                                              [m.value.decode() for m in msgs]))
    assert code == 1 and rep["first_broken"]["kind"] == "bad_hash", rep
    assert rep["first_broken"]["line"] == n + 1, rep

    # Records deleted from the head of the partition (Kafka's DeleteRecords).
    admin = kafka.admin()
    try:
        admin.delete_records({TopicPartition(topic, 0): 3})
    finally:
        admin.close()
    msgs = kafka.consume(topic, min_messages=n + 1 - 3, timeout=60)
    assert [m.offset for m in msgs][0] == 3 and len(msgs) == n + 1 - 3
    trimmed = write_lines(tmp_path / "kafka-trimmed.jsonl", [m.value.decode() for m in msgs][: n - 3])
    code, rep = audit_verify(cli, trimmed)
    assert code == 1 and rep["first_broken"]["kind"] == "mid_chain_start", rep
    # Anchored on the hash of the last record still known (offset 2), the rest verifies.
    code, rep = audit_verify(cli, trimmed, extra=("--initial-prev", json.loads(lines[2])["hash"]))
    assert code == 0 and rep["records"] == n - 3, rep


def _tamper_opensearch(cli: Cli, index: str, hits: list[dict[str, Any]], victim: int,
                       tmp_path: Path) -> None:
    by_chain = chain_order([h["_source"] for h in hits])
    target = json.loads(by_chain[victim])
    gone = json.loads(by_chain[victim + 3])

    # Rewrite one stored document: its exact line and its searchable field.
    forged = by_chain[victim].replace('"allowed":false', '"allowed":true', 1)
    assert forged != by_chain[victim]
    r = requests.post(f"{OPENSEARCH_URL}/{index}/_update/{target['hash']}?refresh=true",
                      json={"doc": {"allowed": True, "event": {"original": forged}}}, timeout=10)
    assert r.status_code == 200, r.text
    lines = chain_order([h["_source"] for h in export_opensearch(index)])
    code, rep = audit_verify(cli, write_lines(tmp_path / "os-forged.jsonl", lines))
    assert code == 1 and rep["first_broken"]["kind"] == "bad_hash", rep
    assert rep["first_broken"]["line"] == victim + 1, rep
    export = tmp_path / "os-forged.json"
    export.write_text(json.dumps(export_opensearch(index)))
    p = verify_chain_py("es", export)
    assert p.returncode == 1 and "hash mismatch" in (p.stdout + p.stderr), p.stdout + p.stderr

    # Delete another document.
    r = requests.delete(f"{OPENSEARCH_URL}/{index}/_doc/{gone['hash']}?refresh=true", timeout=10)
    assert r.status_code == 200, r.text
    docs = [h["_source"] for h in export_opensearch(index)]
    assert len(docs) == len(hits) - 1
    code, rep = audit_verify(cli, write_lines(tmp_path / "os-deleted.jsonl", chain_order(docs)))
    assert code == 1, rep
    assert {"bad_hash", "broken_link"} <= problem_kinds(rep), rep
    # verify_chain.py must fail on the deletion by its exit status alone. Leave the
    # forged document out so the deletions are the only problem in the export.
    untouched = [h for h in export_opensearch(index) if h["_id"] != target["hash"]]
    export = tmp_path / "os-deleted.json"
    export.write_text(json.dumps(untouched))
    p = verify_chain_py("es", export)
    assert p.returncode == 1 and "missing record" in (p.stdout + p.stderr), p.stdout + p.stderr
