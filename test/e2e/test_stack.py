"""Harness self-check: each conftest helper against the real service it drives.

These tests do not start HaltSQL; they make sure a scenario failure points at
HaltSQL and not at the harness or a half-started stack.
"""

from __future__ import annotations

import json
import time

import requests

from conftest import (
    KEYCLOAK_ISSUER,
    OPA_URL,
    REGISTRY_URL,
    Kafka,
    Keycloak,
    Minio,
    OpenSearch,
    Postgres,
    opa_decision_logs,
    unique_name,
)


def test_keycloak_tokens(keycloak: Keycloak) -> None:
    sa = Keycloak.claims(keycloak.client_token())
    assert sa["iss"] == KEYCLOAK_ISSUER
    assert sa["aud"] == "haltsql" or "haltsql" in sa["aud"]
    assert sa["groups"] == ["support"]
    bob = Keycloak.claims(keycloak.user_token("bob"))
    assert bob["preferred_username"] == "bob"
    assert bob["groups"] == ["finance"]


def test_kafka_round_trip(kafka: Kafka) -> None:
    from kafka import KafkaProducer

    topic = kafka.create_topic(unique_name("e2e-stack"))
    try:
        p = KafkaProducer(bootstrap_servers=kafka.bootstrap)
        for i in range(3):
            p.send(topic, json.dumps({"i": i}).encode())
        p.flush()
        p.close()
        recs = kafka.consume(topic, min_messages=3)
        assert [json.loads(r.value)["i"] for r in recs] == [0, 1, 2]
    finally:
        kafka.delete_topic(topic)


def test_opensearch_round_trip(opensearch_client: OpenSearch) -> None:
    index = unique_name("e2e-stack")
    try:
        r = requests.post(f"{opensearch_client.url}/{index}/_doc", json={"k": "v"}, timeout=10)
        assert r.status_code == 201, r.text
        assert opensearch_client.wait_for(index, 1) == [{"k": "v"}]
    finally:
        opensearch_client.delete_index(index)


def test_postgres_database(postgres: Postgres, pg_database: str) -> None:
    with postgres.connect(pg_database) as c:
        assert c.execute("SELECT current_database(), current_setting('server_version_num')::int / 10000").fetchone() == (pg_database, 17)


def test_minio_bucket(minio: Minio) -> None:
    bucket = unique_name("e2e-stack")
    try:
        minio.make_bucket(bucket)
        ls = minio.mc("ls", "--json", "e2e/").stdout
        assert any(json.loads(line).get("key") == f"{bucket}/" for line in ls.splitlines())
    finally:
        minio.remove_bucket(bucket)


def test_opa_base_policy_and_decision_log(opa: str) -> None:
    marker = unique_name("e2e-stack")
    r = requests.post(
        f"{OPA_URL}/v1/data/haltsql/e2e/decision",
        json={"input": {"allowed": True, "tables": ["app.payroll"], "fingerprint": marker}},
        timeout=10,
    )
    assert r.json()["result"]["allow"] is False
    time.sleep(0.5)
    seen = [d for d in opa_decision_logs() if d.get("input", {}).get("fingerprint") == marker]
    assert len(seen) == 1 and seen[0]["result"]["allow"] is False


def test_registry(registry: str) -> None:
    r = requests.get(f"{REGISTRY_URL}/v2/", timeout=5)
    assert r.status_code == 200
