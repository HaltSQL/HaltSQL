"""Scenario: policy distribution through an OCI registry (registry:2).

CI signs a bundle and publishes it with `haltsql bundle push --oci`; a running
haltsql-server pulls it from the registry, hot-swaps a newer signed version,
and refuses a bundle signed with a key it does not trust while the last good
version keeps serving. Every step is checked on what the services actually
did: the manifest registry:2 stores, the server's admin status and metrics,
its verify verdicts, and the files in its bundle cache.

Ports: 17050-17051.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from conftest import (
    Cli,
    Processes,
    new_token,
    reason_codes,
    registry_manifest,
    render_policy,
    sha256_hex,
    unique_name,
    wait_until,
)

SERVER_PORT = 17050
POLL_S = 10  # the minimum poll_interval_s; a new tag is seen within ~11 s
UPDATE_TIMEOUT = 60.0

# v1: id, total_cents. v1.1 adds status. The untrusted v1.2 would add note.
V1_COLUMNS = ["id", "total_cents"]
V11_COLUMNS = V1_COLUMNS + ["status"]
ROGUE_COLUMNS = V11_COLUMNS + ["note"]


def build_signed(cli: Cli, work: Path, *, version: str, columns: list[str], key: Path) -> Path:
    pol = work / f"shop-{version}.yaml"
    pol.write_text(render_policy("shop", columns))
    bundle = cli.build_bundle([pol], work / f"prod-{version}.haltsqlbundle",
                              name="prod", version=version)
    cli.sign(bundle, key)
    return bundle


def server_config(*, ref: str, pub: Path, cache: Path, audit: Path, token: str) -> str:
    return f"""apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:{SERVER_PORT}
  auth:
    tokens:
      - {{ name: agent, token_sha256: {sha256_hex(token)}, policy: remote-shop }}
  admin: {{ enabled: true, callers: [token:agent] }}
policies:
  - bundle_source: {{ oci: {ref}, plain_http: true }}
    public_keys: [{pub}]
    name_prefix: remote-
    poll_interval_s: {POLL_S}
    cache_dir: {cache}
audit:
  sinks:
    - {{ type: file, path: {audit} }}
"""


def source_status(server, token: str) -> dict:
    st = server.admin_status(token)
    sources = st["bundle_sources"]
    assert len(sources) == 1, sources
    return sources[0]


def metric(server, name: str) -> float:
    body = server.get("/metrics").text
    vals = [float(line.rsplit(" ", 1)[1]) for line in body.splitlines()
            if line.startswith(name + "{") or line.startswith(name + " ")]
    assert len(vals) == 1, f"{name} in /metrics: {vals}"
    return vals[0]


def cached_bundles(cache: Path) -> list[Path]:
    return sorted(p for p in cache.rglob("*") if p.is_file() and p.suffix == ".haltsqlbundle")


def test_policy_distribution_over_oci(cli: Cli, registry: str, processes: Processes,
                                      tmp_path: Path) -> None:
    work = tmp_path / "ci"
    work.mkdir()
    trusted_key = work / "release.key"
    rogue_key = work / "rogue.key"
    trusted_id = cli.keygen(trusted_key)
    rogue_id = cli.keygen(rogue_key)
    assert trusted_id != rogue_id
    trusted_pub = Path(f"{trusted_key}.pub")

    repo = unique_name("e2e/policy-distribution")
    ref = f"{registry}/{repo}:prod"

    # ---- v1.0.0: CI signs and publishes; registry:2 stores the artifact ----
    v1 = build_signed(cli, work, version="1.0.0", columns=V1_COLUMNS, key=trusted_key)
    _, pushed = cli.push_oci(ref, v1, public_keys=[trusted_pub])
    assert pushed["ok"] is True
    assert pushed["verified_keyid"] == trusted_id
    assert pushed["bundle"] == "prod@1.0.0"
    digest, manifest = registry_manifest(ref)
    assert pushed["digest"] == digest
    assert pushed["pinned"] == f"{registry}/{repo}@{digest}"
    assert manifest["artifactType"] == "application/vnd.haltsql.bundle.v1"
    assert manifest["annotations"]["dev.haltsql.bundle.version"] == "1.0.0"
    assert manifest["annotations"]["dev.haltsql.bundle.digest"] == pushed["bundle_digest"]
    layers = {l["mediaType"]: l for l in manifest["layers"]}
    assert layers["application/vnd.haltsql.bundle.v1+json"]["digest"] == (
        "sha256:" + hashlib.sha256(v1.read_bytes()).hexdigest())

    # ---- the server pulls it from the registry at startup ----
    token = new_token()
    cache = tmp_path / "cache"
    audit = tmp_path / "audit.jsonl"
    server = processes.server(
        server_config(ref=ref, pub=trusted_pub, cache=cache, audit=audit, token=token),
        SERVER_PORT)

    verdicts: list[dict] = []

    def verify(sql: str) -> dict:
        v = server.verify(sql, token)
        verdicts.append(v)
        return v

    src = source_status(server, token)
    assert src["source"] == f"oci:{ref}"
    cur = src["current"]
    assert cur["bundle"] == "prod" and cur["version"] == "1.0.0"
    assert cur["origin"] == "source"
    assert cur["revision"] == digest
    assert cur["policies"] == ["remote-shop"]
    assert cur["signed_by"] == trusted_id
    assert src["last_error"] is None
    status = server.admin_status(token)
    assert [(p["name"], p["origin"]) for p in status["policies"]] == [("remote-shop", "bundle_source")]
    v1_policy_version = status["policies"][0]["version"]
    assert metric(server, "haltsql_bundle_source_healthy") == 1

    allowed = verify("SELECT id, total_cents FROM orders LIMIT 5")
    assert allowed["allowed"] is True, allowed
    assert (allowed["policy"]["name"], allowed["policy"]["version"]) == ("remote-shop", v1_policy_version)
    denied = verify("SELECT status FROM orders LIMIT 5")
    assert denied["allowed"] is False, denied
    assert "E_COLUMN_DENIED" in reason_codes(denied), denied
    assert [p.name for p in cached_bundles(cache)] == [f"{sha256_hex(v1.read_bytes())}.haltsqlbundle"]

    # ---- v1.1.0: pushed to the same tag, hot-swapped without a restart ----
    checks_before = src["checks"]
    v11 = build_signed(cli, work, version="1.1.0", columns=V11_COLUMNS, key=trusted_key)
    cli.push_oci(ref, v11)
    digest11, manifest11 = registry_manifest(ref)
    assert manifest11["annotations"]["dev.haltsql.bundle.version"] == "1.1.0"
    assert digest11 != digest

    src = wait_until("the server to serve bundle 1.1.0",
                     lambda: (s := source_status(server, token))["current"]["version"] == "1.1.0" and s,
                     timeout=UPDATE_TIMEOUT)
    assert src["current"]["revision"] == digest11
    assert src["current"]["origin"] == "source"
    assert src["checks"] > checks_before
    assert src["last_error"] is None
    assert server.alive(), "hot update must not restart the server"
    v11_policy_version = server.admin_status(token)["policies"][0]["version"]
    assert v11_policy_version != v1_policy_version

    now_allowed = verify("SELECT status FROM orders LIMIT 5")
    assert now_allowed["allowed"] is True, now_allowed
    assert (now_allowed["policy"]["name"], now_allowed["policy"]["version"]) == ("remote-shop", v11_policy_version)
    still_denied = verify("SELECT note FROM orders LIMIT 5")
    assert still_denied["allowed"] is False
    assert "E_COLUMN_DENIED" in reason_codes(still_denied)
    assert [p.name for p in cached_bundles(cache)] == [f"{sha256_hex(v11.read_bytes())}.haltsqlbundle"]

    # ---- v1.2.0 signed with an untrusted key: refused, 1.1.0 keeps serving ----
    rogue = build_signed(cli, work, version="1.2.0", columns=ROGUE_COLUMNS, key=rogue_key)
    # The CLI runs the same checks as the server: the rogue bundle does not verify.
    bad = cli.run("bundle", "verify", rogue, "--public-key", trusted_pub, check=False)
    assert bad.returncode == 1, (bad.stdout, bad.stderr)
    cli.run("bundle", "verify", rogue, "--public-key", f"{rogue_key}.pub")
    # A CI push that checks against the trusted key refuses it; the tag is untouched.
    code, out = cli.push_oci(ref, rogue, public_keys=[trusted_pub], check=False)
    assert code == 1, out
    assert out["ok"] is False and rogue_id in out["error"], out
    assert registry_manifest(ref)[0] == digest11
    # Pushing without the check (an attacker with registry write access) works.
    cli.push_oci(ref, rogue)
    digest_rogue, manifest_rogue = registry_manifest(ref)
    assert manifest_rogue["annotations"]["dev.haltsql.bundle.version"] == "1.2.0"

    def refused() -> dict | None:
        s = source_status(server, token)
        err = s["last_error"]
        return s if err is not None and err["code"] == "bundle_source_signature" else None

    src = wait_until("the server to refuse the untrusted bundle", refused, timeout=UPDATE_TIMEOUT)
    assert src["current"]["version"] == "1.1.0"
    assert src["current"]["revision"] == digest11
    assert metric(server, "haltsql_bundle_source_healthy") == 0
    assert server.admin_status(token)["policies"][0]["version"] == v11_policy_version
    # Verdicts are still those of 1.1.0: the rogue bundle's extra column stays denied.
    rogue_col = verify("SELECT note FROM orders LIMIT 5")
    assert rogue_col["allowed"] is False, rogue_col
    assert "E_COLUMN_DENIED" in reason_codes(rogue_col)
    assert rogue_col["policy"]["version"] == v11_policy_version
    assert verify("SELECT status FROM orders LIMIT 5")["allowed"] is True
    # The refused bundle was never cached; readiness is unaffected.
    assert [p.name for p in cached_bundles(cache)] == [f"{sha256_hex(v11.read_bytes())}.haltsqlbundle"]
    assert server.get("/readyz").status_code == 200
    # The refusal names the untrusted signer, in the status and in the log.
    assert rogue_id in src["last_error"]["message"], src
    warn = [l for l in server.log().splitlines() if "bundle_source_signature" in l]
    assert warn and rogue_id in warn[0] and '"level":"warn"' in warn[0], server.log()
    assert token not in server.log()

    # ---- restart while the registry still serves the rogue bundle ----
    # The server starts from its verified cache (1.1.0) and refuses the tag again.
    server.stop()
    server = processes.server(
        server_config(ref=ref, pub=trusted_pub, cache=cache, audit=audit, token=token),
        SERVER_PORT, name="haltsql-server-restarted")
    src = wait_until("the restarted server to refuse the untrusted bundle", refused,
                     timeout=UPDATE_TIMEOUT)
    assert src["current"]["version"] == "1.1.0"
    assert src["current"]["origin"] == "cache"
    assert src["current"]["signed_by"] == trusted_id
    rogue_col = verify("SELECT note FROM orders LIMIT 5")
    assert rogue_col["allowed"] is False and rogue_col["policy"]["version"] == v11_policy_version

    # ---- recovery: the next trusted version is accepted again ----
    v13 = build_signed(cli, work, version="1.3.0", columns=ROGUE_COLUMNS, key=trusted_key)
    cli.push_oci(ref, v13)
    digest13, _ = registry_manifest(ref)
    src = wait_until("the server to serve bundle 1.3.0",
                     lambda: (s := source_status(server, token))["current"]["version"] == "1.3.0" and s,
                     timeout=UPDATE_TIMEOUT)
    assert src["current"]["revision"] == digest13
    assert src["last_error"] is None
    assert metric(server, "haltsql_bundle_source_healthy") == 1
    assert verify("SELECT note FROM orders LIMIT 5")["allowed"] is True

    # Every verdict above was audited by the server, against the policy
    # version that produced it, in one unbroken hash chain.
    records = [json.loads(l) for l in audit.read_text().splitlines() if l.strip()]
    assert [(r["policy"], r["policy_version"], r["allowed"], r["sql_sha256"]) for r in records] == [
        (v["policy"]["name"], v["policy"]["version"], v["allowed"], v["sql_sha256"])
        for v in verdicts
    ]
    assert all(r["prev_hash"] == p["hash"] for p, r in zip(records, records[1:]))
