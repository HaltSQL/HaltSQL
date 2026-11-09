# Runbooks

This page is for on-call engineers responding to HaltSQL incidents. Each
playbook says how the incident shows up, how to confirm it, how to restore
service without weakening the controls, and what to check afterwards. Use
[troubleshooting.md](troubleshooting.md) for symptom-level detail.

All commands assume a server on `127.0.0.1:8080`; adjust for your
environment. Log lines are JSON on stderr with a `msg` field, so `jq` filters
such as `select(.msg == "...")` work on them.

## Ground rules

- **HaltSQL fails closed by design.** When it cannot verify or audit a query,
  the query does not run. There is no fail-open switch in the server, the
  proxy or the official SDKs. Do not add one during an incident.
- **Do not turn on `allow_unauthenticated`, switch policies to
  `mode: shadow`, or widen a policy to restore service.** Each of these removes
  a control. If the business decides to accept that risk, record the decision.
- **Preserve audit data first** when an incident might be a security event.
  Copy it before anything rotates it.

## Verifier down

**Trigger.** Agents report errors instead of query results; SDK errors such as
`HaltSQLUnavailable` (Python) or transport/HTTP errors in the other SDKs;
alerts on `/readyz`, pod restarts, or a drop in
`haltsql_verify_total`. Through `haltsql-proxy`: clients cannot connect.

**Impact.** Agents cannot run queries. No unverified query runs.

### Diagnose

1. Is the process up?

   ```sh
   curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/healthz
   curl -sS http://127.0.0.1:8080/readyz
   kubectl get pods -l app.kubernetes.io/name=haltsql    # adjust the selector
   ```

2. Pick the branch:

   | What you see | Branch |
   |---|---|
   | `/healthz` fails; pods in `CrashLoopBackOff`; exit code 2 | Startup failure. Read the last log lines: `failed to load configuration` and the `error` field name the cause. See [troubleshooting.md](troubleshooting.md#the-process-will-not-start). |
   | `/readyz` 503 with `"policies":0` | No policy loaded. Check bundle sources (`bundle source poll failed; keeping the last good bundle`) and the config. |
   | `/readyz` 503 with `unhealthy_audit_sinks` | Go to [Audit sink outage](#audit-sink-outage). |
   | `/readyz` 200, but callers get `503 AUTH_UNAVAILABLE` | The OIDC provider's keys are unreachable. Check egress to the IdP; `oidc signing keys unavailable` in the logs. |
   | `/readyz` 200, but callers get `503 AUDIT_UNAVAILABLE` | A `file` or `stdout` sink is failing (these do not flip `/readyz`). Go to [Audit sink outage](#audit-sink-outage). |
   | `/readyz` 200, slow responses or timeouts | Saturation. Check CPU, `haltsql_http_open_connections`, and `connection limit reached; new connections wait in the listen backlog`. |
   | Everything healthy on the pod, failures at the client | Network path: Service, load balancer, NetworkPolicy, TLS. Test from the agent's pod with `curl`. |

3. What changed? Check the last deploy, config change, bundle version
   (`GET /v1/admin/status` → `bundle_sources[].current`), certificate expiry
   and IdP changes.

### Mitigate

| Cause | Action |
|---|---|
| A bad config or image | Roll back to the last good revision (`helm rollback`, revert the manifest or `HaltSQLServer`). With `maxUnavailable: 0`, old pods may still be serving; do not delete them. |
| A bundle source is down and pods cannot start | Running pods keep their last good bundle. Stop restarting pods until the source is back, or restore a `cache_dir` volume. |
| Saturation | Add replicas (`kubectl scale`, HPA). One instance verifies on one event loop, so more cores per pod do not help ([high-availability.md](high-availability.md#sizing)). |
| IdP outage | Nothing on the HaltSQL side; cached keys are used for a bounded time, then requests fail closed. Static tokens or mTLS identities are unaffected. |
| Node or zone loss | Check the PodDisruptionBudget and spread; reschedule. |

### Recover and follow up

- `/readyz` is 200 on every replica, `haltsql_verify_total` is back to its
  usual rate, and agents succeed.
- If audit sinks restarted their chains, verify them
  ([Audit chain verification](troubleshooting.md#audit-chain-verification-fails)).
- Review alerts, replica count and probes against the
  [production checklist](production-checklist.md#availability).

## Audit sink outage

**Trigger.** `rate(haltsql_audit_errors_total[5m]) > 0`;
`haltsql_audit_sink_healthy == 0` or `haltsql_audit_stream_sink_healthy == 0`;
`/readyz` lists `unhealthy_audit_sinks`; callers get `503 AUDIT_UNAVAILABLE`;
proxy clients get SQLSTATE `58030`.

**Impact.** With `on_error: fail_closed` (the default), requests are refused
until the sink can be written. This is intended: no request is served without
its audit record.

### Diagnose

1. Identify the sink:

   ```sh
   curl -sS http://127.0.0.1:8080/readyz
   curl -sS http://127.0.0.1:8080/metrics | grep -E 'haltsql_audit_(sink|stream_sink)_'
   kubectl logs deploy/haltsql | jq -c 'select(.msg == "audit sink write failed; failing request closed") | {ts, sink, error}'
   ```

   With the admin API: `GET /v1/admin/status` → `audit_sinks[]` with
   `healthy`.

2. Find the cause on the destination side: S3/GCS permissions or Object Lock
   configuration, Elasticsearch cluster health and mappings, Kafka topic and
   leaders, disk space for `file` sinks. The error types are listed in
   [troubleshooting.md](troubleshooting.md#audit-sink-errors).

### Mitigate

- **Fix the destination.** Recovery is automatic:
  - S3/GCS: the background loop retries held objects every
    `batch.max_seconds`; the first success makes the sink healthy.
  - Elasticsearch/Kafka: a background loop retries the held batch after a
    growing, jittered delay.
  - `file`/`stdout`: every request retries the write.
  - Proxy `stdout`/`file`: every statement retries the write; `s3`/`gcs`
    recover when a background upload succeeds.
- **Do not restart pods to "clear" the error** unless you have to. Records
  accepted into an S3/GCS batch but not uploaded are kept in memory, or in
  `spool_dir` if configured; streaming sinks have no spool, so a restart loses
  their queued records.
- **Changing `on_error` is a compliance decision, not a quick fix.** Switching
  a sink to `buffer` (or `drop` for streaming sinks and the proxy) needs a
  restart, and `drop` serves requests without an audit trail in that sink.
  Only do it with the approval of whoever owns the audit requirement, and
  only when another sink still fails closed.

### Recover and follow up

1. Confirm `haltsql_audit_sink_pending_objects` or
   `haltsql_audit_stream_sink_buffered_records` drain to 0 and
   `/readyz` is 200.
2. Verify the chain across the outage:

   ```sh
   # object sinks, against the live spool (one host)
   aws s3 cp --recursive s3://BUCKET/PREFIX/ ./audit/
   haltsql audit verify --spool /path/to/spool --host HOST ./audit/

   # file sinks
   haltsql audit verify /var/log/haltsql/audit.jsonl
   ```

   For Elasticsearch and Kafka, use `test/siem/verify_chain.py` (see
   [audit-sinks.md](../audit-sinks.md#verifying-from-kafka)).
3. Account for gaps: `haltsql_audit_stream_sink_records_dropped_total{reason}`
   shows dropped records; a process that died with records queued in a
   streaming sink lost them.
4. Record the outage window and the requests refused
   (`haltsql_audit_sink_rejected_writes_total`,
   `haltsql_audit_stream_sink_rejected_writes_total`).

## Bad policy rolled out

**Trigger.** After a policy change: a spike in denials
(`haltsql_verify_total{policy,result="denied"}`), one reason code
jumping in `haltsql_reasons_total`, agents failing on queries that used to
work. Or the opposite: a policy that allows more than intended.

**Impact.** Too strict: agents cannot do their work. Too permissive: a
security issue; the database role and RLS are the remaining controls.

### Diagnose

1. Confirm which version is live:

   ```sh
   curl -sS -H "Authorization: Bearer $HALTSQL_TOKEN" http://127.0.0.1:8080/v1/policies
   kubectl logs deploy/haltsql | jq -c 'select(.msg == "policies reloaded") | {ts, policies}'
   ```

   Every verdict and audit record carries `policy_version`, so you can find
   the first decision made under the new version.
2. See what the new version denies:
   `haltsql report AUDIT_FILES --since 1h --policy NAME --format markdown`
   (by reason code, table, column, caller, and top denied queries). With the
   admin API, `GET /v1/admin/report?since=1h&policy=NAME` gives the same view
   for one replica.

### Roll back

Use the path that matches how the policy is delivered:

| Delivery | Rollback |
|---|---|
| Policy files or ConfigMap, `reload.watch` on | Revert the change in version control and redeploy the files; the server reloads within about 2 seconds. Check for `policies reloaded`. |
| Policy files, no watch | Revert and `kill -HUP <pid>` / `systemctl reload haltsql`, or roll the deployment. |
| ConfigMap mounted with `subPath`, Helm or operator | Revert and roll out (`helm upgrade`/`helm rollback`, revert the `HaltSQLPolicy`). |
| Local `bundle:` file | Put the previous `.haltsqlbundle` and its `.sig` back (atomic write, then rename) and reload. |
| `bundle_source` | Rebuild the previous policies as a bundle with a **higher** `metadata.version` than the bad one, sign it, and push it. Servers refuse older or equal versions (`bundle_source_rollback`), and the config file cannot turn that off. Servers pick it up on the next poll (`poll_interval_s`, default 60). |
| `haltsql-proxy` | Revert the policy files and reload. New connections get the old policy; existing sessions keep the bad one until they close, so restart the proxy if that matters. |

### Verify

- `GET /v1/policies` (or the `policies reloaded` log line) shows the previous
  `policy.version`, or for bundle sources `GET /v1/admin/status` shows the new
  rollback version as `current`.
- Denial rates return to their earlier level.
- For a too-permissive policy, list what was allowed under the bad version:

  ```sh
  jq -c 'select(.policy_version == "sha256:BAD..." and .allowed == true)
         | {ts, request_id, caller, fingerprint, sql_sha256}' audit.jsonl
  ```

### Follow up

- Add the queries that broke (or that should have been denied) as cases in
  the policy's test suite, so CI catches it next time.
- Roll stricter changes out in `mode: shadow` first
  ([deployment.md](../deployment.md#rolling-out-a-policy-change)).

## Signing key rotation

Bundles are verified against the Ed25519 public keys in each `bundle` or
`bundle_source` entry's `public_keys`. Any listed key may verify. The steps
come from [policy-bundles.md](../policy-bundles.md#key-management-and-rotation).

> **Note:** For a local `bundle:` entry, a reload applies a new
> `public_keys` list. For a `bundle_source` entry, changing `public_keys`
> changes the entry, and changes to the list of bundle sources need a restart.

### Planned rotation

1. Generate the new key and store the private key in your CI secret store:

   ```sh
   haltsql bundle keygen -o policy-signing-2.key     # prints the key id
   ```

2. Add `policy-signing-2.key.pub` to every server's `public_keys` next to the
   old key, and roll it out (reload or restart as noted above).
3. Optionally dual-sign while both keys are trusted:

   ```sh
   haltsql bundle sign B --key old.key
   haltsql bundle sign B --key new.key --append
   ```

4. Switch CI to the new key. Confirm with
   `haltsql bundle verify B --public-key policy-signing-2.key.pub` and, on the
   servers, `GET /v1/admin/status` → `bundle_sources[].current.signed_by`.
5. Once no bundle signed only by the old key is in circulation, remove the old
   public key from the servers.

### Compromised key

1. Generate a new key pair.
2. Rebuild the current, known-good policies from version control, sign them
   with the new key only, and publish with a **higher** `metadata.version` than
   anything the compromised key could have signed into circulation.
3. Remove the compromised key from `public_keys` and add the new one, then
   reload (local bundles) or restart (bundle sources). Bundles signed only by
   the removed key stop loading. A cached bundle in `cache_dir` is verified
   again with the current keys at start, so a bundle signed only by the
   removed key is not used from the cache either.
4. Make sure step 2 is done before step 3 for bundle sources: a server that
   restarts with no bundle it can verify (neither cached nor at the source)
   fails to start.
5. Find decisions made under policies from suspect bundles: compare the
   `policy_version` values in the audit records with the versions your
   known-good bundles produce (`haltsql bundle inspect` lists each policy's
   version).
6. Review who had access to the key and your registry's push history.

## Suspected prompt-injection attempt

HaltSQL does not detect prompt injection: it judges the SQL, not the prompt
([threat-model.md](../threat-model.md#known-limitations-and-non-goals)). What
it gives you is a tamper-evident record of every SQL string an agent tried and
what happened to it. An injected prompt usually shows up as an agent suddenly
producing queries outside its normal pattern.

**Trigger.** A spike in denials for one caller or policy, or codes that a
well-behaved agent rarely produces:

| Code | What the agent tried |
|---|---|
| `E_TABLE_DENIED` | Tables outside the policy, including system catalogs (`pg_catalog`, `information_schema`). |
| `E_FUNCTION_DENIED` | Functions such as `pg_sleep`, `set_config`, file access or `dblink`. |
| `E_MULTI_STATEMENT` | A second, stacked statement. |
| `E_STATEMENT_KIND`, `E_DATA_MODIFYING_CTE`, `E_WRITE_DENIED`, `E_SELECT_INTO`, `E_LOCKING_CLAUSE` | Writes, DDL or locks from a read-only agent. |
| `E_TENANT_MISMATCH`, `E_TENANT_MISSING` | Another tenant's data, or no tenant filter. |
| `E_CAST_DENIED` | `reg*` casts that look up catalog objects. |
| `E_COLUMN_DENIED` | Columns the policy hides. |

Also watch `403` responses on `/v1/verify`
(`haltsql_http_requests_total{route="/v1/verify",status="403"}`):
`CONTEXT_NOT_ALLOWED` means a caller tried to set a context field, such as
the tenant, that its identity does not allow. Refused requests (401, 403) are
not verdicts, so they have no audit record.

### Preserve evidence

1. Copy the audit records for the window (file, objects, or an export).
2. Verify the chain before you analyse it, and record the head:

   ```sh
   haltsql audit verify --json audit.jsonl | jq '{ok, heads: [.inputs[].heads[]]}'
   ```

### Find the activity

An audit record has `ts`, `request_id`, `caller` (token name,
`oidc:<provider>` or `mtls:<subject>`), `caller_type`, `subject` (OIDC `sub`,
SPIFFE ID or CN), `policy`, `policy_version`, `allowed`, `shadow`, `codes`,
`sql_sha256`, `fingerprint` and, only with `audit.log_raw_sql`, `sql`.

1. Summarise:

   ```sh
   haltsql report audit/ --since 24h --format markdown
   ```

   *By caller*, *By reason code*, *Over time* and *Top denied queries* (by
   fingerprint) point to the session and the query shapes.
2. List the suspect caller's denials:

   ```sh
   jq -c 'select(.caller == "oidc:corp-okta" and .allowed == false)
          | {ts, request_id, subject, codes, fingerprint, sql_sha256}' audit.jsonl
   ```

3. **Check what was allowed** for the same caller in the same window. These
   queries passed the policy and ran:

   ```sh
   jq -c 'select(.caller == "oidc:corp-okta" and .allowed == true)
          | {ts, request_id, subject, codes, shadow, fingerprint}' audit.jsonl
   ```

   A record with `"allowed": true` and `"shadow": true` was allowed only
   because its policy is in shadow mode: its `codes` are what enforcement
   would have denied. Treat those as unprotected.
4. Get the SQL text. Audit records hold it only with `audit.log_raw_sql`.
   Otherwise join on identifiers your application logs: `request_id` (send
   your own `X-Request-Id`), or `sql_sha256` (the SHA-256 of the exact SQL
   string) against the agent's own logs; OpenTelemetry spans carry the same
   hash as `db.statement.sha256`. Then find the prompt or document that led to
   it in your agent's conversation logs.
5. For `haltsql-proxy`, records carry `user`, `reasons`, `shadow_reasons`,
   `tables`, and local denials as `event` `parse`, `bind` or
   `function_call`.

### Contain

- Stop the session or user in your application. HaltSQL has no per-user
  block list.
- If a credential may be misused, revoke it: remove the static token entry
  and reload, disable the identity in your IdP, or remove the mTLS identity
  and reload ([Token and credential rotation](#token-and-credential-rotation)).
- If the attempts found a gap (an allowed query that should have been
  denied), tighten the policy through the normal rollout, and report a
  possible bypass privately per [SECURITY.md](../../SECURITY.md).

### Follow up

- Confirm the database role and RLS held for every allowed query in the
  window ([defense-in-depth.md](../defense-in-depth.md)).
- Add the attack queries to the policy's test suite.

## Token and credential rotation

What applies without a restart, and what does not:

| Credential | Where it lives | Apply the change with |
|---|---|---|
| Static token hashes (`server.auth.tokens`) | Config, usually through `${env:...}` or `${file:...}` | Reload, if the hash comes from the config file or a `${file:...}` file (send `SIGHUP`: `${file:...}` targets are not watched). A hash from `${env:...}` needs a restart, because the process environment does not change. |
| OIDC provider settings | Config | Reload. Key caches of unchanged providers are kept. |
| IdP signing keys | The IdP's JWKS | Nothing: an unknown `kid` triggers a refresh (at most every 30 s per provider). |
| Server TLS certificate, key, client CA | Files in `server.tls` | Reload or file watch; `haltsql_tls_reload_total{result="success"}`. A broken key keeps the previous material. |
| mTLS identities | Config | Reload. |
| OPA and OTLP headers | Config with secret placeholders | Reload (`opa` and `telemetry.otlp` are applied on reload; a reload resolves placeholders again). |
| Audit sink credentials (static S3 keys, Elasticsearch API key, Kafka SASL password) | Config with secret placeholders | Restart: audit sinks are opened once. Temporary credentials (`web_identity`, `instance`, GCS metadata) refresh by themselves. |
| Bundle source `auth` | Config with secret placeholders | Restart: the running pollers keep their settings. |
| Proxy users (`scram_verifier`) and identities | Proxy config | Reload; applies to new connections only. Restart the proxy to end existing sessions. |
| Proxy upstream password | Proxy config | Reload; applies to new connections. |
| Kubernetes Secrets under the operator | Projected Secret volume | `kubectl rollout restart deploy/<server>`: the operator cannot read Secret values, so it does not roll on value changes. |
| Kubernetes Secrets under Helm | Secret injected as env | The chart rolls pods when `tokens` change; with `existingTokenSecret` it does not, so restart the pods. |

### Rotate a static token

Token names and hashes must be unique, and the audit `caller` field is the
token name, so give the new token a new name.

1. Generate the token and its hash:

   ```sh
   token="$(openssl rand -hex 32)"
   printf '%s' "$token" | sha256sum | cut -d' ' -f1
   ```

2. Add a second entry pinned to the same policy:

   ```yaml
   server:
     auth:
       tokens:
         - name: analytics-agent-2025a        # old
           token_sha256: ${file:/etc/haltsql/secrets/analytics-agent-2025a.sha256}
           policy: analytics-agent
         - name: analytics-agent-2025b        # new
           token_sha256: ${file:/etc/haltsql/secrets/analytics-agent-2025b.sha256}
           policy: analytics-agent
   ```

3. Apply it (see the table above) and confirm `policies reloaded` in the logs.
4. Switch the client to the new token. A client that reads the token only when
   it is constructed (for example from `HALTSQL_TOKEN` at startup) must be
   restarted.
5. Confirm the old token is unused: no new audit records with
   `"caller": "analytics-agent-2025a"`.
6. Remove the old entry and apply again.

For a **compromised** token, skip to step 6 immediately: remove the entry and
reload. Requests with that token get `401 UNAUTHORIZED` from then on.

### Revoke one mTLS client

Remove its `spiffe_id` or `subject_cn` identity and reload. Its certificate
still completes the TLS handshake if it chains to `client_ca`, but it no longer
matches an identity; without a bearer token, the request is refused with
`401`. The proxy does not check CRLs or OCSP for client certificates; remove
the identity there too.

### Rotate the proxy's upstream password

PostgreSQL keeps one password per role, so there is a short window between
changing it in the database and reloading the proxy in which new proxy
connections fail with `08006`. Existing sessions are not affected. Do both
steps back to back, or switch the proxy to a second login role with the same
grants and retire the old one.

## Related

- [Troubleshooting](troubleshooting.md)
- [High availability and scaling](high-availability.md)
- [Upgrades and versioning](upgrades.md)
- [Production checklist](production-checklist.md)
- [Audit chain verification](../audit-verify.md)
- [Signed policy bundles](../policy-bundles.md)
- [Authentication and TLS](../authentication.md)
