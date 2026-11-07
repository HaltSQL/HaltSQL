# Audit sinks

Every verify request produces one audit record per configured sink. Each
record is one JSON line:

```json
{"ts":"2024-06-01T12:00:00Z","request_id":"...","caller":"support-bot","policy":"support",
 "policy_version":"v3","allowed":false,"shadow":false,"codes":["E_TABLE_DENIED"],
 "sql_sha256":"...","fingerprint":"...","elapsed_us":183,
 "prev_hash":"<64 hex>","hash":"<64 hex>"}
```

Records are **hash-chained**: `hash = sha256_hex(prev_hash ^ L)`, where `L` is
the compact JSON of the record without its `hash` field. The first record of
a chain has `prev_hash` = 64 zeros. Each sink keeps its own chain. A modified,
deleted, inserted or reordered record breaks verification (see
[Verifying a chain](#verifying-a-chain)).

| Sink | Durability | Use for |
|---|---|---|
| `stdout` | your log pipeline | containers with log shipping |
| `file` | local disk, appended per record | VMs, sidecars with a volume |
| `s3` | S3 or S3-compatible, optionally WORM (Object Lock) | compliance archives on AWS / MinIO |
| `gcs` | Google Cloud Storage | compliance archives on GCP |

The cloud sinks are in library `haltsql.cloud`, modules `S3_sink`, `Gcs_sink`
and `Object_sink`.

## How the cloud sinks work

1. `write` seals the record into the sink's chain and appends it to the
   current **batch**. The call is synchronous and never waits on the network.
2. A batch closes when it holds `batch.max_records` records (default 500) or
   is `batch.max_seconds` old (default 10). The closed batch becomes one
   object:

   ```
   <prefix>YYYY/MM/DD/HH/<host>-<run>-<seq>-<sha256>.jsonl
   ```

   - `YYYY/MM/DD/HH`: the UTC hour when the batch closed;
   - `<host>`: the sanitized hostname;
   - `<run>`: the run id of the process that sealed the batch: its UTC start
     time with microseconds, then its pid (e.g. `20240601T115900.042000Z.7`).
     Two runs never share a sequence namespace, and run ids sort by start time;
   - `<seq>`: a zero-padded per-sink sequence number;
   - `<sha256>`: the SHA-256 of the object body.

   Example:
   `haltsql/audit/2024/06/01/12/haltsql-7f9c-20240601T115900.042000Z.7-0000000042-9b1e....jsonl`.
3. Objects are uploaded **strictly in order**. If an upload fails, that
   object stays at the head of the queue and nothing behind it overtakes it.
4. **The chain spans objects.** The first record of object *n+1* carries the
   `hash` of the last record of object *n*. Concatenate a sink's objects in
   `<seq>` order and the result verifies as a single chain:

   Each host has its own chain. Within one host, sorting the full object
   names gives chain order: by hour, then by run (start time), then by
   `<seq>`. Batches close in `<seq>` order and keep the hour they closed in,
   even when uploaded later. Across restarts the chain is only continuous with
   a spool directory (see [Restarts](#restarts-and-chain-continuity)):

   ```sh
   aws s3 cp --recursive s3://corp-haltsql-audit/haltsql/audit/2024/06/01/ ./audit/
   find ./audit -name 'haltsql-7f9c-*.jsonl' | sort | xargs cat > day.jsonl
   python3 verify_chain.py day.jsonl     # see "Verifying a chain" below
   ```

   A chain that starts mid-stream (e.g. one day of objects) begins with a
   non-zero `prev_hash`; verify it from that record onwards.

5. **Objects are create-only.** S3 PUTs send `If-None-Match: *` and GCS
   uploads send `ifGenerationMatch=0`, so an existing object is never
   overwritten. The object name embeds the body's SHA-256, so a "precondition
   failed" reply on a retry means the object is already stored, and it counts
   as delivered.

## Failure policy (`on_error`)

| Mode | While uploads fail | Recovery |
|---|---|---|
| `fail_closed` (default) | After an upload has failed every attempt (3 by default, with backoff), the sink reports **unhealthy**. Every audit write is refused and `/v1/verify` answers **503**. No request is ever served without its audit record. | The background loop retries the held objects every `batch.max_seconds`. The first success makes the sink healthy again. |
| `buffer` | Writes keep succeeding while failed objects wait, up to `max_buffer_records` records (default 100 000). At the bound, writes are refused (503). Records are **never silently dropped**. | Same background retry; the buffer drains in order. |

Records accepted into a batch but not yet uploaded live in memory. To make
them survive a crash, give the sink a **spool directory** (`spool_dir` in the
sink's config, or `S3_sink.create ~spool_dir`). Use one directory per sink,
on persistent storage:

- Every record is appended to `<spool>/current.jsonl` before `write` returns.
  Writes are refused if the spool cannot be written.
- Closed batches stay on disk as `batch-<seq>.jsonl` until they are uploaded,
  then they are deleted. Each batch's object name is kept beside it in
  `batch-<seq>.key`.
- Each time a batch closes, the chain head and the next sequence number are
  written to `<spool>/head.json` (temporary file, fsync, rename).
- On restart, the sink re-queues the spooled batches under their original
  object names, and continues the chain and the sequence from the last sealed
  record. This holds even when every batch had already been uploaded. A
  corrupt `head.json` or spool file stops the sink from starting; it is never
  silently reset.

### Restarts and chain continuity

| | With `spool_dir` | Without `spool_dir` |
|---|---|---|
| After a restart | the chain continues: the new run's first record has the `prev_hash` of the previous run's last record, and `<seq>` keeps counting | the new run starts a new chain at genesis (`prev_hash` = 64 zeros) and `<seq>` 0, under its own `<run>` |
| Objects of an earlier run deleted | detected: the later run's first record points to a hash that is gone | **not detected** by the chain alone |
| Crash after an upload, before the spool file is removed | the batch is retried under the same object name, so the create-only PUT reports it as already stored | (nothing is spooled) |

Without a spool directory, verify each run on its own: group a host's
objects by `<run>`, and verify each group from genesis. To make an earlier
run's objects impossible to delete, enable S3 Object Lock (`object_lock`),
or a GCS retention policy.

### Metrics and alerts

`Object_sink.metrics_text` renders these metrics for `/metrics`:

| Metric | Type | Alert when |
|---|---|---|
| `haltsql_audit_sink_healthy{sink}` | gauge | `== 0`: writes are being refused |
| `haltsql_audit_sink_buffered_records{sink}` | gauge | growing steadily: uploads are failing (`buffer` mode) |
| `haltsql_audit_sink_pending_objects{sink}` | gauge | `> 0` for longer than a few `max_seconds` |
| `haltsql_audit_sink_objects_uploaded_total{sink}` | counter | flat while traffic flows |
| `haltsql_audit_sink_upload_failures_total{sink}` | counter | `rate > 0` |
| `haltsql_audit_sink_rejected_writes_total{sink}` | counter | `rate > 0`: requests got 503 |

`sink` is `s3://<bucket>/<prefix>` or `gs://<bucket>/<prefix>`.

## S3

```yaml
audit:
  sinks:
    - type: s3
      bucket: corp-haltsql-audit
      region: eu-west-1
      prefix: haltsql/audit/
      object_lock: { mode: COMPLIANCE, retain_days: 365 }
      batch: { max_records: 500, max_seconds: 10 }
      credentials: { source: web_identity }
      on_error: fail_closed
```

Every PUT is signed with **AWS Signature Version 4**, verified against AWS's
published test vectors. Each PUT sends:

- `Content-MD5` and `x-amz-checksum-sha256`, so S3 rejects a body corrupted
  in transit;
- `x-amz-content-sha256`;
- `If-None-Match: *`;
- with `object_lock`: `x-amz-object-lock-mode: GOVERNANCE|COMPLIANCE` and
  `x-amz-object-lock-retain-until-date` (upload time + `retain_days`).

The bucket must have Object Lock enabled; S3 refuses lock headers otherwise.

**URLs.** Without `endpoint`, requests go to
`https://<bucket>.s3.<region>.amazonaws.com/<key>` (virtual-hosted style).
With `endpoint` (MinIO, Ceph, LocalStack), they go to
`<endpoint>/<bucket>/<key>` (path style).

**Credentials** (`credentials.source`):

| Source | How |
|---|---|
| `env` (default) | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`. |
| `static` | Keys from the config. Always use secret placeholders, e.g. `secret_access_key: ${vault:secret/data/haltsql/s3#secret}`. |
| `web_identity` | EKS IRSA / OIDC federation. Reads `AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN` (optional `AWS_ROLE_SESSION_NAME`) and calls STS `AssumeRoleWithWebIdentity` as a form POST, so the token never appears in a URL. The endpoint is `https://sts.<region>.amazonaws.com`, or `AWS_ENDPOINT_URL_STS`. |
| `instance` | EC2 instance profile via **IMDSv2**: a session token from `PUT /latest/api/token`, then the role's credentials. `AWS_EC2_METADATA_SERVICE_ENDPOINT` overrides the endpoint; `AWS_EC2_METADATA_DISABLED=true` disables it. |

Temporary credentials are cached and refreshed 5 minutes before they expire.
If a refresh fails while the cached credentials are still valid, those are
used. If S3 answers `ExpiredToken`, `InvalidToken`, `RequestExpired` or
`TokenRefreshRequired`, the cache is dropped and the upload is retried.
`429`, `SlowDown` and `5xx` are retried. Other `4xx` errors, such as
`AccessDenied`, are not retried within a flush, but the object is still kept.

Minimal IAM policy:

```json
{"Effect": "Allow",
 "Action": ["s3:PutObject", "s3:PutObjectRetention"],
 "Resource": "arn:aws:s3:::corp-haltsql-audit/haltsql/audit/*"}
```

## GCS

```yaml
audit:
  sinks:
    - type: gcs
      bucket: corp-haltsql-audit
      prefix: haltsql/audit/
      credentials: { source: metadata }      # or: { source: service_account_file, file: /var/run/gcp/key.json }
      on_error: buffer
```

**Upload.** Objects are uploaded with the JSON API simple upload
(`uploadType=media`, `ifGenerationMatch=0`). The `md5Hash` that GCS returns
must equal the MD5 of the body, otherwise the upload counts as failed. For
WORM storage, use a bucket retention policy (Bucket Lock).

**Credentials.** Choose one:

- **Metadata server** (GKE Workload Identity, GCE). The sink sends
  `Metadata-Flavor: Google` and requires that header on the response.
  `GCE_METADATA_HOST` overrides the host.
- **Service-account key file.** The sink builds an RS256 JWT and exchanges it
  at the key's `token_uri`, which must be https.

Tokens are cached and refreshed 60 s before expiry. A `401` refreshes the
token once.

**Emulators.** `STORAGE_EMULATOR_HOST` (for example `localhost:4443`)
redirects uploads to an emulator.

Grant the identity `roles/storage.objectCreator` on the bucket.

## Verifying a chain

From OCaml, call `Haltsql_cloud.Audit_chain.verify_lines`. It accepts
`?initial_prev:None` for a chain that starts mid-stream. Without OCaml, this
script checks the same invariants. It never re-serializes JSON: it hashes the
exact bytes written, minus the trailing `"hash"` member.

```python
import hashlib, json, sys
prev = None                      # None: accept the first record's prev_hash
count = 0
for n, line in enumerate(open(sys.argv[1], encoding="utf-8"), 1):
    line = line.rstrip("\n")
    if not line:
        continue
    i = line.rindex(',"hash":"')
    body, claimed = line[:i] + "}", json.loads(line)["hash"]
    p = json.loads(body)["prev_hash"]
    if prev is not None and p != prev:
        sys.exit(f"line {n}: prev_hash does not match the previous record")
    if hashlib.sha256((p + body).encode()).hexdigest() != claimed:
        sys.exit(f"line {n}: hash mismatch (record was modified)")
    prev = claimed
    count += 1
print(f"OK: {count} records")
```
