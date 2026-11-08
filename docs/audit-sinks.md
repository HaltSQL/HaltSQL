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
| `elasticsearch` | Elasticsearch or OpenSearch index / data stream | search, dashboards and SIEM rules |
| `kafka` | a Kafka topic (acknowledged by the brokers) | feeding a SIEM pipeline or data lake |

The cloud sinks are in library `haltsql.cloud`, modules `S3_sink`, `Gcs_sink`
and `Object_sink`. The streaming sinks (`elasticsearch`, `kafka`) are in
library `haltsql-server.siem`; see
[Streaming sinks](#streaming-sinks-elasticsearch-opensearch-kafka).

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
| `buffer` | Writes keep succeeding while failed objects wait, up to 100 000 waiting records (the `?max_buffer_records` argument of the library's `S3_sink.create` / `Gcs_sink.create`; it is not a config-file key). At the bound, writes are refused (503). Records are **never silently dropped**. | Same background retry; the buffer drains in order. |

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

## Streaming sinks (Elasticsearch, OpenSearch, Kafka)

The `elasticsearch` and `kafka` sinks ship records as they are written,
instead of uploading objects. The configuration keys are in the
[configuration reference](config-reference.md#streaming-sinks-elasticsearch-and-kafka).
Both sinks work the same way:

1. `write` adds two fields to the record and **seals** it into the sink's own
   hash chain: `prev_hash` and `hash`, exactly as in every other sink. This
   call is synchronous and never waits on the network.
2. Sealed records wait in an in-memory queue, in chain order. A batch is sent
   when the queue holds `batch.max_records` records (default 500) or
   `batch.max_bytes` bytes (default 5 MiB), or when its oldest record is
   `batch.flush_interval_ms` old (default 1000). One request is in flight at a
   time, so batches are never reordered.
3. The destination answers **per record**:
   - Delivered records leave the queue.
   - Records the destination rejects for good leave the queue too. Examples:
     an Elasticsearch mapping error, or a Kafka record larger than the broker
     allows. They are counted in
     `haltsql_audit_stream_sink_records_dropped_total{reason}` and logged with
     their `hash` and the error type, never their contents. They are never
     dropped silently.
   - Records that hit a transient error are sent again, **alone**, on the next
     attempt.
4. Each batch gets 3 attempts, with exponential backoff and jitter between
   them: 0.2 s × 2^n, capped at 30 s, times a random factor between 0.5 and
   1.5. After the last attempt the batch stays at the head of the queue, so
   nothing overtakes it, and the sink is **failing**. A background loop retries
   it after a growing, jittered delay.

Each process starts a new chain at genesis (`prev_hash` = 64 zeros). The
streaming sinks have no spool: records still queued when the process dies are
lost. Use a `file`, `s3` or `gcs` sink with a spool directory next to a
streaming sink when that matters.

### Failure policy (`on_error`)

| Mode | While the destination is unreachable | At the bound (`max_buffer_records`) |
|---|---|---|
| `fail_closed` (default) | After a batch has failed all its attempts, the sink is **unhealthy**: every audit write is refused and `/v1/verify` answers **503** until a retry succeeds. | Writes are refused. |
| `buffer` | Writes keep succeeding; records wait in the queue. | Writes are refused (fail closed). |
| `drop` | New records are **dropped before they are sealed**, so the chain of shipped records stays intact. They are counted with `reason="on_error_drop"` and `write` succeeds. Records already queued are kept and retried. | New records are dropped. |

`drop` is the only mode that serves requests without an audit trail in that
sink. Use it only next to another sink that fails closed.

### Metrics

`Haltsql_siem.Siem.metrics_text` renders these metrics. Their names differ
from the object sinks' metrics, so both can be on one `/metrics` page. Labels:
`sink` (for example `kafka://kafka-1:9093/haltsql.audit`) and `type`
(`elasticsearch` or `kafka`).

| Metric | Type | Alert when |
|---|---|---|
| `haltsql_audit_stream_sink_healthy` | gauge | `== 0`: writes are being refused |
| `haltsql_audit_stream_sink_delivering` | gauge | `== 0`: deliveries are failing (also in `buffer` and `drop` modes) |
| `haltsql_audit_stream_sink_buffered_records` | gauge | growing steadily |
| `haltsql_audit_stream_sink_records_written_total` | counter | |
| `haltsql_audit_stream_sink_records_delivered_total` | counter | flat while traffic flows |
| `haltsql_audit_stream_sink_records_dropped_total{reason}` | counter | `rate > 0`. Reasons: `mapping`, `too_large`, `on_error_drop` |
| `haltsql_audit_stream_sink_delivery_failures_total` | counter | `rate > 0` |
| `haltsql_audit_stream_sink_retries_total` | counter | |
| `haltsql_audit_stream_sink_rejected_writes_total` | counter | `rate > 0`: requests got 503 |

A dropped record (`mapping` or `too_large`) was already sealed, so the
verifier reports a gap at that point in the chain. The log line names the
missing record's hash.

## Elasticsearch and OpenSearch

```yaml
audit:
  sinks:
    - type: elasticsearch
      urls: [https://es-1.corp.example:9200, https://es-2.corp.example:9200]
      data_stream: logs-haltsql-prod       # or index: haltsql-audit
      auth: { api_key: "${vault:secret/data/haltsql/es#api_key}" }
      tls: { ca_file: ./certs/es-ca.pem }
      on_error: buffer
```

The sink only uses the `_bulk` API, so it works with Elasticsearch and
OpenSearch alike. The test suite runs against Elasticsearch 8.15 (security
on, TLS, API key) and OpenSearch 2.17.

**Requests.** Each batch is one `POST <url>/_bulk` (with `?pipeline=` when
`pipeline` is set). Each record is a `create` action whose `_id` is the
record's `hash`:

```
{"create":{"_index":"logs-haltsql-prod","_id":"9b1e…"}}
{"@timestamp":"2024-06-01T12:00:00Z","ts":"2024-06-01T12:00:00Z",…,"prev_hash":"…","hash":"9b1e…","event":{"original":"{\"@timestamp\":…,\"hash\":\"9b1e…\"}"}}
```

- `@timestamp` is added to the record **before** it is sealed (a copy of
  `ts`), because data streams require it. A top-level `event` field would be
  renamed `haltsql_event`; audit records have none.
- The document holds the record's fields, so they are searchable, and
  [`event.original`](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-original):
  the exact sealed line, the bytes the hash covers. Ingest pipelines and
  synthetic `_source` re-serialize documents. Synthetic `_source` is the
  default for `logs-*-*` data streams. So a verifier always starts from
  `event.original`, and checks that the searchable fields match it. The cost
  is about twice the storage per record.
- `create` never overwrites. When a response is lost and the batch is sent
  again, Elasticsearch answers `409` for records it already stored. Their
  `_id` is their hash, so a `409` means "this exact record is stored", and
  counts as delivered. (In a data stream, `_id` is unique per backing index:
  a retry that spans a rollover can store a record twice. The verifier skips
  duplicates.)

**Responses.**

| Answer | What the sink does |
|---|---|
| item `2xx` or `409` | delivered |
| item `429` or `5xx` | that record is retried alone |
| item `400` with `mapper_parsing_exception`, `document_parsing_exception`, `strict_dynamic_mapping_exception` or `mapper_exception` | that record is dropped: `records_dropped_total{reason="mapping"}`, logged with its hash and the error type |
| any other item error (e.g. `403 cluster_block_exception`, a pipeline failure) | that record is retried; while it keeps failing, the sink is failing and `on_error` applies |
| whole request: connection error, timeout, `5xx` | the attempt fails; the next attempt uses the next URL in `urls` |
| whole request: `401`, `403`, `413`, `429` | the attempt fails |

The sink asks for `filter_path=errors,items.*.status,items.*.error.type`, so
item error *reasons* are not even downloaded: they can quote field values.
Only error types are logged.

**Authentication.** `auth.api_key` is sent as `Authorization: ApiKey <key>`,
using the `encoded` value that `POST /_security/api_key` returns. Basic auth
(`username`/`password`) also works. Neither is ever logged. Minimal role for
an API key:

```json
{"haltsql-audit": {"indices": [{"names": ["logs-haltsql-*"],
                                "privileges": ["create_doc", "auto_configure"]}]}}
```

**TLS.** `https` URLs are verified against the system roots, or against the
CA bundle in `tls.ca_file`, including the host name. Plain `http` is accepted
only for loopback addresses.

**Mapping.** Strings in audit records are short. With an `index`, create an
index template first, or rely on dynamic mapping. A field that changes type
(for example after you add a field to the record from a custom integration)
produces `mapping` drops. Watch that metric.

### Verifying from Elasticsearch or OpenSearch

Export the documents and run the verifier. It is the script
[`test/siem/verify_chain.py`](https://github.com/HaltSQL/HaltSQL/blob/main/test/siem/verify_chain.py)
in the repository; the test suite runs it against real clusters.

```sh
curl -s --cacert es-ca.pem -H "Authorization: ApiKey $KEY" \
  -H 'Content-Type: application/json' \
  "https://es-1.corp.example:9200/logs-haltsql-prod/_search" \
  -d '{"size":10000,"query":{"range":{"@timestamp":{"gte":"2024-06-01","lt":"2024-06-02"}}}}' \
  > day.json
python3 verify_chain.py es day.json
# chain from genesis: 8123 records, head 4f0c…
# OK: 8123 records in 1 chain(s)
```

The documents carry no sequence number. The verifier links them by
`prev_hash`, starting from genesis (64 zeros). For each document it:

- recomputes the hash of `event.original`;
- checks that `_id` is that hash;
- checks that the searchable fields equal `event.original`. It tolerates
  synthetic `_source` sorting and de-duplicating arrays. An ingest
  `pipeline` that adds or changes fields makes this check fail even though
  `event.original` itself verifies; enrich into a separate index, or relax
  the check in your copy of the script.

Each process run is one chain from genesis, so an index written by several
runs (restarts) or replicas holds several chains from genesis; the verifier
follows each one. Two records claiming the same non-genesis `prev_hash` are a
fork and fail. A chain that starts anywhere else follows a record that is
missing from the export: a record dropped for a mapping error, a deleted
document, or a time range that cuts the chain. That makes the verifier exit
with status 1. For an export that is expected to begin mid-chain (a time
range), pass `--any-start`: `python3 verify_chain.py es --any-start day.json`.
For more than 10 000 documents, page with `search_after` and pass the hits as
a JSON list.

To make deletion impossible, give the HaltSQL key only `create_doc`, and put
the index under an ILM policy without a delete phase. Or snapshot it to a
WORM repository.

## Kafka

```yaml
audit:
  sinks:
    - type: kafka
      brokers: [kafka-1.corp.example:9093, kafka-2.corp.example:9093]
      topic: haltsql.audit
      acks: all
      tls: { ca_file: /etc/haltsql/kafka/ca.pem }
      sasl: { mechanism: scram-sha-512, username: haltsql, password: "${env:KAFKA_PASSWORD}" }
      on_error: fail_closed
```

The producer is written in OCaml and needs no librdkafka. It implements only
what audit shipping needs:

- **Bootstrap.** The `brokers` are tried in turn. Each connection negotiates
  protocol versions (ApiVersions), authenticates, and fetches the topic's
  metadata. **Topics are never created automatically**: create the topic
  first. A missing topic is a delivery failure
  (`UNKNOWN_TOPIC_OR_PARTITION`), and `on_error` applies.
- **One partition per chain.** Each record is one Kafka message. Its value
  is the sealed record, byte for byte. Its key is the chain id
  `haltsql/<host>/<run>`. Every record of a sink goes to one partition, so
  the chain is that partition's offset order. The partition is chosen once,
  the way the Java client's default partitioner does it:
  `murmur2(key) mod partitions`. It stays the same for the life of the
  process, even if partitions are added.
- **Produce.** One RecordBatch v2 per request: magic 2, CRC-32C, no
  compression, no headers. `acks: all` is sent as `-1`, `acks: 1` as `1`.
  The sink waits for the acknowledgement before sending the next batch.
- **Leader changes.** `NOT_LEADER_OR_FOLLOWER`, `LEADER_NOT_AVAILABLE`,
  `UNKNOWN_TOPIC_OR_PARTITION`, leader-epoch errors and connection failures
  close the connection and forget the leader. The next attempt asks the
  bootstrap brokers again and reconnects to the new leader.
- **Too large.** On `MESSAGE_TOO_LARGE` or `RECORD_LIST_TOO_LARGE`, the
  batch is split in halves. A single record that is still too large is
  dropped and counted with `reason="too_large"`.
- **TLS** uses the same tls-lwt stack as the rest of HaltSQL. The broker
  certificate and host name are verified against the system roots or
  `tls.ca_file`. A broker name that is neither an IP address nor a valid DNS
  host name (for example `kafka_1`: `_` is not allowed in host names) cannot
  be checked, so the sink refuses to connect to it; this applies to the
  configured brokers and to the leaders they advertise. An optional client
  certificate (`cert_file` + `key_file`) enables mTLS; the test suite runs it
  against a broker with `ssl.client.auth=required`.
- **SASL**: `PLAIN`, `SCRAM-SHA-256` and `SCRAM-SHA-512` (RFC 5802 / RFC
  7677). With SCRAM, the broker's final signature is verified: a broker that
  does not prove it knows the password is refused. Passwords never appear in
  logs or errors. `PLAIN` without TLS is only allowed to loopback brokers
  (`localhost`, `::1`, a literal 127.0.0.0/8 address), and the rule is applied
  to every connection: a leader that the bootstrap broker advertises at a
  non-loopback address is refused instead of receiving the password in clear
  text.

**Delivery is at least once.** There is no idempotent producer. When a
request times out after the broker stored the batch, the batch is sent
again. The partition then holds the same records twice: the whole batch can
follow itself (offsets 3-7 repeated at 8-12, for example), and nothing on the
sink side shows it. `verify_chain.py kafka` skips an exact re-delivery of a
record it has already seen (same `hash`, content verified) and keeps linking
from the last new record. `haltsql audit verify` reports such copies as
`duplicate_record` errors unless you pass `--allow-redelivery`, which makes
them warnings; missing, reordered or modified records still fail either way.

**Limits.**

- Protocol versions: Produce v3-v8, Metadata v1-v8, SaslHandshake v1,
  SaslAuthenticate v0-v1, all supported by Kafka 1.0 and later (4.x
  included). The test suite runs against Apache Kafka 3.9 (KRaft).
- One request in flight per sink. Throughput is about one batch per broker
  round trip, which is far more than one HaltSQL instance produces.
- Not supported: compression, transactions, the idempotent producer,
  OAUTHBEARER and GSSAPI (Kerberos), SASLprep of user names and passwords
  (Kafka's own client does not apply it either).
- Records queued in memory are lost if the process dies.

Minimal ACL for the HaltSQL principal:

```sh
kafka-acls.sh --bootstrap-server … --add --allow-principal User:haltsql \
  --operation Write --operation Describe --topic haltsql.audit
```

### Verifying from Kafka

Read the topic with the broker's own console consumer. Print the key, so
each chain can be told apart, and run the verifier:

```sh
kafka-console-consumer.sh --bootstrap-server kafka-1:9093 \
  --consumer.config client.properties --topic haltsql.audit --from-beginning \
  --timeout-ms 30000 --property print.key=true --property key.separator=$'\t' \
  > audit.tsv
python3 verify_chain.py kafka audit.tsv
# chain haltsql/haltsql-7f9c/20240601T115900.042000Z.7: 5120 records from genesis, head 4f0c…
# OK: 5120 records in 1 chain(s)
```

Message values are the exact bytes HaltSQL hashed, so the verifier hashes
them as they are (no re-serialization). With several partitions, read them
all: each chain lives in one partition, in offset order. Records deleted by
retention make a chain start mid-stream. The verifier then exits with status
1 (records before the chain are missing); `--any-start` verifies from there. Use `cleanup.policy=delete` with a long `retention.ms`,
or tiered storage, for audit topics. Never use compaction: it keeps one
record per key, and every record of a chain has the same key.

## Verifying a chain

From OCaml, call `Haltsql_cloud.Audit_chain.verify_lines`. It accepts
`?initial_prev:None` for a chain that starts mid-stream. For Kafka and
Elasticsearch/OpenSearch exports, use `verify_chain.py` (see
[Verifying from Kafka](#verifying-from-kafka) and
[Verifying from Elasticsearch or OpenSearch](#verifying-from-elasticsearch-or-opensearch)). Without OCaml, this
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
