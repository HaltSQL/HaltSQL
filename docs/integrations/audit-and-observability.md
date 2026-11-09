# Audit and observability destinations

`haltsql-server` produces two kinds of output: a hash-chained **audit log**
(one record per verify request, the compliance record) and **telemetry**
(Prometheus metrics, OpenTelemetry traces and metrics, logs). This page gives
a recipe per destination, and shows how to reach a SIEM through the
destinations HaltSQL supports. The references are
[audit-sinks.md](../audit-sinks.md), [audit-verify.md](../audit-verify.md)
and [observability.md](../observability.md).

Destinations covered:

- Audit: [Amazon S3](#amazon-s3), [Google Cloud Storage](#google-cloud-storage),
  [Apache Kafka](#apache-kafka), [Elasticsearch](#elasticsearch),
  [OpenSearch](#opensearch)
- Telemetry: [OpenTelemetry Collector](#opentelemetry-collector),
  [Prometheus](#prometheus)
- [SIEMs (Splunk, Datadog, Microsoft Sentinel, ...)](#forwarding-to-a-siem)

## Choosing destinations

| Destination | Native | Byte-exact, verifiable copy | Survives a crash | Use for |
|---|---|---|---|---|
| `stdout`, `file` | yes | yes | `file`: yes (appended per record) | log pipelines; the source for most SIEM agents |
| Amazon S3 (and S3-compatible stores) | yes, `type: s3` | yes, with optional Object Lock | with `spool_dir` | the compliance archive on AWS or MinIO |
| Google Cloud Storage | yes, `type: gcs` | yes, with a bucket retention policy | with `spool_dir` | the compliance archive on GCP |
| Apache Kafka | yes, `type: kafka` | yes (message values are the exact records) | no (in-memory queue) | feeding SIEM and data-lake pipelines |
| Elasticsearch, OpenSearch | yes, `type: elasticsearch` | yes, through `event.original` | no (in-memory queue) | search, dashboards, detection rules |
| Splunk, Datadog, Sentinel, other SIEMs | no | depends on the forwarder | depends on the forwarder | detection, through one of the destinations above |
| OpenTelemetry Collector | yes, `telemetry.otlp` | (telemetry, not audit) | | traces and metrics to any OTLP backend |
| Prometheus | yes, `GET /metrics` | (telemetry, not audit) | | metrics and alerts |

Every audit sink keeps its own hash chain, and sinks can be combined: list
them all under `audit.sinks`. A common production setup is one
**verifiable archive** (S3 or GCS with a spool directory, in `fail_closed`
mode) plus one **detection feed** (Kafka or Elasticsearch, in `buffer`
mode). Audit sinks are fixed at startup; changing `audit.sinks` needs a
restart.

Each record looks like this (`sql` only appears with `audit.log_raw_sql:
true`):

```json
{"ts":"2026-11-07T12:00:00Z","request_id":"...","caller":"oidc:corp-okta","caller_type":"oidc",
 "subject":"00u1abcd","policy":"support-bot","policy_version":"sha256:4f1c...","allowed":false,
 "shadow":false,"codes":["E_TENANT_MISSING"],"sql_sha256":"...","fingerprint":"0a9d55c2e1f04b7c",
 "elapsed_us":183,"prev_hash":"<64 hex>","hash":"<64 hex>"}
```

> **Note:** `haltsql-proxy` supports the `stdout`, `file`, `s3` and `gcs`
> sinks with the same keys, but not `elasticsearch` or `kafka`
> ([proxy.md](../proxy.md#audit-and-logs)).

## Amazon S3

**Config.**

```yaml
audit:
  sinks:
    - type: s3
      bucket: corp-haltsql-audit
      region: eu-west-1
      prefix: haltsql/audit/
      object_lock: { mode: COMPLIANCE, retain_days: 365 }
      credentials: { source: web_identity }        # env | static | web_identity | instance
      spool_dir: /var/lib/haltsql/spool/s3         # persistent volume, one per sink
      batch: { max_records: 500, max_seconds: 10 }
      on_error: fail_closed
```

Records are batched into objects named
`<prefix>YYYY/MM/DD/HH/<host>-<run>-<seq>-<sha256>.jsonl`, uploaded strictly
in order with create-only PUTs. For S3-compatible stores (MinIO, Ceph), set
`endpoint`; requests then use path-style URLs.

**Bucket and IAM.** Create the bucket with Object Lock enabled if you use
`object_lock` (S3 refuses the lock headers otherwise). The identity needs:

```json
{"Effect": "Allow",
 "Action": ["s3:PutObject", "s3:PutObjectRetention"],
 "Resource": "arn:aws:s3:::corp-haltsql-audit/haltsql/audit/*"}
```

Credentials come from `credentials.source`: `env` (default), `static` (use
secret placeholders), `web_identity` (EKS IRSA) or `instance` (EC2 IMDSv2).
ECS task roles and EKS Pod Identity are not supported by the S3 sink; see
[Audit on ECS](../deploy-aws.md#audit-on-ecs) for the alternatives.

**Verify.** Read the objects straight from the bucket (the identity needs
`s3:ListBucket` and `s3:GetObject`):

```sh
haltsql audit verify --region eu-west-1 s3://corp-haltsql-audit/haltsql/audit/
# one day only: the chain starts mid-stream
haltsql audit verify --region eu-west-1 --any-start s3://corp-haltsql-audit/haltsql/audit/2026/11/07/
```

**Alerts.** `haltsql_audit_sink_healthy{sink="s3://corp-haltsql-audit/haltsql/audit/"} == 0`,
`rate(haltsql_audit_sink_upload_failures_total[5m]) > 0` and
`haltsql_audit_sink_pending_objects > 0` for longer than a few
`max_seconds`. Details: [S3](../audit-sinks.md#s3).

## Google Cloud Storage

**Config.**

```yaml
audit:
  sinks:
    - type: gcs
      bucket: corp-haltsql-audit
      prefix: haltsql/audit/
      credentials: { source: metadata }            # or { source: service_account_file, file: /var/run/gcp/key.json }
      spool_dir: /var/lib/haltsql/spool/gcs
      on_error: fail_closed
```

Objects have the same names and ordering as for S3, and are uploaded with
`ifGenerationMatch=0` so an existing object is never overwritten.

**Bucket and IAM.** Grant the identity `roles/storage.objectCreator` on the
bucket. For WORM storage, set a bucket retention policy and lock it (Bucket
Lock). On GKE, use Workload Identity with `source: metadata`.

**Verify.** GCS is not read directly by `haltsql audit verify`; download the
objects and verify the directory:

```sh
gcloud storage cp -r gs://corp-haltsql-audit/haltsql/audit/ ./audit/
haltsql audit verify ./audit/
```

**Alerts.** The same `haltsql_audit_sink_*` metrics as S3, with
`sink="gs://corp-haltsql-audit/haltsql/audit/"`. Details:
[GCS](../audit-sinks.md#gcs).

## Apache Kafka

**Config.**

```yaml
audit:
  sinks:
    - type: kafka
      brokers: [kafka-1.corp.example:9093, kafka-2.corp.example:9093]
      topic: haltsql.audit
      client_id: haltsql-prod
      acks: all
      tls: { ca_file: /etc/haltsql/kafka/ca.pem }
      sasl: { mechanism: scram-sha-512, username: haltsql, password: "${vault:secret/data/haltsql/kafka#password}" }
      on_error: buffer
      max_buffer_records: 20000
```

Each record is one message whose value is the exact sealed record and whose
key is the chain id `haltsql/<host>/<run>`, so a process's records stay in
one partition, in order.

**Broker side.**

- Create the topic first; HaltSQL never creates topics. Use
  `cleanup.policy=delete` with a long retention. Never use compaction: all
  records of a chain share one key.
- Grant the principal `Write` and `Describe` on the topic:

  ```sh
  kafka-acls.sh --bootstrap-server … --add --allow-principal User:haltsql \
    --operation Write --operation Describe --topic haltsql.audit
  ```

- Supported: TLS (with optional client certificates), SASL `PLAIN`,
  `SCRAM-SHA-256` and `SCRAM-SHA-512`, `acks: all` or `1`, Kafka 1.0 and
  later (tested against Apache Kafka 3.9). Not supported: compression,
  transactions, the idempotent producer, OAUTHBEARER (and the IAM
  mechanisms of managed services built on it) and GSSAPI/Kerberos. A managed
  Kafka service works if it offers one of the supported SASL mechanisms; such
  services are not tested.

**Delivery is at least once.** A retried batch can appear twice in the
partition. Verify with `--allow-redelivery` or the repository's verifier
script, which skip exact re-deliveries.

**Verify.**

```sh
kafka-console-consumer.sh --bootstrap-server kafka-1:9093 \
  --consumer.config client.properties --topic haltsql.audit --from-beginning \
  --timeout-ms 30000 --property print.key=true --property key.separator=$'\t' > audit.tsv
python3 verify_chain.py kafka audit.tsv
```

`verify_chain.py` is [`test/siem/verify_chain.py`](../../test/siem/verify_chain.py).

**Alerts.** `haltsql_audit_stream_sink_healthy == 0`,
`haltsql_audit_stream_sink_delivering == 0`,
`rate(haltsql_audit_stream_sink_records_dropped_total[5m]) > 0` (labels
`sink="kafka://kafka-1.corp.example:9093/haltsql.audit"`, `type="kafka"`).
Details: [Kafka](../audit-sinks.md#kafka).

## Elasticsearch

**Config.**

```yaml
audit:
  sinks:
    - type: elasticsearch
      urls: [https://es-1.corp.example:9200, https://es-2.corp.example:9200]
      data_stream: logs-haltsql-prod                # or index: haltsql-audit
      auth: { api_key: "${vault:secret/data/haltsql/es#api_key}" }
      tls: { ca_file: /etc/haltsql/es-ca.pem }
      on_error: buffer
```

The sink only uses the `_bulk` API with `create` actions whose `_id` is the
record's hash. Each document holds the record's fields (searchable) and
`event.original`, the exact sealed line.

**Cluster side.** Create an API key whose role can only create documents:

```json
{"haltsql-audit": {"indices": [{"names": ["logs-haltsql-*"],
                                "privileges": ["create_doc", "auto_configure"]}]}}
```

Put the index under an ILM policy without a delete phase, or snapshot it to
a WORM repository, if it must not be deleted. With an `index` instead of a
data stream, create an index template first or rely on dynamic mapping.

**Verify.** Export the documents and check them against `event.original`:

```sh
curl -s --cacert es-ca.pem -H "Authorization: ApiKey $KEY" -H 'Content-Type: application/json' \
  "https://es-1.corp.example:9200/logs-haltsql-prod/_search" \
  -d '{"size":10000,"query":{"range":{"@timestamp":{"gte":"2026-11-07","lt":"2026-11-08"}}}}' > day.json
python3 verify_chain.py es --any-start day.json
```

An ingest `pipeline` that adds or changes fields makes the field check fail
even though `event.original` verifies; enrich into a separate index instead.

**Alerts.** The `haltsql_audit_stream_sink_*` metrics with
`type="elasticsearch"`. Watch
`haltsql_audit_stream_sink_records_dropped_total{reason="mapping"}`: a field
that changes type is dropped, which leaves a gap in the chain. Details:
[Elasticsearch and OpenSearch](../audit-sinks.md#elasticsearch-and-opensearch).

## OpenSearch

OpenSearch uses the same `type: elasticsearch` sink: it only needs the
`_bulk` API.

```yaml
audit:
  sinks:
    - type: elasticsearch
      url: https://opensearch.corp.example:9200
      index: haltsql-audit                          # or data_stream:, with a matching index template
      auth: { username: haltsql, password: "${aws-sm:prod/haltsql/opensearch#password}" }
      tls: { ca_file: /etc/haltsql/opensearch-ca.pem }
      on_error: buffer
```

- **Authentication** is basic auth (`username`/`password`) for OpenSearch's
  security plugin. Give the user a role that can write (create) documents in
  the index; see the OpenSearch security documentation.
- **Not supported:** AWS SigV4 request signing, so Amazon OpenSearch Service
  domains that only accept IAM-signed requests cannot be used. A domain with
  fine-grained access control and an internal user (basic auth) can.
- **Tested** against OpenSearch 2.17 (index and data stream) without the
  security plugin; TLS and authentication are tested against Elasticsearch.

Verification and metrics are as for [Elasticsearch](#elasticsearch).

## OpenTelemetry Collector

HaltSQL pushes traces and metrics over **OTLP/HTTP with JSON encoding** to
`<endpoint>/v1/traces` and `<endpoint>/v1/metrics`. gRPC is not supported.

**HaltSQL config.**

```yaml
telemetry:
  otlp:
    endpoint: http://otel-collector.observability:4318
    headers:
      authorization: "Bearer ${vault:secret/data/haltsql/otel#token}"
    service_name: haltsql-support-bot
    traces: true
    metrics: true
    export_interval_seconds: 15
    timeout_seconds: 5
```

`telemetry.otlp` is applied on reload. Header values are treated as secrets
and never logged.

**Collector config.** The `otlp` receiver with the `http` protocol accepts
it; route the data to any exporter your backend supports:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
processors:
  batch: {}
exporters:
  debug: {}            # replace with your backend's exporter
service:
  pipelines:
    traces:  { receivers: [otlp], processors: [batch], exporters: [debug] }
    metrics: { receivers: [otlp], processors: [batch], exporters: [debug] }
```

Complete collector deployments are in
[`deploy/cloud/gcp/gke/otel-collector.yaml`](../../deploy/cloud/gcp/gke/otel-collector.yaml)
(Google Cloud exporter) and
[`deploy/cloud/azure/aks/otel-collector.yaml`](../../deploy/cloud/azure/aks/otel-collector.yaml)
(Azure Monitor).

**What you get.** One `SERVER` span named `haltsql.verify` per verify
request, with `haltsql.policy`, `haltsql.allowed`, `haltsql.reason_codes`
and `db.statement.sha256` (never the SQL text), joined to the caller's trace
through `traceparent`. Metrics have the same names as on `/metrics`. Join a
span to its audit record on `db.statement.sha256` = `sql_sha256`. Spans
are dropped, never queued without bound, when the collector is slow:
alert on `rate(haltsql_otlp_spans_dropped_total[5m]) > 0` in your OTLP
backend (this metric is exported over OTLP only, not on `/metrics`).
Verification is never slowed down by telemetry. Details:
[OpenTelemetry export](../observability.md#opentelemetry-export).

## Prometheus

`GET /metrics` serves the Prometheus text format on the main listener when
`telemetry.metrics.prometheus` is `true` (the default; `--no-metrics` turns
it off). It needs no bearer token, so restrict who can reach it with network
policy. It is not served on the `--health-listen` port.

**Scrape config.**

```yaml
scrape_configs:
  - job_name: haltsql
    metrics_path: /metrics
    scheme: https                                  # http when HaltSQL has no server.tls
    tls_config:
      ca_file: /etc/prometheus/haltsql-ca.pem
      # With server.tls.client_auth: required, Prometheus must present a
      # certificate signed by server.tls.client_ca:
      cert_file: /etc/prometheus/haltsql-client.crt
      key_file: /etc/prometheus/haltsql-client.key
    static_configs:
      - targets: ['haltsql.internal:8443']
```

On Kubernetes with the Helm chart, set `serviceMonitor.enabled: true`
(Prometheus Operator) or `podMonitoring.enabled: true` (Google Managed
Prometheus; not with the chart's TLS), and allow the scraper in
`networkPolicy.metricsFrom`.

**Metric names.**

| Metric | Type | Labels |
|---|---|---|
| `haltsql_build_info` | gauge | `version`, `pg` |
| `haltsql_policies_loaded` | gauge | |
| `haltsql_verify_total` | counter | `policy`, `result` (`allowed`, `denied`, `shadow_denied`) |
| `haltsql_reasons_total` | counter | `code` |
| `haltsql_verify_duration_seconds` | histogram | |
| `haltsql_policy_reload_total` | counter | `result` (`success`, `error`) |
| `haltsql_audit_errors_total` | counter | |
| `haltsql_http_requests_total` | counter | `route`, `status` |
| `haltsql_auth_total` | counter | `method` (`token`, `oidc`, `mtls`, `anonymous`, `none`), `result` (`ok`, `rejected`, `unavailable`) |
| `haltsql_tls_reload_total` | counter | `result` |
| `haltsql_opa_decisions_total` | counter | `outcome` (`skipped`, `allowed`, `denied`, `error_allowed`, `error_denied`) |
| `haltsql_opa_duration_seconds` | summary | |
| `haltsql_admin_requests_total` | counter | `endpoint`, `result` |
| `haltsql_bundle_source_healthy` | gauge | `source` |
| `haltsql_bundle_source_checks_total` | counter | `source` |
| `haltsql_audit_sink_healthy`, `haltsql_audit_sink_buffered_records`, `haltsql_audit_sink_pending_objects` | gauge | `sink` (S3/GCS sinks) |
| `haltsql_audit_sink_objects_uploaded_total`, `haltsql_audit_sink_upload_failures_total`, `haltsql_audit_sink_rejected_writes_total` | counter | `sink` |
| `haltsql_audit_stream_sink_healthy`, `haltsql_audit_stream_sink_delivering`, `haltsql_audit_stream_sink_buffered_records` | gauge | `sink`, `type` (Kafka/Elasticsearch sinks) |
| `haltsql_audit_stream_sink_records_written_total`, `haltsql_audit_stream_sink_records_delivered_total`, `haltsql_audit_stream_sink_delivery_failures_total`, `haltsql_audit_stream_sink_retries_total`, `haltsql_audit_stream_sink_rejected_writes_total` | counter | `sink`, `type` |
| `haltsql_audit_stream_sink_records_dropped_total` | counter | `sink`, `type`, `reason` (`mapping`, `too_large`, `on_error_drop`) |

`haltsql_otlp_spans_dropped_total` is exported over OTLP only. The sink
metrics only appear when such a sink is configured.

**Suggested alerts.**

```yaml
groups:
  - name: haltsql
    rules:
      - alert: HaltSQLAuditSinkUnhealthy          # requests are getting 503
        expr: haltsql_audit_sink_healthy == 0 or haltsql_audit_stream_sink_healthy == 0
        for: 1m
      - alert: HaltSQLAuditErrors
        expr: rate(haltsql_audit_errors_total[5m]) > 0
      - alert: HaltSQLAuditDeliveryFailing        # also in buffer and drop modes
        expr: haltsql_audit_stream_sink_delivering == 0
        for: 5m
      - alert: HaltSQLAuditRecordsDropped         # gaps in a streaming sink's chain
        expr: rate(haltsql_audit_stream_sink_records_dropped_total[5m]) > 0
      - alert: HaltSQLAuditUploadsStuck
        expr: haltsql_audit_sink_pending_objects > 0
        for: 10m
      - alert: HaltSQLInternalError
        expr: increase(haltsql_reasons_total{code="E_INTERNAL"}[5m]) > 0
      - alert: HaltSQLPolicyReloadFailed          # the last good config is still active
        expr: increase(haltsql_policy_reload_total{result="error"}[10m]) > 0
      - alert: HaltSQLBundleSourceUnhealthy
        expr: haltsql_bundle_source_healthy == 0
        for: 10m
      - alert: HaltSQLIdPKeysUnavailable          # OIDC callers are getting 503
        expr: rate(haltsql_auth_total{method="oidc",result="unavailable"}[5m]) > 0
      - alert: HaltSQLOPAErrorsDenied
        expr: increase(haltsql_opa_decisions_total{outcome="error_denied"}[5m]) > 0
      - alert: HaltSQLSlowVerification
        expr: histogram_quantile(0.99, rate(haltsql_verify_duration_seconds_bucket[5m])) > 0.05
        for: 10m
      - alert: HaltSQLDown
        expr: up{job="haltsql"} == 0
        for: 2m
```

Add severities, labels and routing to suit your Alertmanager. For dashboards,
`haltsql_verify_total` by `result` and `haltsql_reasons_total` by `code` show
what agents attempt and why it is denied; `result="shadow_denied"` shows what
a shadow-mode policy would deny before you enforce it.

## Forwarding to a SIEM

HaltSQL has **no native Splunk, Datadog or Microsoft Sentinel integration**.
It reaches them through the destinations above: the SIEM's own collector
reads the records from a file, container stdout, a Kafka topic or a bucket.
Elasticsearch and OpenSearch are native destinations, so their security
tooling can query the index directly.

| SIEM | Supported route (configure the SIEM side with its vendor's documentation) |
|---|---|
| Splunk | A `kafka` sink and Splunk's Kafka connector; or an `s3` sink and Splunk's AWS add-on; or a `file`/`stdout` sink and a Splunk forwarder or collector. |
| Datadog | A `file` or `stdout` sink collected by the Datadog Agent's log collection; or an `s3` sink with Datadog's S3 log forwarding. |
| Microsoft Sentinel | A `stdout` sink collected into Log Analytics (for example by Container Insights on AKS), or a `file` sink shipped by an agent. See [Deploying on Azure](../deploy-azure.md). |
| Elastic Security, OpenSearch Security Analytics | The `elasticsearch` sink, natively. |
| Anything that consumes Kafka, S3 or GCS | The matching sink. |

Things to keep in mind:

- **Keep a verifiable copy outside the SIEM.** Forwarders and SIEMs parse
  and re-serialize JSON, so the stored record may no longer be the exact
  bytes the hash covers, and SIEM retention is usually shorter than audit
  retention. Treat the SIEM copy as the detection feed, and keep a separate
  `s3`/`gcs` (with a spool directory), `file` or `kafka` sink as the record
  you verify with [`haltsql audit verify`](../audit-verify.md) or
  `verify_chain.py`.
- **Do not let the SIEM path stop verification.** Give the detection sink
  `on_error: buffer` (or, for `kafka` and `elasticsearch` sinks, `drop`,
  only next to a `fail_closed` sink), so a SIEM outage does not turn into
  `503`s.
- **Raw SQL stays out by default.** Records carry `sql_sha256` and the
  `fingerprint`, not the SQL, unless `audit.log_raw_sql: true`. Leave it off
  unless the SIEM is cleared to hold query literals.

**Useful detections**, on the record fields:

| Detection | Condition |
|---|---|
| Tenant bypass attempts | `codes` contains `E_TENANT_MISSING` or `E_TENANT_MISMATCH` |
| Probing for sensitive data | repeated `E_COLUMN_DENIED` or `E_TABLE_DENIED` for one `caller` or `subject` |
| Write attempts by a read-only agent | `codes` contains `E_STATEMENT_KIND` or `E_WRITE_DENIED` |
| Unexpected callers | `caller_type` is `anonymous` in production, or an unknown `caller` |
| Engine faults | `codes` contains `E_INTERNAL` |
| Policy drift | a `policy_version` you did not deploy |

Reason codes are listed in [reason-codes.md](../reason-codes.md).

## Related

- [Audit sinks](../audit-sinks.md): sink internals, failure modes, spool
  directories and metrics.
- [Verifying audit chains](../audit-verify.md): `haltsql audit verify`.
- [Observability](../observability.md): OTLP export, traces and metric
  semantics.
- [Config reference: audit](../config-reference.md#audit) and
  [telemetry](../config-reference.md#telemetry).
- [HTTP API: GET /metrics](../http-api.md#get-metrics).
- [Secrets managers](secrets-managers.md): credentials for sinks and
  collectors.
