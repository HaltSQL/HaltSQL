# Observability

`haltsql-server` gives you three kinds of signal:

| Signal | Where | Configured by |
|---|---|---|
| Prometheus metrics | `GET /metrics` | `telemetry.metrics.prometheus` |
| OpenTelemetry traces and metrics | pushed over OTLP/HTTP (JSON) | `telemetry.otlp` |
| Structured logs | stderr (JSON or text) | `logging` |

The audit log is separate. It is a hash-chained compliance record, not
telemetry; see [audit-sinks.md](audit-sinks.md).

## OpenTelemetry export

```yaml
telemetry:
  otlp:
    endpoint: https://otel-collector.observability:4318
    headers:
      authorization: "Bearer ${vault:secret/data/haltsql/otel#token}"
    service_name: haltsql-support-bot
    traces: true
    metrics: true
    export_interval_seconds: 15
    timeout_seconds: 5
```

The exporter (library `haltsql-server.telemetry`, module `Exporter`) speaks
**OTLP/HTTP with the JSON encoding**. Any OpenTelemetry Collector with the
`otlp` receiver and its `http` protocol enabled accepts it, and so do most vendor endpoints that take
OTLP/HTTP. Data is posted to:

- `<endpoint>/v1/traces`: an `ExportTraceServiceRequest`
  (`resourceSpans`, then `scopeSpans`, then `spans`);
- `<endpoint>/v1/metrics`: an `ExportMetricsServiceRequest`
  (`resourceMetrics`, then `scopeMetrics`, then `metrics`).

Encoding follows the OTLP JSON mapping:

- trace and span ids are lower-case hex;
- 64-bit integers (timestamps, `asInt`, `count`, `bucketCounts`) are decimal
  strings;
- enums are integers.

Resource attributes are `service.name`, `service.version`,
`telemetry.sdk.name=haltsql`, `telemetry.sdk.language=ocaml` and
`host.name`.

### Traces

Each `POST /v1/verify` produces one `SERVER` span named `haltsql.verify`:

| Attribute | Example |
|---|---|
| `haltsql.policy` | `support-bot` |
| `haltsql.policy_version` | `2024-06-01` |
| `haltsql.allowed` | `false` |
| `haltsql.shadow` | `false` (true when shadow-mode denials were recorded) |
| `haltsql.reason_codes` | `["E_TABLE_DENIED"]` (enforced codes, then shadow codes) |
| `db.system` | `postgresql` |
| `db.statement.sha256` | SHA-256 of the exact SQL string |
| `haltsql.elapsed_us` | `183` |

**The SQL text is never exported**, not even with `audit.log_raw_sql: true`.
To correlate a span with an audit record, join on `db.statement.sha256` =
`sql_sha256`.

A span's status is OK when the request was verified, including when the SQL
was denied: a denial is a correct answer, not an error. The status is ERROR
only when the request itself failed.

**Context propagation.** An incoming W3C `traceparent` header is honoured: the
verify span joins that trace, and its parent is the caller's span. The span is
exported only when the caller's sampled flag is set. A missing or malformed
header starts a new, sampled trace. The parser follows the spec strictly:

- hex must be lower-case;
- all-zero ids and version `ff` are rejected;
- future versions may carry extra fields.

### Metrics

OTLP metrics have the same names as the Prometheus metrics on `/metrics`, so
dashboards work with either. They are cumulative: monotonic sums for counters
and explicit-bucket histograms.

| Metric | Type | Attributes |
|---|---|---|
| `haltsql_verify_total` | sum | `policy`, `result` (`allowed`, `denied`, `shadow_denied`) |
| `haltsql_reasons_total` | sum | `code` |
| `haltsql_verify_duration_seconds` | histogram, buckets 0.1 ms to 1 s | none |
| `haltsql_policy_reload_total` | sum | `result` (`success`, `error`) |
| `haltsql_audit_errors_total` | sum | none |
| `haltsql_http_requests_total` | sum | `route`, `status` |
| `haltsql_policies_loaded` | gauge | none |
| `haltsql_otlp_spans_dropped_total` | sum | none |

The cloud audit sinks add `haltsql_audit_sink_*` metrics to `/metrics`; see
[audit-sinks.md](audit-sinks.md#metrics-and-alerts).

### Delivery guarantees

Telemetry must never slow down or break verification, so:

- **Finished spans go into a bounded queue** (2048 by default). Recording a
  span is a constant-time, non-blocking operation. When the queue is full,
  new spans are dropped and counted in `haltsql_otlp_spans_dropped_total`.
- **Export runs in the background.** It runs every `export_interval_seconds`,
  and immediately once a batch of 512 spans is waiting.
- **Every POST has a deadline** of `timeout_seconds`.
- **Failed exports are retried with exponential backoff** (0.5 s, doubling,
  capped at 30 s, up to 5 retries). Retries happen on network errors,
  timeouts, `429`, `500`, `502`, `503` and `504`. A `Retry-After` header
  (delta-seconds or HTTP-date) takes precedence over the backoff and is
  capped at 30 s. Any other status drops the batch without retrying. A batch
  that still fails after all retries is dropped and counted.
- **Header values are never logged.** Treat them as secrets; they usually
  hold collector credentials. Export failures are logged with the path,
  status and cause only.
- **gzip compression** (`Content-Encoding: gzip`) is supported by the library
  (`Exporter.create ~gzip:true`).

### Recommended alerts

| Condition | Meaning |
|---|---|
| `rate(haltsql_otlp_spans_dropped_total[5m]) > 0` | The collector is unreachable or too slow. Verification is unaffected. This counter is exported over OTLP, not on `/metrics`, so alert on it in the backend that receives the OTLP metrics. |
| `rate(haltsql_audit_errors_total[5m]) > 0` | An audit sink is failing. With `fail_closed`, requests are being refused. |
| `haltsql_audit_sink_healthy == 0` | A cloud audit sink is refusing writes. |
| `histogram_quantile(0.99, rate(haltsql_verify_duration_seconds_bucket[5m])) > 0.05` | Verification is slower than expected. |

## Library API (for embedders)

```ocaml
let exporter =
  match Haltsql_telemetry.Exporter.of_config ~service_version:"0.2.0" cfg.otlp with
  | Ok e -> e
  | Error msg -> failwith msg
in
Haltsql_telemetry.Exporter.start exporter;            (* inside Lwt_main.run *)
let span = Exporter.start_verify exporter ?traceparent:(header "traceparent") () in
let verdict = Haltsql.verify policy ctx sql in
Exporter.end_verify exporter span verdict;
Exporter.observe_verify exporter ~policy ~result ~codes ~seconds;
(* on shutdown *)
Exporter.shutdown exporter
```

`Exporter.noop` is a disabled exporter, so callers do not need to branch.
