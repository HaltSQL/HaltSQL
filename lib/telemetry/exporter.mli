(** OpenTelemetry exporter for haltsql-server (OTLP/HTTP with JSON encoding).

    {1 Model}

    - {b Traces}: finished spans go into a bounded in-memory queue. [end_span] never
      blocks and never fails: when the queue is full the span is dropped and counted
      ([spans_dropped], and the [haltsql_otlp_spans_dropped_total] metric). A background
      loop posts batches to [<endpoint>/v1/traces] every [export_interval_seconds], or as
      soon as [max_batch] spans are waiting.
    - {b Metrics}: in-process cumulative instruments (monotonic sums, gauges and
      explicit-bucket histograms) whose names mirror the Prometheus metrics of [/metrics]
      ([haltsql_verify_total], [haltsql_verify_duration_seconds], ...). A snapshot is
      posted to [<endpoint>/v1/metrics] every interval.
    - {b Delivery}: each POST has a [timeout_seconds] deadline and is retried with
      exponential backoff on network errors, timeouts, 429 and retryable 5xx responses
      (500, 502, 503, 504), honouring [Retry-After] (seconds or HTTP-date, capped at
      [max_backoff]). Other statuses drop the batch. Configured headers are sent on every
      request and never logged; bodies may be gzip-compressed.

    {1 Privacy}

    Verify spans carry [haltsql.policy], [haltsql.allowed], [haltsql.reason_codes] and
    [db.statement.sha256] — never the SQL text.

    {1 Concurrency}

    Lwt-based; call [start] once inside the server's Lwt main loop. All recording
    functions are synchronous and safe to call from request handlers. *)

module Config = Haltsql_load.Config

type t

val noop : t
(** A disabled exporter: every function is a cheap no-op. *)

val create :
  ?max_queue:int ->
  ?max_batch:int ->
  ?gzip:bool ->
  ?max_retries:int ->
  ?base_backoff:float ->
  ?max_backoff:float ->
  ?service_version:string ->
  ?resource_attributes:(string * string) list ->
  ?on_error:(string -> unit) ->
  ?now:(unit -> float) ->
  Config.otlp ->
  (t, string) result
(** Defaults: [max_queue] 2048 spans, [max_batch] 512, [gzip] false, [max_retries] 5,
    [base_backoff] 0.5 s (doubling per attempt), [max_backoff] 30 s. [on_error] receives
    one human-readable line per failed export (status codes and causes only; never header
    values or payloads). Fails if the endpoint is not an http(s) URL. *)

val of_config :
  ?gzip:bool ->
  ?service_version:string ->
  ?on_error:(string -> unit) ->
  Config.otlp option ->
  (t, string) result
(** [noop] for [None]. *)

val enabled : t -> bool
(** [false] for the no-op exporter. *)

val start : t -> unit
(** Starts the background export loop (idempotent). *)

val flush : t -> unit Lwt.t
(** Exports every queued span and a metrics snapshot now. *)

val shutdown : t -> unit Lwt.t
(** Stops the loop and performs a final [flush]. *)

(** {1 Spans} *)

type span

val start_span :
  t ->
  ?parent:Traceparent.t ->
  ?kind:Otlp_json.span_kind ->
  ?attrs:Otlp_json.attrs ->
  string ->
  span
(** Starts a span; with [parent] it joins that trace (and inherits its sampled flag,
    unsampled spans are never exported). Default kind [Internal]. *)

val set_attribute : span -> string -> Otlp_json.value -> unit
(** Adds or replaces an attribute. *)

val set_status : span -> Otlp_json.status -> unit
(** Sets the span status. *)

val end_span : t -> span -> unit
(** Ends the span and enqueues it (idempotent; never blocks). *)

val traceparent : span -> Traceparent.t
(** This span's context, for a response [traceparent] header or downstream calls. *)

val span_trace_id : span -> string
(** 32 lower-case hex characters. *)

val span_id : span -> string
(** 16 lower-case hex characters. *)

val start_verify : t -> ?traceparent:string -> unit -> span
(** A [SERVER] span named [haltsql.verify]. [traceparent] is the raw incoming header; an
    invalid header starts a new trace. *)

val end_verify : t -> span -> Haltsql_core.Verdict.t -> unit
(** Sets [haltsql.policy], [haltsql.policy_version], [haltsql.allowed], [haltsql.shadow],
    [haltsql.reason_codes] (enforced then shadow codes), [db.system],
    [db.statement.sha256] and [haltsql.elapsed_us], status OK, then ends the span. *)

val end_verify_error : t -> span -> string -> unit
(** Ends the span with an error status. The message must not contain SQL or secrets. *)

(** {1 Metrics} *)

val counter_add :
  t ->
  ?description:string ->
  ?unit_:string ->
  ?attrs:(string * string) list ->
  string ->
  int ->
  unit
(** Adds to a monotonic counter (negative increments are ignored). *)

val gauge_set :
  t ->
  ?description:string ->
  ?unit_:string ->
  ?attrs:(string * string) list ->
  string ->
  float ->
  unit
(** Records the latest value of a gauge. *)

val histogram_record :
  t ->
  ?description:string ->
  ?unit_:string ->
  ?bounds:float array ->
  ?attrs:(string * string) list ->
  string ->
  float ->
  unit
(** The bounds of a histogram are fixed by its first recording (default
    {!duration_buckets}). *)

val duration_buckets : float array
(** The [haltsql_verify_duration_seconds] buckets of [/metrics]. *)

val observe_verify :
  t -> policy:string -> result:string -> codes:string list -> seconds:float -> unit
(** Mirrors [Metrics.observe_verify]: [haltsql_verify_total{policy,result}],
    [haltsql_reasons_total{code}] and [haltsql_verify_duration_seconds]. *)

val observe_reload : t -> ok:bool -> unit
(** [haltsql_policy_reload_total{result=success|error}]. *)

val observe_http : t -> route:string -> status:int -> unit
(** [haltsql_http_requests_total{route,status}]. *)

val observe_audit_error : t -> unit
(** [haltsql_audit_errors_total]. *)

val set_policies_loaded : t -> int -> unit
(** [haltsql_policies_loaded]. *)

val metrics_snapshot : t -> Otlp_json.metric list
(** The current cumulative instruments, sorted by name. *)

(** {1 Introspection} *)

type stats = {
  spans_queued : int;  (** currently waiting *)
  spans_exported : int;
  spans_dropped : int;  (** queue full, or batch dropped after failed export *)
  batches_sent : int;
  export_failures : int;  (** POSTs that ultimately failed (traces and metrics) *)
  retries : int;
  metric_exports : int;
}

val stats : t -> stats
(** Counters for monitoring and tests. *)

(** {1 Helpers (exposed for tests)} *)

val parse_retry_after : now:float -> string -> float option
(** Seconds to wait for a [Retry-After] value: delta-seconds or an IMF-fixdate. *)

val random_hex : int -> string
(** [n] random bytes as lower-case hex (never all zeros). *)
