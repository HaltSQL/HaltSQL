(** Batching engine shared by the streaming audit sinks (Elasticsearch / OpenSearch and
    Kafka). It has the same contract as {!Haltsql_cloud.Object_sink}: [write] seals the
    record into the sink's hash chain ({!Haltsql_cloud.Audit_chain}) synchronously and
    never waits on the network; a background loop ships batches; [on_error] decides what
    happens while the destination is unreachable.

    {1 Batches}

    Sealed records wait in an in-memory queue, in chain order. A batch is shipped when the
    queue holds [batch_max_records] records or [batch_max_bytes] bytes, or when its oldest
    record is [flush_interval_ms] old. A batch holds at most [batch_max_records] records
    and [batch_max_bytes] bytes of record lines (at least one record, even if it alone is
    larger).

    {1 Delivery and retries}

    The transport ({!deliver}) answers per record. Delivered records leave the queue;
    [Rejected] records (e.g. an Elasticsearch mapping error) leave it too and are counted
    under their reason in [records_dropped] and reported through [on_event] (hash and
    reason only, never the record): they are never dropped silently. [Retry] records are
    sent again, alone, on the next attempt. A whole-request [Error] retries every record.
    A batch gets [max_attempts] attempts, with exponential backoff and jitter between them
    ([base_backoff * 2^n], capped at [max_backoff], times a random factor from 0.5 to 1.5).
    After the last attempt the batch stays at the head of the queue (nothing overtakes it)
    and the sink is {e failing}: the background loop retries it after a growing, jittered
    delay (from [base_backoff] up to [max_backoff]).

    {1 Failure policy}

    - [Stream_fail_closed]: while failing, every [write] returns [Error] (the server
      answers 503) until a retry succeeds.
    - [Stream_buffer]: writes keep succeeding while failing, until [max_buffer_records]
      records are queued; then writes fail (fail closed at the bound).
    - [Stream_drop]: while failing or when the queue is full, new records are dropped
      before they are sealed (so the chain of shipped records stays intact) and counted
      under reason ["on_error_drop"]; [write] returns [Ok]. Records already queued are
      kept and retried.

    In every mode the queue never exceeds [max_buffer_records]. Records still queued when
    the process exits are lost (there is no spool); see docs/audit-sinks.md. *)

type entry = {
  line : string;  (** the sealed JSON record *)
  hash : string;  (** its hash *)
}

type item_result =
  | Delivered  (** stored (including "already stored" duplicates) *)
  | Retry of string  (** transient: sent again alone *)
  | Rejected of { reason : string; detail : string }
      (** permanent for this record: dropped and counted under [reason]. [detail] must not
          contain record contents. *)

type deliver = entry array -> (item_result array, string) result Lwt.t
(** Ships one batch, in order. The result array must have one element per entry. [Error]
    means the whole request failed. The message must not contain secrets or record
    contents. *)

type t

val create :
  ?now:(unit -> float) ->
  ?max_attempts:int ->
  ?base_backoff:float ->
  ?max_backoff:float ->
  ?jitter:(unit -> float) ->
  ?prepare:((string * Yojson.Safe.t) list -> (string * Yojson.Safe.t) list) ->
  ?close_transport:(unit -> unit Lwt.t) ->
  ?on_event:(string -> unit) ->
  ?initial_prev:string ->
  name:string ->
  kind:string ->
  batch:Haltsql_load.Config.stream_batch ->
  on_error:Haltsql_load.Config.stream_on_error ->
  max_buffer_records:int ->
  deliver ->
  (t, string) result
(** Defaults: [max_attempts] 3, [base_backoff] 0.2 s, [max_backoff] 30 s, [jitter] a
    uniform random factor from 0.5 (inclusive) to 1.5 (exclusive), [prepare] the identity
    (applied to the fields before sealing, e.g. to add [@timestamp]), [initial_prev]
    genesis. [kind] labels the metrics ([elasticsearch], [kafka]). Not started: call
    {!start}. *)

val name : t -> string
val kind : t -> string

val start : t -> unit
(** Starts the background loop that ships batches and retries failed ones. *)

val write : t -> (string * Yojson.Safe.t) list -> (unit, string) result
(** Synchronous, non-blocking. The chain only advances when the record is queued. *)

val flush : t -> (unit, string) result Lwt.t
(** Ships every queued record now (each batch gets [max_attempts] attempts). [Error] if
    records remain queued. *)

val close : t -> (unit, string) result Lwt.t
(** Stops the loop, flushes, and closes the transport. Later writes are refused. *)

val healthy : t -> bool
(** [false] while writes are being refused (fail closed after a failure, or the buffer is
    full). A [Stream_drop] sink is always healthy (it never refuses); watch [delivering]
    and the drop counter instead. *)

type stats = {
  records_written : int;  (** accepted and sealed *)
  records_delivered : int;
  records_dropped : (string * int) list;  (** per reason, sorted *)
  delivery_failures : int;  (** batches that failed every attempt *)
  retries : int;  (** extra attempts *)
  write_rejections : int;
  buffered_records : int;  (** queued, not yet delivered *)
  delivering : bool;  (** [false] while failing *)
  last_error : string option;
  chain_head : string;  (** hash of the last sealed record *)
}

val stats : t -> stats

val metrics_text : t list -> string
(** Prometheus exposition lines ([haltsql_audit_stream_sink_*{sink,type}]) for these
    sinks. The metric names differ from {!Haltsql_cloud.Object_sink.metrics_text}'s, so
    both can be concatenated on one [/metrics] page. *)
