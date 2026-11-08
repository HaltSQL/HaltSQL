(** Batching audit sink that writes the hash-chained JSONL records to an object store.

    {1 Records and objects}

    [write] seals each record into the sink's hash chain ({!Audit_chain}) and appends it
    to the current batch. A batch is closed when it holds [batch.max_records] records or
    is [batch.max_seconds] old, and becomes one object named

    [<prefix>YYYY/MM/DD/HH/<host>-<run>-<seq>-<sha256>.jsonl]

    (UTC hour of closing, the sanitized host name, the run id of the process that sealed
    it, a zero-padded per-sink sequence number, and the SHA-256 of the object body). The
    default run id is the process start time in UTC with microseconds followed by the pid
    (e.g. [20240601T120000.123456Z.4242]): two runs never share a sequence namespace, and
    sorting names within an hour directory orders runs by start time. The chain continues
    across objects: the first record of object [n+1] has the [prev_hash] of the last
    record of object [n]. Objects are uploaded strictly in order; an object that fails
    stays at the head of the queue.

    {1 Failure policy}

    - [Fail_closed]: after an upload fails (all attempts), the sink is unhealthy and every
      [write] returns [Error] (the server answers 503) until a background retry succeeds.
    - [Buffer]: failed objects stay queued and [write] keeps succeeding until
      [max_buffer_records] records are waiting; then writes fail (fail closed at the bound
      — records are never silently dropped). [buffered_records] and [upload_failures] are
      exported as alert metrics.

    {1 Spool and restarts}

    With [spool_dir], every record is also appended synchronously to
    [<spool_dir>/current.jsonl] before [write] returns, closed batches are kept as
    [batch-<seq>.jsonl] (with their object name in [batch-<seq>.key]) until uploaded, and
    the chain head and next sequence number are persisted in [head.json] each time a batch
    is sealed. A restarted sink re-queues spooled batches under their original object
    names (so a batch uploaded just before a crash is not stored twice) and continues the
    chain and the sequence from the last sealed record, even when every batch had already
    been uploaded. No acknowledged record is lost on crash, and deleting the objects of an
    earlier run breaks verification of the later one.

    Without [spool_dir], nothing survives the process: each run starts a new chain at
    [initial_prev] (default genesis) and sequence 0, under its own run id. *)

type upload_error =
  | Retryable of string  (** network errors, timeouts, 429, 5xx, expired credentials *)
  | Permanent of string  (** e.g. 403 AccessDenied: not retried within this flush *)

type uploader = key:string -> body:string -> (unit, upload_error) result Lwt.t
type t

val create :
  ?now:(unit -> float) ->
  ?host:string ->
  ?run_id:string ->
  ?spool_dir:string ->
  ?max_buffer_records:int ->
  ?max_attempts:int ->
  ?base_backoff:float ->
  ?initial_prev:string ->
  ?on_event:(string -> unit) ->
  name:string ->
  prefix:string ->
  batch:Haltsql_load.Config.batch ->
  on_error:Haltsql_load.Config.on_error ->
  uploader ->
  (t, string) result
(** Defaults: [host] the sanitized hostname, [run_id] as described above (1-64 characters
    from [A-Za-z0-9.]), [max_buffer_records] 100000 (at least [batch.max_records]),
    [max_attempts] 3 per flush, [base_backoff] 0.2 s, [initial_prev] genesis (ignored when
    the spool holds a chain head). Fails if the spool's [head.json] or last record is
    corrupt (fail closed: the chain is never silently restarted). [on_event] receives
    operational messages (failures, recoveries); never record contents. *)

val name : t -> string
(** The sink's configured name. *)

val start : t -> unit
(** Starts the background loop that closes aged batches and retries failed uploads. *)

val write : t -> (string * Yojson.Safe.t) list -> (unit, string) result
(** Synchronous and non-blocking (apart from the optional spool append). The chain only
    advances when [Ok]. *)

val flush : t -> (unit, string) result Lwt.t
(** Closes the current batch and uploads every queued object. *)

val close : t -> (unit, string) result Lwt.t
(** Stops the loop and flushes. *)

val healthy : t -> bool
(** [false] while writes are being refused (fail-closed after a failure, or the buffer is
    full). Suitable for [/readyz]. *)

type stats = {
  records_written : int;
  objects_uploaded : int;
  upload_failures : int;
  write_rejections : int;
  buffered_records : int;  (** records not yet uploaded (current batch + queue) *)
  pending_objects : int;
  last_error : string option;
  chain_head : string;  (** hash of the last sealed record *)
}

val stats : t -> stats
(** Counters and state for monitoring. *)

val metrics_text : t list -> string
(** Prometheus exposition lines ([haltsql_audit_sink_*{sink="..."}]) for these sinks. *)

val object_key :
  prefix:string -> host:string -> run:string -> seq:int -> time:float -> string -> string
(** The object name for a body. *)
