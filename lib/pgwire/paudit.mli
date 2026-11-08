(** The proxy's tamper-evident audit log: the same hash chain, sinks and failure policies
    as haltsql-server's [audit.sinks] (see docs/audit-sinks.md and docs/proxy.md).

    Every record is one JSON line
    [{"ts":...,<fields>...,"prev_hash":"<64 hex>","hash":"<64 hex>"}] sealed with
    {!Haltsql_cloud.Audit_chain.seal}: [hash = sha256_hex (prev_hash ^ L)], [L] being the
    compact JSON without ["hash"]. Each sink keeps its own chain:

    - [stdout]: starts at genesis (64 zeros) in every process;
    - [file]: appends (created 0640) and continues the chain from the file's last record;
      a last line that is not a sealed record refuses to start (rotate the file).
      Non-regular files (FIFOs, devices) start at genesis;
    - [s3] / [gcs]: a {!Haltsql_cloud.Object_sink} (batches, ordered create-only uploads,
      optional spool), which continues its chain across objects.

    Failure policies ({!Proxy_config.audit_on_error}):
    - [Audit_fail_closed]: a write that fails makes {!record} return [Error]; the session
      refuses the statement. For stdout/file every statement retries the write, so the
      proxy recovers as soon as the sink does; an object sink refuses writes until a
      background upload retry succeeds.
    - [Audit_buffer]: records that cannot be written are queued (unsealed, so the chain
      stays intact when they are written later, in order) and retried before the next
      record and every second; [Error] once [max_buffer_records] are queued.
    - [Audit_drop]: the record is discarded, counted and logged at warn level.

    A write that fails after part of a line reached a file marks the sink torn: the next
    successful write starts on a fresh line, so the fragment shows up as one invalid
    record in [haltsql audit verify] instead of corrupting the following record. *)

type t

val open_ : ?on_event:(string -> unit) -> Proxy_config.audit_sink_spec list -> t
(** Opens (and for object sinks, starts) every sink. Must run inside [Lwt_main.run].
    Raises [Failure] with a message naming the sink if one cannot be opened. [on_event]
    gets operational messages (never record contents); default: a warn log. *)

val spec : t -> Proxy_config.audit_sink_spec list
(** What {!open_} was given (for detecting configuration changes on reload). *)

val record : t -> (string * Yojson.Safe.t) list -> (unit, string) result
(** Prepends ["ts"] and delivers the record to every sink. [Error msg] when at least one
    sink refused it under [Audit_fail_closed] (or its buffer is full): the caller must
    refuse the statement. Never raises. *)

val healthy : t -> bool
(** [false] while some fail-closed sink's last write failed, a buffer is full, or an
    object sink refuses writes. *)

val stats_json : t -> Yojson.Safe.t
(** Per-sink counters: records written, buffered, dropped, write failures, health and last
    error (operational text only). *)

val close : t -> unit Lwt.t
(** Final flush: writes buffered records if possible, flushes and closes object sinks,
    closes files. Errors are logged. *)
