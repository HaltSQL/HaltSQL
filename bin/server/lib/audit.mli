(** Tamper-evident audit log.

    One JSON line per verify request, per sink:
    {v
    {ts, request_id, caller, caller_type, subject, policy, policy_version, allowed, shadow,
     codes, sql_sha256, fingerprint, elapsed_us, [sql], prev_hash, hash}
    v}
    where [hash = sha256_hex (prev_hash ^ L)] and [L] is the compact JSON serialization of
    the same object without the ["hash"] field (keys in exactly the order written). The
    first line of a new chain has [prev_hash] = 64 zeros ({!genesis}). Appending to an
    existing file continues its chain from the last line's hash. Each sink keeps its own
    chain. The raw SQL is included only with [server.audit.log_raw_sql].

    Writes are synchronous: within the single Lwt thread a record is sealed and written
    before the next one, so the chain cannot interleave. *)

val genesis : string
(** The [prev_hash] of the first record of a chain: 64 zeros. *)

val sha256_hex : string -> string
(** Lower-case hex SHA-256. *)

(** Where a sink writes. *)
type backend =
  | Fd of Unix.file_descr
  | Custom of { write : string -> unit; close : unit -> unit }
      (** e.g. a sink registered by an integrator; [write] gets one line (with its
          trailing newline) and raises on failure *)
  | Object of Haltsql_cloud.Object_sink.t
      (** S3 / GCS: the object sink seals records into its own hash chain (continued
          across objects), batches, uploads, and applies [on_error] itself *)
  | Stream of Haltsql_siem.Stream_sink.t
      (** Elasticsearch / OpenSearch / Kafka: like [Object], the stream sink seals records
          into its own chain, batches, ships in the background and applies [on_error]
          itself *)

type sink = {
  name : string;  (** ["stdout"], the file path, or the custom sink's name *)
  backend : backend;
  mutable prev : string;  (** hash of the last record written *)
  on_error : Haltsql.Config.on_error;
  pending : (string * Yojson.Safe.t) list Queue.t;
      (** records not yet written ([buffer] mode); sealed when written *)
}

val max_pending : int
(** Upper bound on buffered records per sink; beyond it requests fail closed. *)

(** {1 Opening and closing} *)

val of_fd : ?on_error:Haltsql.Config.on_error -> name:string -> Unix.file_descr -> sink
(** A sink writing to an open descriptor (new chain). *)

val custom :
  ?on_error:Haltsql.Config.on_error ->
  name:string ->
  write:(string -> unit) ->
  close:(unit -> unit) ->
  unit ->
  sink
(** A sink backed by arbitrary functions (new chain). *)

val of_object_sink : Haltsql_cloud.Object_sink.t -> sink
(** Wraps an S3 / GCS object sink. Call {!start} once the sink is registered. *)

val of_stream_sink : Haltsql_siem.Stream_sink.t -> sink
(** Wraps a SIEM streaming sink. Call {!start} once the sink is registered. *)

val open_stdout : ?on_error:Haltsql.Config.on_error -> unit -> sink
(** Standard output (new chain). *)

val open_file : ?on_error:Haltsql.Config.on_error -> string -> sink
(** Appends to a file (created with mode 0640), continuing its chain. Raises [Failure] if
    the last line is not a valid audit record, and [Unix.Unix_error] if the file cannot be
    opened. *)

val start : sink -> unit
(** Starts background work (object sinks' batching); a no-op otherwise. *)

val shutdown : sink -> (unit, string) result Lwt.t
(** Final flush of batching sinks, at shutdown. *)

val close : sink -> unit
(** Releases the descriptor (never stdout). Object sinks are closed by {!shutdown}. *)

(** {1 Writing} *)

val record_fields :
  ts:string ->
  request_id:string ->
  caller:string ->
  caller_type:string ->
  subject:string option ->
  verdict:Haltsql.Verdict.t ->
  sql:string ->
  log_raw_sql:bool ->
  (string * Yojson.Safe.t) list
(** The unsealed fields of one record. [sql] is included only if [log_raw_sql]. *)

val append : sink -> (string * Yojson.Safe.t) list -> unit
(** Seals and writes one record. The chain advances only if the write succeeded. Raises on
    failure. *)

type delivery =
  | Written
  | Buffered  (** the write failed; the record is queued ([buffer] mode) *)
  | Failed of string  (** the request must fail closed *)

val deliver : sink -> (string * Yojson.Safe.t) list -> delivery
(** Writes buffered records first (in order), then this one, applying the sink's
    [on_error] policy. *)

val healthy : sink -> bool
(** False when the sink cannot currently accept records (used by [/readyz]). *)

val object_sinks : sink list -> Haltsql_cloud.Object_sink.t list
(** The S3 / GCS sinks among these (for their metrics). *)

val stream_sinks : sink list -> Haltsql_siem.Stream_sink.t list
(** The SIEM streaming sinks among these (for their metrics). *)

val kind : sink -> string
(** ["stdout"], ["file"], ["custom"], ["object"] (S3 / GCS) or the stream sink's kind. *)

(** {1 Verification} *)

type chain_error = { line_no : int; problem : string }

val verify_lines : ?initial_prev:string option -> string list -> (int, chain_error) result
(** Verifies a sequence of audit lines and returns the number of records. [initial_prev]
    is the expected [prev_hash] of the first record (default [Some genesis]; [None]
    accepts whatever the first record claims, e.g. for a rotated file). Blank lines are
    skipped. *)

val verify_file : ?initial_prev:string option -> string -> (int, chain_error) result
(** {!verify_lines} on a file's lines. *)
