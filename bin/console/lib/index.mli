(** In-memory index of audit records for the retention window.

    Ingestion ({!Ingest}) adds entries; every feature reads through this interface. An
    entry is a {!Haltsql_report.Record.t} (the same normalisation the [haltsql report]
    command uses) plus what the console needs for search and chain of custody.

    Thread-safety: Lwt is cooperative and no function here yields, so reads and writes
    never interleave.

    Cost model ([n] entries, [k] verifiers, [m] entries returned or of one verifier, [b]
    entries in the minute buckets a time range overlaps). Entries are bucketed by minute
    of [ts] in an ordered map and listed per verifier; every structure holds references to
    one shared node per entry, never copies. Removal is O(1) amortised (lazy, with
    per-structure compaction).
    - [add]: O(log B) for [B] minute buckets (at most ~10k for 7 days), amortised.
    - [oldest], [newest], [size]: O(1); after the extreme entry is evicted, the next call
      rescans the first/last bucket once.
    - [verifiers], [verifier_counts]: O(k log k).
    - [between]: O(b + m log m) over the overlapping buckets only.
    - [verifier_stream]: O(m) (O(m log m) once if that verifier's entries arrived out of
      [seq] order).
    - [search ~limit]: newest buckets first, stopping once [limit] matches are collected
      from whole buckets; [since]/[until] in the filter prune buckets.
    - [expire]: O(log B + entries removed + the boundary bucket). *)

type entry = {
  record : Haltsql_report.Record.t;
  request_id : string;  (** the record's [request_id]; a synthetic id when absent *)
  ts : float;  (** Unix seconds; ingestion time when the record has none *)
  verifier : string;  (** configured verifier name, or the source's name *)
  hash : string option;  (** audit-chain [hash] *)
  prev_hash : string option;  (** audit-chain [prev_hash] *)
  elapsed_us : int option;
  location : string;
      (** where it was read, e.g. [s3://b/k.jsonl#L12] or [/var/log/a.jsonl#L3] *)
  seq : int;  (** position in its verifier's stream as ingested (0-based) *)
  raw : Yojson.Safe.t;  (** the original JSON line *)
}

type t

val create : ?max_records:int -> ?retention_seconds:float -> unit -> t

val add : t -> entry -> unit
(** Adds an entry; a duplicate [request_id] from the same verifier replaces nothing and is
    ignored. Evicts the oldest entries beyond [max_records]. *)

val entry_of_json :
  verifier:string ->
  location:string ->
  seq:int ->
  now:float ->
  Yojson.Safe.t ->
  entry option
(** Builds an entry from one audit JSON object (server or proxy format); [None] when it is
    not an audit record. *)

val expire : t -> now:float -> unit
(** Drops every entry with [ts < now - retention], wherever it sits in insertion order. *)

val size : t -> int
val oldest : t -> float option
val newest : t -> float option

val find : t -> string -> entry option
(** By exact request id. *)

val iter : t -> (entry -> unit) -> unit
(** Oldest first. *)

val fold : t -> init:'a -> f:('a -> entry -> 'a) -> 'a

val between : t -> since:float -> until:float -> entry list
(** Entries with [since <= ts < until], oldest first. *)

val verifier_stream : t -> string -> entry list
(** Every entry of one verifier, in [seq] order (for chain checks and neighbours). *)

val verifiers : t -> string list
(** Verifiers with at least one entry, sorted. *)

val verifier_counts : t -> (string * int) list
(** Entries per verifier, sorted by verifier name. Maintained incrementally. *)

type filter = {
  q : string option;
      (** request-id prefix, caller substring, fingerprint prefix or table name *)
  caller : string option;
  policy : string option;
  outcome : Haltsql_report.Record.outcome option;
  code : string option;
  table : string option;
  fingerprint : string option;
  verifier : string option;
  since : float option;
  until : float option;
}

val no_filter : filter

val search : ?limit:int -> t -> filter -> entry list
(** Matching entries, newest first (equal timestamps: most recently added first). With
    [limit], exactly the first [limit] elements of the unlimited result, computed by
    walking minute buckets newest to oldest and stopping early. The filter's [since] and
    [until] restrict the buckets visited. *)

val count : t -> filter -> int
(** [List.length (search t f)] without building the list; O(1) for {!no_filter}. *)

(** {2 Warm start}

    The index is a cache: the source of truth stays the verifiers' audit records, which
    ingestion re-reads. A snapshot only lets the console serve the last known window
    immediately after a restart instead of starting empty until re-ingestion finishes.
    {!Ingest} owns when to call these (e.g. [restore] before its first poll, followed by
    {!expire}; [snapshot] periodically and on shutdown) and where the file lives (under
    [state_dir]). Re-ingesting records that were restored is harmless: {!add} ignores an
    entry with the same request id, verifier and location. *)

val snapshot : t -> string -> int
(** [snapshot t path] writes every entry, oldest first, as JSONL
    [{"verifier","location","seq","ts","raw"}] to [path] (via a temporary file and rename,
    so a crash leaves the previous snapshot intact) and returns the number written.
    Synchronous: it blocks the Lwt loop while writing (roughly a second per few hundred
    thousand entries), so it is also a consistent point-in-time copy. Raises [Sys_error]
    on I/O failure. *)

val restore : t -> string -> int
(** [restore t path] adds the entries of a {!snapshot} file (rebuilt with
    {!entry_of_json}, with the saved [ts] as [now] so records without a timestamp keep
    theirs) and returns how many were added. A missing file gives [0]; malformed lines and
    duplicates are skipped. [max_records] applies as usual; call {!expire} afterwards. *)

val outcome_of_string : string -> Haltsql_report.Record.outcome option

val entry_to_json : entry -> Yojson.Safe.t
(** The public record shape of [GET /api/v1/queries]: never includes SQL. *)

val raw_sql : entry -> string option
