(** In-memory index of audit records for the retention window.

    Ingestion ({!Ingest}) adds entries; every feature reads through this interface. An
    entry is a {!Haltsql_report.Record.t} (the same normalisation the [haltsql report]
    command uses) plus what the console needs for search and chain of custody.

    Thread-safety: Lwt is cooperative and no function here yields, so reads and writes
    never interleave. *)

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
(** Drops entries older than the retention window. *)

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

val search : t -> filter -> entry list
(** Matching entries, newest first. *)

val outcome_of_string : string -> Haltsql_report.Record.outcome option

val entry_to_json : entry -> Yojson.Safe.t
(** The public record shape of [GET /api/v1/queries]: never includes SQL. *)

val raw_sql : entry -> string option
