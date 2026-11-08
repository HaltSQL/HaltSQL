(** Aggregate statistics over a set of audit records. *)

type count = { total : int; allowed : int; denied : int; shadow_denied : int }

type query = {
  key : string;  (** {!Record.fingerprint_key} *)
  count : count;
  codes : (string * int) list;  (** reason code -> records, most frequent first *)
  callers : (string * int) list;
  policies : string list;
  example_sql : string option;
      (** SQL of one record of the group, only when a record contained it; clipped to
          {!max_example_bytes} *)
  example_sql_sha256 : string option;
  first_seen : float option;
  last_seen : float option;
}

type t = {
  records : int;
  first_ts : float option;
  last_ts : float option;
  untimed : int;  (** records without a parsable timestamp *)
  with_sql : int;  (** records that contain the raw SQL *)
  with_details : int;  (** records with detailed reasons (rule + message) *)
  totals : count;
  by_code : (string * count) list;  (** records carrying each code *)
  by_table : (string * count) list;
  by_column : (string * count) list;
  by_caller : (string * count) list;
  by_policy : (string * count) list;
  by_source : (string * count) list;
  bucket_seconds : int;
  buckets : (float * count) list;  (** bucket start (Unix seconds) -> counts, ascending *)
  top_denied : query list;  (** groups with denials or shadow denials, worst first *)
}

val max_example_bytes : int

val auto_bucket : float option -> float option -> int
(** Bucket width for a time span: 5 minutes up to 6 h, 1 h up to 3 days, else 1 day. *)

val compute : ?bucket_seconds:int -> ?top:int -> Record.t list -> t
(** [top] (default 20) bounds [top_denied]. Tables and columns come from the records' own
    lists and from the objects their detailed reasons name. *)

val count_to_json : count -> Yojson.Safe.t
val to_json : t -> Yojson.Safe.t
