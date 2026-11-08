(** The haltsql audit hash chain (identical to the server's file sink):

    [hash = sha256_hex (prev_hash ^ L)] where [L] is the compact JSON of the record
    without its trailing ["hash"] field, and [prev_hash] is the previous record's hash (64
    zeros for the first record of a chain). Object sinks continue one chain across all the
    objects they write, so the concatenation of a sink's objects in sequence order
    verifies as a single chain. *)

val genesis : string
(** 64 zeros: the [prev_hash] of the first record of a chain. *)

val seal : prev:string -> (string * Yojson.Safe.t) list -> string * string
(** [(line, hash)]: appends [prev_hash] and [hash] to the fields. *)

val hash_of_line : string -> string option
(** The [hash] field of a sealed record line, if it has a 64-hex one (no verification). *)

val verify_lines :
  ?initial_prev:string option -> string list -> (int, int * string) result
(** Number of verified records, or [(line_no, problem)]. [initial_prev] defaults to
    [Some genesis]; [None] accepts whatever the first record claims. Blank lines are
    skipped. *)
