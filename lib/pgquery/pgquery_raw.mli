(** Thin binding to the vendored libpg_query (the real PostgreSQL parser).

    Thread- and domain-safe. Every call runs on a fixed pool of long-lived worker threads
    with 256 MB stacks (libpg_query's tree writers recurse without a depth check, and
    OCaml domains run on small-stack threads); the OCaml runtime lock is released while
    waiting, so domains parse in parallel. Pool size: number of CPUs, or
    [HALTSQL_PARSER_THREADS]. Inputs containing a NUL byte are rejected (C strings would
    silently truncate them, which could hide a second statement from the parser). *)

val parse_json : string -> (string, string * int) result
(** [Ok json] in libpg_query's JSON format
    ([{"version":170007,"stmts":[{"stmt":{...},"stmt_location":0,"stmt_len":0}]}]), or
    [Error (message, cursorpos)] where [cursorpos] is 1-based (0 if unknown). *)

val fingerprint : string -> (string, string) result
(** Hex fingerprint: equal for queries that differ only in literal values. *)

val pg_version : string
(** e.g. ["17.7"] *)

val pg_version_num : int
(** e.g. [170007] *)
