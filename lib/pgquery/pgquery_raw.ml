(* Bindings to pgquery_stubs.c; see pgquery_raw.mli. *)

external parse_json : string -> (string, string * int) result = "haltsql_pgq_parse"
external fingerprint : string -> (string, string) result = "haltsql_pgq_fingerprint"
external pg_version_ : unit -> string = "haltsql_pgq_version"
external pg_version_num_ : unit -> int = "haltsql_pgq_version_num" [@@noalloc]

let pg_version = pg_version_ ()
let pg_version_num = pg_version_num_ ()
