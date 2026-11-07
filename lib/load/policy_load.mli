(** Policy document -> compiled {!Haltsql_core.Policy.t}. *)

open Haltsql_core

val of_json :
  ?file:string ->
  ?base_dir:string ->
  Yojson.Safe.t ->
  (Policy.t, Load_error.t list) result
(** Validates and compiles. [base_dir] resolves a relative [catalog:] path. Unknown keys
    are errors. Collects all errors rather than stopping at the first. *)

val of_file : string -> (Policy.t, Load_error.t list) result

val of_string :
  ?file:string ->
  ?base_dir:string ->
  Docload.format ->
  string ->
  (Policy.t, Load_error.t list) result

val to_json : Policy.t -> Yojson.Safe.t
(** Normalized form (stable key order, presets expanded). Its SHA-256 is [Policy.version].
*)

val function_presets : (string * string list) list
(** Built-in function allowlist presets, e.g.
    ["aggregates"; "math"; "string"; "datetime"]. *)

val default_operators : string list
val default_deny_casts : string list
