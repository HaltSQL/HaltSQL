(** Policy document -> compiled {!Haltsql_core.Policy.t}.

    This is how every policy enters HaltSQL. Loading fails closed: a policy is returned
    only if the whole document is valid, and the invariants documented on
    {!Haltsql_core.Policy} then hold. Every problem is reported (not just the first), each
    located as [file:line:col: key.path: message]. *)

open Haltsql_core

val of_json :
  ?file:string ->
  ?base_dir:string ->
  Yojson.Safe.t ->
  (Policy.t, Load_error.t list) result
(** Validates and compiles. [base_dir] resolves a relative [catalog:] path. Unknown keys
    are errors. Collects all errors rather than stopping at the first. *)

val of_file : string -> (Policy.t, Load_error.t list) result
(** Reads and compiles a policy file (YAML or JSON, by extension). A relative [catalog:]
    path is resolved against the file's directory. *)

val of_string :
  ?file:string ->
  ?base_dir:string ->
  Docload.format ->
  string ->
  (Policy.t, Load_error.t list) result
(** Parses (with source positions for error messages) and compiles a policy document. *)

val to_json : Policy.t -> Yojson.Safe.t
(** Normalized form (stable key order, presets expanded). Its SHA-256 is [Policy.version].
*)

val function_presets : (string * string list) list
(** Built-in function allowlist presets, e.g.
    ["aggregates"; "math"; "string"; "datetime"]. *)

val default_operators : string list
(** Operators allowed when a policy has no [operators] section. *)

val default_casts : string list
(** Cast target types allowed when a policy has no [casts] section. *)

val default_deny_casts : string list
(** Cast target types denied when a policy has no [deny_casts] section (the
    object-identifier types such as [regclass], whose input functions read the system
    catalogs). *)
