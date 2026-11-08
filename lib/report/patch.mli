(** Applies accepted suggestions to a policy {e document} (the YAML/JSON tree from
    [Docload]), so that everything else in the document stays as written: presets, the
    catalog reference, tenancy, writes, mode. Only these edits are made:

    - [Add_column]: append to [tables.<t>.columns] (a list);
    - [Add_function]: append to [functions.allow];
    - [Set_limit_max]: set [require_limit.max];
    - [Add_table]: add a [tables] entry with [columns] and [tenant_column]/
      [tenant_columns].

    YAML comments are not preserved: the document is re-serialized (the output starts with
    a comment saying so). The result must be validated with {!validate} before it is
    written. *)

open Haltsql_core

type outcome = { applied : string list; skipped : (string * string) list }
(** suggestion ids applied, and (id, why) for those that were not *)

val apply :
  Policy.t -> Yojson.Safe.t -> Suggest.suggestion list -> Yojson.Safe.t * outcome
(** [apply policy doc suggestions]. [policy] is [doc] compiled (for [search_path] and
    tenancy keys). Suggestions for another policy name, or not [applicable], are skipped.
*)

val validate :
  ?file:string -> base_dir:string -> Yojson.Safe.t -> (Policy.t, Load_error.t list) result

val rebase_catalog : from_dir:string -> to_dir:string -> Yojson.Safe.t -> Yojson.Safe.t
(** Rewrites a relative [catalog:] path so that it still points at the same file from a
    document written to [to_dir]. Both directories must be absolute. *)

val relative_path : from_dir:string -> string -> string
(** [relative_path ~from_dir target], both absolute. *)

val render : Haltsql_load.Docload.format -> applied:string list -> Yojson.Safe.t -> string
