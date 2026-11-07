(** Schema snapshot (catalog) documents. See {!Haltsql_core.Catalog.to_json}. *)

open Haltsql_core

val of_json : ?file:string -> Yojson.Safe.t -> (Catalog.t, Load_error.t list) result
val of_file : string -> (Catalog.t, Load_error.t list) result
