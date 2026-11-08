(** Schema snapshot (catalog) documents. See {!Haltsql_core.Catalog.to_json} for the
    format.

    Names are stored exactly as written (no case folding), because a snapshot records
    names as PostgreSQL stores them. Loading fails closed: any error rejects the whole
    document. *)

open Haltsql_core

val of_json :
  ?allow_non_authoritative:bool ->
  ?file:string ->
  Yojson.Safe.t ->
  (Catalog.t, Load_error.t list) result
(** Decodes a snapshot document; [file] is used only in error locations. A document with
    [metadata.authoritative: false] (written by [haltsql schema fetch]) is refused unless
    [allow_non_authoritative] (default [false]); never pass [true] for a catalog the
    analyzer will trust. *)

val of_file :
  ?allow_non_authoritative:bool -> string -> (Catalog.t, Load_error.t list) result
(** Reads (YAML or JSON, by extension) and decodes a snapshot file. *)
