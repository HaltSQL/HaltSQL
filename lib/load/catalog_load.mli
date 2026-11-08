(** Schema snapshot (catalog) documents. See {!Haltsql_core.Catalog.to_json} for the
    format.

    Names are stored exactly as written (no case folding), because a snapshot records
    names as PostgreSQL stores them. Loading fails closed: any error rejects the whole
    document. *)

open Haltsql_core

val of_json : ?file:string -> Yojson.Safe.t -> (Catalog.t, Load_error.t list) result
(** Decodes a snapshot document; [file] is used only in error locations. *)

val of_file : string -> (Catalog.t, Load_error.t list) result
(** Reads (YAML or JSON, by extension) and decodes a snapshot file. *)
