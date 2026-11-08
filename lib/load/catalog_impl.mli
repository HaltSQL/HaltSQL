(** Catalog snapshot documents: decoding and printing.

    A catalog snapshot lists the {b complete} column sets of real tables, typically
    produced by [haltsql schema pull]. The analyzer relies on it to expand [*] and to
    prove that an unqualified table name cannot resolve to an unlisted relation earlier in
    the search path, so it must describe the database exactly:
    - names are stored {b exactly as written} (no case folding): a snapshot records names
      as PostgreSQL stores them;
    - table keys are ["schema.table"]; a part that is not a plain identifier is
      double-quoted, e.g. [app."odd.name"];
    - a column is a name or a [{name, type}] mapping; types are lower-cased;
    - empty column lists, duplicate columns and duplicate tables are errors;
    - tables are returned sorted by [(schema, name)].

    The public API is [Catalog_load]; [Policy_impl] uses {!decode} for inline [catalog:]
    sections and [haltsql.bundle] uses {!to_json}. *)

open Haltsql_core

val to_json : Catalog.t -> Yojson.Safe.t
(** The snapshot document form ([{"tables": {...}}]); {!of_json} reads it back to an equal
    value. Columns without a type are written as plain names. *)

val decode : Dec.ctx -> Lpath.t -> Yojson.Safe.t -> Catalog.t option
(** Decodes a snapshot document (or an inline [catalog:] mapping) at the given path,
    recording errors in the context. The [apiVersion]/[kind] header is optional. *)

val of_json :
  ?file:string ->
  ?positions:Docpos.positions ->
  ?path:Lpath.t ->
  Yojson.Safe.t ->
  (Catalog.t, Load_error.t list) result
(** Decodes a whole snapshot document; [Ok] only if no error was recorded. *)

val of_file : string -> (Catalog.t, Load_error.t list) result
(** Reads (YAML or JSON, by extension) and decodes a snapshot file. *)
