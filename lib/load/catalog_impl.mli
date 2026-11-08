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

val non_authoritative_message : string
(** The error recorded for a document with [metadata.authoritative: false]. *)

val decode :
  ?allow_non_authoritative:bool -> Dec.ctx -> Lpath.t -> Yojson.Safe.t -> Catalog.t option
(** Decodes a snapshot document (or an inline [catalog:] mapping) at the given path,
    recording errors in the context. The [apiVersion]/[kind] header is optional.

    A document whose [metadata.authoritative] is [false] (a snapshot of a data catalog's
    view, written by [haltsql schema fetch]) is an error unless [allow_non_authoritative]
    (default [false]): the analyzer trusts a catalog as the complete truth about the
    database, which a data catalog is not. [metadata.authoritative] must be a boolean when
    present. *)

val of_json :
  ?allow_non_authoritative:bool ->
  ?file:string ->
  ?positions:Docpos.positions ->
  ?path:Lpath.t ->
  Yojson.Safe.t ->
  (Catalog.t, Load_error.t list) result
(** Decodes a whole snapshot document; [Ok] only if no error was recorded. *)

val of_file :
  ?allow_non_authoritative:bool -> string -> (Catalog.t, Load_error.t list) result
(** Reads (YAML or JSON, by extension) and decodes a snapshot file. *)
