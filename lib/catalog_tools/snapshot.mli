(** Catalog snapshot documents as written by [haltsql schema pull].

    A snapshot is a {!Haltsql_core.Catalog.t} (loadable with {!Haltsql_load.Catalog_load})
    plus metadata. The metadata records the kind of every relation under
    [metadata.relations], so that tools such as the policy drafter can tell views,
    partitions and sequences from tables:

    {v
    {"apiVersion": "haltsql.dev/v1", "kind": "Catalog",
     "metadata": {"source": "haltsql schema pull", "database": "app",
                  "server_version": "17.2", "schemas": ["app"],
                  "relations": {"app.orders": "partitioned table", ...}},
     "tables": {"app.orders": {"columns": [{"name": "id", "type": "bigint"}, ...]}}}
    v}

    Table keys are ["schema.table"], each part rendered so that it parses back to the
    exact stored name (parts that are not plain lower-case identifiers are double-quoted).
*)

open Haltsql_core

type relkind =
  | Table
  | Partitioned_table
  | Partition  (** a leaf or intermediate partition of a partitioned table *)
  | View
  | Materialized_view
  | Foreign_table
  | Sequence

val relkind_to_string : relkind -> string
(** ["table"], ["partitioned table"], ["partition"], ["view"], ["materialized view"],
    ["foreign table"], ["sequence"]. *)

val relkind_of_string : string -> relkind option
(** Parses a relation kind as written in snapshots. *)

type t = {
  catalog : Catalog.t;  (** tables sorted by (schema, name), byte order *)
  relkinds : ((string * string) * relkind) list;  (** [((schema, name), kind)] *)
  database : string option;
  server_version : string option;
  schemas : string list;  (** schemas that were requested ([[]] = all user schemas) *)
  authoritative : bool;
      (** [true] for a snapshot of the database itself ([haltsql schema pull]): complete,
          typed column lists the analyzer can trust. [false] for a data catalog's view of
          the tables ([haltsql schema fetch --snapshot-out]), which can lag behind the
          database: written with [metadata.authoritative: false] (and
          [metadata.source: "haltsql schema fetch"]), refused as a policy [catalog:], and
          used by the policy drafter only to choose column lists. *)
}

val render_ident : string -> string
(** Renders one stored name so that HaltSQL's identifier parser gives it back exactly
    (bare if it is a plain lower-case identifier, otherwise double-quoted). *)

val table_key : schema:string -> name:string -> string
(** [render_ident schema ^ "." ^ render_ident name]. *)

val parse_table_key : string -> (string * string, string) result
(** Inverse of {!table_key}; quoted parts keep their case, unquoted parts are taken
    verbatim (snapshot convention). *)

val relkind : t -> schema:string -> name:string -> relkind option
(** The kind of a relation in the snapshot, if present. *)

val to_json : t -> Yojson.Safe.t
(** The snapshot document (accepted back by {!of_json}). [metadata.authoritative: false]
    is written only for non-authoritative snapshots, so pulled snapshots are unchanged. *)

val of_json :
  ?allow_non_authoritative:bool -> ?file:string -> Yojson.Safe.t -> (t, string) result
(** Loads the tables with {!Haltsql_load.Catalog_load.of_json} (so every rule of the
    catalog loader applies) and reads the optional metadata. Unknown relation kinds are an
    error. A non-authoritative snapshot is refused unless [allow_non_authoritative]
    (default [false]); pass [true] only where the structure is a hint (the policy
    drafter). *)

val of_file : ?allow_non_authoritative:bool -> string -> (t, string) result
(** {!of_json} on a file's contents. *)
