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

type t = {
  catalog : Catalog.t;  (** tables sorted by (schema, name), byte order *)
  relkinds : ((string * string) * relkind) list;  (** [((schema, name), kind)] *)
  database : string option;
  server_version : string option;
  schemas : string list;  (** schemas that were requested ([[]] = all user schemas) *)
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
val to_json : t -> Yojson.Safe.t

val of_json : ?file:string -> Yojson.Safe.t -> (t, string) result
(** Loads the tables with {!Haltsql_load.Catalog_load.of_json} (so every rule of the
    catalog loader applies) and reads the optional metadata. Unknown relation kinds are an
    error. *)

val of_file : string -> (t, string) result
