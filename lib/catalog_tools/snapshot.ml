(* Catalog snapshot documents (see snapshot.mli). *)

open Haltsql_core
module Ident = Haltsql_load.Ident

type relkind =
  | Table
  | Partitioned_table
  | Partition
  | View
  | Materialized_view
  | Foreign_table
  | Sequence

let relkind_to_string = function
  | Table -> "table"
  | Partitioned_table -> "partitioned table"
  | Partition -> "partition"
  | View -> "view"
  | Materialized_view -> "materialized view"
  | Foreign_table -> "foreign table"
  | Sequence -> "sequence"

let all_relkinds =
  [
    Table; Partitioned_table; Partition; View; Materialized_view; Foreign_table; Sequence;
  ]

let relkind_of_string s = List.find_opt (fun k -> relkind_to_string k = s) all_relkinds

type t = {
  catalog : Catalog.t;
  relkinds : ((string * string) * relkind) list;
  database : string option;
  server_version : string option;
  schemas : string list;
}

let render_ident = Ident.render
let table_key ~schema ~name = render_ident schema ^ "." ^ render_ident name

let parse_table_key k =
  match Ident.parse_parts ~lower_unquoted:false k with
  | Ok [ s; n ] -> Ok (s, n)
  | Ok _ -> Error (Printf.sprintf "table %S must be written as \"schema.table\"" k)
  | Error e -> Error e

let relkind t ~schema ~name = List.assoc_opt (schema, name) t.relkinds

let to_json t : Yojson.Safe.t =
  let opt k = function Some v -> [ (k, `String v) ] | None -> [] in
  let relations =
    List.map
      (fun (tb : Catalog.table) ->
        match relkind t ~schema:tb.schema ~name:tb.name with
        | Some k ->
            [ (table_key ~schema:tb.schema ~name:tb.name, `String (relkind_to_string k)) ]
        | None -> [])
      t.catalog.tables
    |> List.concat
  in
  let metadata =
    [ ("source", `String "haltsql schema pull") ]
    @ opt "database" t.database
    @ opt "server_version" t.server_version
    @ [ ("schemas", `List (List.map (fun s -> `String s) t.schemas)) ]
    @ if relations = [] then [] else [ ("relations", `Assoc relations) ]
  in
  `Assoc
    [
      ("apiVersion", `String "haltsql.dev/v1");
      ("kind", `String "Catalog");
      ("metadata", `Assoc metadata);
      ( "tables",
        `Assoc
          (List.map
             (fun (tb : Catalog.table) ->
               ( table_key ~schema:tb.schema ~name:tb.name,
                 `Assoc
                   [
                     ( "columns",
                       `List
                         (List.map
                            (fun (c : Catalog.column) ->
                              `Assoc
                                (("name", `String c.col_name)
                                ::
                                (match c.col_type with
                                | Some ty -> [ ("type", `String ty) ]
                                | None -> [])))
                            tb.columns) );
                   ] ))
             t.catalog.tables) );
    ]

let ( let* ) = Result.bind
let errors_to_string errs = String.concat "\n" (List.map Load_error.to_string errs)

let of_json ?file (j : Yojson.Safe.t) =
  let* catalog =
    match Haltsql_load.Catalog_load.of_json ?file j with
    | Ok c -> Ok c
    | Error errs -> Error (errors_to_string errs)
  in
  let meta =
    match j with
    | `Assoc kvs -> (
        match List.assoc_opt "metadata" kvs with Some (`Assoc m) -> m | _ -> [])
    | _ -> []
  in
  let str k = match List.assoc_opt k meta with Some (`String s) -> Some s | _ -> None in
  let schemas =
    match List.assoc_opt "schemas" meta with
    | Some (`List l) -> List.filter_map (function `String s -> Some s | _ -> None) l
    | _ -> []
  in
  let* relkinds =
    match List.assoc_opt "relations" meta with
    | None -> Ok []
    | Some (`Assoc rels) ->
        List.fold_left
          (fun acc (k, v) ->
            let* acc = acc in
            let* key = parse_table_key k in
            match v with
            | `String s -> (
                match relkind_of_string s with
                | Some kind -> Ok ((key, kind) :: acc)
                | None ->
                    Error
                      (Printf.sprintf "metadata.relations.%s: unknown relation kind %S" k
                         s))
            | _ -> Error (Printf.sprintf "metadata.relations.%s: expected a string" k))
          (Ok []) rels
        |> Result.map List.rev
    | Some _ -> Error "metadata.relations: expected a mapping"
  in
  Ok
    {
      catalog;
      relkinds;
      database = str "database";
      server_version = str "server_version";
      schemas;
    }

let of_file file =
  match Haltsql_load.Docload.of_file file with
  | Error errs -> Error (errors_to_string errs)
  | Ok j -> of_json ~file j
