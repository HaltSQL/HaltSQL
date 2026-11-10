(* Policy vs database comparison; see policy_drift.mli. *)

open Haltsql_core

type severity = Error | Warning

type finding = {
  severity : severity;
  code : string;
  table : string option;
  message : string;
}

let severity_to_string = function Error -> "error" | Warning -> "warning"
let sprintf = Printf.sprintf
let covers (snap : Snapshot.t) schema = snap.schemas = [] || List.mem schema snap.schemas

let policy_columns (tb : Policy.table) =
  let listed = function Policy.All -> [] | Policy.Only l -> l in
  let writable = match tb.writes.update with None -> [] | Some c -> listed c in
  List.sort_uniq String.compare
    (listed tb.columns @ List.map fst tb.tenant_columns @ writable)

let diff a b = List.filter (fun x -> not (List.mem x b)) a

let check_table (p : Policy.t) (snap : Snapshot.t) (tb : Policy.table) =
  let name = Policy.table_qualified_name tb in
  let f severity code fmt =
    Printf.ksprintf (fun message -> { severity; code; table = Some name; message }) fmt
  in
  if not (covers snap tb.schema) then
    [
      f Warning "W_DRIFT_SCHEMA_NOT_PULLED"
        "schema %s is not in the snapshot; %s was not checked" tb.schema name;
    ]
  else
    match Catalog.find snap.catalog ~schema:tb.schema ~name:tb.name with
    | None -> [ f Error "E_DRIFT_TABLE_MISSING" "%s does not exist in the database" name ]
    | Some live ->
        let live_cols = Catalog.column_names live in
        let missing =
          List.map
            (fun c ->
              f Error "E_DRIFT_COLUMN_MISSING" "column %s.%s does not exist" name c)
            (diff (policy_columns tb) live_cols)
        in
        let stale =
          match Catalog.find p.catalog ~schema:tb.schema ~name:tb.name with
          | None ->
              [
                f Warning "W_DRIFT_NO_CATALOG"
                  "the policy has no catalog entry for %s; add catalog: from haltsql \
                   schema pull"
                  name;
              ]
          | Some known -> (
              let known_cols = Catalog.column_names known in
              match (diff live_cols known_cols, diff known_cols live_cols) with
              | [], [] -> []
              | added, removed ->
                  let part what = function
                    | [] -> []
                    | l -> [ sprintf "%s: %s" what (String.concat ", " l) ]
                  in
                  [
                    f Error "E_DRIFT_CATALOG_STALE"
                      "the policy's catalog entry for %s is out of date (%s); SELECT * \
                       would be checked against the old column list"
                      name
                      (String.concat "; "
                         (part "new in the database" added
                         @ part "gone from the database" removed));
                  ])
        in
        let opaque =
          match List.assoc_opt (tb.schema, tb.name) snap.relkinds with
          | Some ((Snapshot.View | Materialized_view | Foreign_table) as k) ->
              [
                f Warning "W_DRIFT_VIEW"
                  "%s is a %s: what it reads is decided by its definition, which HaltSQL \
                   does not see; tenant and column rules apply to its output only"
                  name
                  (Snapshot.relkind_to_string k);
              ]
          | Some (Table | Partitioned_table | Partition | Sequence) | None -> []
        in
        let shadowed =
          let rec earlier = function
            | [] -> []
            | s :: _ when String.equal s tb.schema -> []
            | s :: rest ->
                (if
                   covers snap s
                   && Option.is_some (Catalog.find snap.catalog ~schema:s ~name:tb.name)
                   && Option.is_none (Policy.find_table p ~schema:s ~name:tb.name)
                 then
                   [
                     f Error "E_DRIFT_SHADOWED"
                       "%s.%s exists and comes before %s in search_path: an unqualified \
                        %s reaches it instead of the policy table"
                       s tb.name tb.schema tb.name;
                   ]
                 else [])
                @ earlier rest
          in
          if List.mem tb.schema p.search_path then earlier p.search_path else []
        in
        missing @ stale @ shadowed @ opaque

let check (p : Policy.t) (snap : Snapshot.t) =
  let all = List.concat_map (check_table p snap) p.tables in
  let rank f = match f.severity with Error -> 0 | Warning -> 1 in
  List.stable_sort
    (fun a b -> compare (rank a, a.table, a.code) (rank b, b.table, b.code))
    all

let to_json fs : Yojson.Safe.t =
  `List
    (List.map
       (fun f ->
         `Assoc
           [
             ("severity", `String (severity_to_string f.severity));
             ("code", `String f.code);
             ("table", match f.table with Some t -> `String t | None -> `Null);
             ("message", `String f.message);
           ])
       fs)
