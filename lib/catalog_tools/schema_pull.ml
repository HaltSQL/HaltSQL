(* Catalog snapshot from a live database (see schema_pull.mli). *)

open Haltsql_core
open Lwt.Syntax

type row = {
  nspname : string;
  relname : string;
  relkind : char;
  relispartition : bool;
  attname : string option;
  atttype : string option;
}

let catalog_query =
  {|SELECT n.nspname::text, c.relname::text, c.relkind::text, c.relispartition::text,
       a.attname::text, lower(pg_catalog.format_type(a.atttypid, a.atttypmod))
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_attribute a
       ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND NOT starts_with(n.nspname, 'pg_toast')
  AND NOT starts_with(n.nspname, 'pg_temp_')
  AND ($1::jsonb IS NULL
       OR n.nspname IN (SELECT jsonb_array_elements_text($1::jsonb)))
ORDER BY n.nspname COLLATE "C", c.relname COLLATE "C", a.attnum|}

let kind_of_row r : Snapshot.relkind option =
  match r.relkind with
  | 'r' -> Some (if r.relispartition then Partition else Table)
  | 'p' -> Some (if r.relispartition then Partition else Partitioned_table)
  | 'v' -> Some View
  | 'm' -> Some Materialized_view
  | 'f' -> Some Foreign_table
  | 'S' -> Some Sequence
  | _ -> None

let build ?database ?server_version ~schemas rows =
  (* Group consecutive rows by relation, preserving column order (attnum). *)
  let tbl : (string * string, Snapshot.relkind * Catalog.column list ref) Hashtbl.t =
    Hashtbl.create 64
  in
  let order = ref [] in
  List.iter
    (fun r ->
      match kind_of_row r with
      | None -> ()
      | Some kind -> (
          let key = (r.nspname, r.relname) in
          let cols =
            match Hashtbl.find_opt tbl key with
            | Some (_, cols) -> cols
            | None ->
                let cols = ref [] in
                Hashtbl.add tbl key (kind, cols);
                order := key :: !order;
                cols
          in
          match r.attname with
          | Some name ->
              cols := { Catalog.col_name = name; col_type = r.atttype } :: !cols
          | None -> ()))
    rows;
  let keys = List.sort compare !order in
  let warnings = ref [] in
  let warn fmt = Printf.ksprintf (fun s -> warnings := s :: !warnings) fmt in
  let tables, relkinds =
    List.filter_map
      (fun ((schema, name) as key) ->
        let kind, cols = Hashtbl.find tbl key in
        match List.rev !cols with
        | [] ->
            warn "skipped %s %s: it has no columns"
              (Snapshot.relkind_to_string kind)
              (Snapshot.table_key ~schema ~name);
            None
        | columns -> Some ({ Catalog.schema; name; columns }, (key, kind)))
      keys
    |> List.split
  in
  List.iter
    (fun s ->
      if not (List.exists (fun (tb : Catalog.table) -> String.equal tb.schema s) tables)
      then warn "schema %s has no relations (or does not exist)" (Snapshot.render_ident s))
    schemas;
  ( { Snapshot.catalog = { Catalog.tables }; relkinds; database; server_version; schemas },
    List.rev !warnings )

let row_of_db (r : Pg_wire.row) =
  let s i = if i < Array.length r then r.(i) else None in
  match (s 0, s 1, s 2, s 3) with
  | Some nspname, Some relname, Some kind, Some part when String.length kind = 1 ->
      {
        nspname;
        relname;
        relkind = kind.[0];
        relispartition = part = "true";
        attname = s 4;
        atttype = s 5;
      }
  | _ -> raise (Pg_wire.Error "unexpected row shape from the catalog query")

let pull ?timeout ?(schemas = []) (dsn : Pg_dsn.t) =
  let schemas = List.sort_uniq compare schemas in
  let param =
    match schemas with
    | [] -> None
    | l -> Some (Yojson.Safe.to_string (`List (List.map (fun s -> `String s) l)))
  in
  let work conn =
    let* _ =
      Pg_wire.simple_query conn
        "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL \
         statement_timeout = '120s'"
    in
    Lwt.finalize
      (fun () ->
        let* ro = Pg_wire.simple_query conn "SHOW transaction_read_only" in
        let* () =
          match ro with
          | [ [| Some "on" |] ] -> Lwt.return_unit
          | _ -> Lwt.fail (Pg_wire.Error "could not open a read-only transaction")
        in
        let* rows = Pg_wire.query conn catalog_query ~params:[ param ] in
        Lwt.return (List.map row_of_db rows))
      (fun () ->
        Lwt.catch
          (fun () ->
            let* _ = Pg_wire.simple_query conn "ROLLBACK" in
            Lwt.return_unit)
          (fun _ -> Lwt.return_unit))
  in
  let run () =
    Pg_wire.with_conn ?timeout dsn (fun conn ->
        let* rows = work conn in
        Lwt.return (rows, Pg_wire.server_parameter conn "server_version"))
  in
  match
    Lwt_main.run
      (Lwt.catch (fun () -> Lwt.map Result.ok (run ())) (fun e -> Lwt.return (Error e)))
  with
  | Ok (rows, server_version) ->
      Ok (build ~database:dsn.dbname ?server_version ~schemas rows)
  | Error (Pg_wire.Error m) -> Error m
  | Error e -> Error ("schema pull failed: " ^ Printexc.to_string e)
