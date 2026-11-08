(* Live catalog fetching: provider registry, import, non-authoritative snapshots (see
   catalog_fetch.mli). *)

open Haltsql_core
open Haltsql_catalog_tools
open Lwt.Infix

(* Each provider PR adds one line here. *)
let providers : (module Provider.S) list = [ (module Openmetadata_fetch) ]

let find n =
  List.find_opt (fun (module P : Provider.S) -> String.equal P.name n) providers

type result = {
  manifest : Pii.t;
  scanned_columns : int;
  tables : Provider.table list;
  warnings : string list;
  requests : int;
}

let import_fetched ?config client (f : Provider.fetched) =
  match Pii_import.import ?config f.source f.document with
  | Error e -> Error e
  | Ok r ->
      Ok
        {
          manifest = r.manifest;
          scanned_columns = r.scanned_columns;
          tables = f.tables;
          warnings = f.warnings @ r.warnings;
          requests = Fetch_client.request_count client;
        }

(* A provider bug must not crash the CLI nor leak a response: Yojson's [Type_error]
   carries the offending JSON value, so only its message is kept. *)
let exn_message = function
  | Yojson.Safe.Util.Type_error (m, _) | Yojson.Safe.Util.Undefined (m, _) -> m
  | Failure m | Invalid_argument m -> m
  | Not_found -> "Not_found"
  | e -> Printexc.exn_slot_name e

let fetch (module P : Provider.S) client filter =
  Lwt.catch
    (fun () -> P.fetch client filter)
    (fun e ->
      Lwt.return
        (Error (Printf.sprintf "%s: internal provider error: %s" P.name (exn_message e))))

let run ?config provider client filter =
  fetch provider client filter >|= function
  | Error e -> Error e
  | Ok f -> import_fetched ?config client f

let catalog_snapshot ~database (tables : Provider.table list) : Snapshot.t =
  (* The catalog loader rejects empty names, empty column lists, duplicate columns and
     duplicate tables: drop / merge them so the snapshot always loads. *)
  let by_key : (string * string, Catalog.column list ref) Hashtbl.t = Hashtbl.create 64 in
  let order = ref [] in
  List.iter
    (fun (tb : Provider.table) ->
      if tb.schema <> "" && tb.name <> "" then begin
        let key = (tb.schema, tb.name) in
        let cols =
          match Hashtbl.find_opt by_key key with
          | Some r -> r
          | None ->
              let r = ref [] in
              Hashtbl.add by_key key r;
              order := key :: !order;
              r
        in
        List.iter
          (fun (c : Provider.column) ->
            if
              c.name <> ""
              && not (List.exists (fun (x : Catalog.column) -> x.col_name = c.name) !cols)
            then cols := !cols @ [ { Catalog.col_name = c.name; col_type = None } ])
          tb.columns
      end)
    tables;
  let tables =
    List.filter_map
      (fun ((schema, name) as key) ->
        match !(Hashtbl.find by_key key) with
        | [] -> None
        | columns -> Some { Catalog.schema; name; columns })
      (List.rev !order)
    |> List.stable_sort (fun (a : Catalog.table) (b : Catalog.table) ->
        compare (a.schema, a.name) (b.schema, b.name))
  in
  {
    Snapshot.catalog = { Catalog.tables };
    relkinds =
      List.map (fun (tb : Catalog.table) -> ((tb.schema, tb.name), Snapshot.Table)) tables;
    database;
    server_version = None;
    schemas =
      List.sort_uniq String.compare
        (List.map (fun (tb : Catalog.table) -> tb.schema) tables);
    authoritative = false;
  }
