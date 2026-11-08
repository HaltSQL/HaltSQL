(* OpenMetadata provider (see openmetadata_fetch.mli). *)

open Lwt.Syntax

let name = "openmetadata"

let description =
  "OpenMetadata REST API (/api/v1/tables): column classification tags and glossary terms"

let default_token_env = "OPENMETADATA_TOKEN"

let page_size () =
  match
    Option.bind (Sys.getenv_opt "HALTSQL_OPENMETADATA_PAGE_SIZE") int_of_string_opt
  with
  | Some n when n >= 1 && n <= 1000 -> n
  | _ -> 100

let quote_name n = if String.contains n '.' then "\"" ^ n ^ "\"" else n
let field k = function `Assoc kvs -> List.assoc_opt k kvs | _ -> None
let str k j = match field k j with Some (`String s) when s <> "" -> Some s | _ -> None
let list k j = match field k j with Some (`List l) -> l | _ -> []
let ref_name k j = Option.bind (field k j) (str "name")

let hint e =
  let has sub =
    let n = String.length e and m = String.length sub in
    let rec go i = i + m <= n && (String.sub e i m = sub || go (i + 1)) in
    go 0
  in
  if has "401" || has "403" then
    e
    ^ " (check the OpenMetadata bot JWT: it must be valid for this server and its bot \
       needs read access to tables, e.g. the DataConsumer role)"
  else e

(* One cursor-paginated listing of [path] with [query]. *)
let list_all client ~what path query =
  Fetch_client.paginate client ~what (fun cursor ->
      let query =
        query
        @ [ ("limit", string_of_int (page_size ())) ]
        @ match cursor with Some c -> [ ("after", c) ] | None -> []
      in
      let+ r = Fetch_client.get_json client ~query path in
      match r with
      | Error e -> Error (hint e)
      | Ok j -> (
          match field "data" j with
          | Some (`List items) ->
              let next =
                match Option.bind (field "paging" j) (field "after") with
                | Some (`String s) when s <> "" -> Some s
                | _ -> None
              in
              Ok (items, next)
          | _ -> Error (Printf.sprintf "%s: response has no \"data\" array" what)))

let table_fields = [ ("fields", "columns,tags"); ("include", "non-deleted") ]

(* The table's place in the hierarchy, from its entity references (falling back to the
   FQN is not needed: the API always returns them for tables). *)
let in_scope (f : Provider.filter) t =
  let eq want got = match want with None -> true | Some w -> got = Some w in
  eq f.service (ref_name "service" t)
  && eq f.database (ref_name "database" t)
  && (f.schemas = []
     ||
     match ref_name "databaseSchema" t with
     | Some s -> List.mem s f.schemas
     | None -> false)

let to_table t : Provider.table option =
  match (ref_name "databaseSchema" t, str "name" t) with
  | Some schema, Some tname ->
      let columns =
        List.filter_map
          (fun c ->
            match str "name" c with
            | None -> None
            | Some cname ->
                let data_type =
                  match str "dataTypeDisplay" c with
                  | Some d -> Some d
                  | None -> Option.map String.lowercase_ascii (str "dataType" c)
                in
                Some { Provider.name = cname; data_type })
          (list "columns" t)
      in
      Some { Provider.schema; name = tname; columns }
  | _ -> None

let fetch client (f : Provider.filter) =
  let tables_in query what =
    list_all client ~what "/api/v1/tables" (table_fields @ query)
  in
  let* items =
    match (f.service, f.database, f.schemas) with
    | None, Some _, _ ->
        Lwt.return
          (Error
             "openmetadata: --database needs --service (OpenMetadata names databases \
              service.database)")
    | Some s, Some d, [] ->
        tables_in
          [ ("database", quote_name s ^ "." ^ quote_name d) ]
          "openmetadata tables"
    | Some s, Some d, schemas ->
        let rec go acc = function
          | [] -> Lwt.return (Ok (List.concat (List.rev acc)))
          | sch :: rest -> (
              let fqn = String.concat "." (List.map quote_name [ s; d; sch ]) in
              let* r =
                tables_in [ ("databaseSchema", fqn) ] ("openmetadata tables of " ^ fqn)
              in
              match r with Ok l -> go (l :: acc) rest | Error _ as e -> Lwt.return e)
        in
        go [] schemas
    | Some s, None, _ -> tables_in [ ("service", s) ] "openmetadata tables"
    | None, None, _ -> tables_in [] "openmetadata tables"
  in
  match items with
  | Error e -> Lwt.return (Error e)
  | Ok [] ->
      Lwt.return
        (Error
           (Printf.sprintf
              "openmetadata: no tables found%s (check --service/--database/--schema: \
               OpenMetadata returns an empty list for unknown names)"
              (match (f.service, f.database) with
              | Some s, Some d -> Printf.sprintf " in database %s.%s" s d
              | Some s, None -> " in service " ^ s
              | _ -> "")))
  | Ok items ->
      let kept, dropped = List.partition (in_scope f) items in
      let warnings =
        if dropped = [] then []
        else
          [
            Printf.sprintf
              "openmetadata: ignored %d table(s) outside the requested scope returned by \
               the server"
              (List.length dropped);
          ]
      in
      let tables, nameless =
        List.fold_left
          (fun (ok, bad) t ->
            match to_table t with Some x -> (x :: ok, bad) | None -> (ok, bad + 1))
          ([], 0) kept
      in
      let warnings =
        warnings
        @
        if nameless = 0 then []
        else
          [
            Printf.sprintf "openmetadata: %d table(s) without databaseSchema/name skipped"
              nameless;
          ]
      in
      Lwt.return
        (Ok
           {
             Provider.source = Haltsql_catalog_tools.Pii_import.Openmetadata;
             document = `Assoc [ ("data", `List kept) ];
             tables = List.rev tables;
             warnings;
           })
