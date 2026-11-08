(* DataHub provider (see datahub_fetch.mli). *)

open Lwt.Syntax

let name = "datahub"

let description =
  "DataHub GraphQL API (scrollAcrossEntities): column tags and glossary terms from \
   schemaMetadata and editableSchemaMetadata of postgres datasets"

let default_token_env = "DATAHUB_TOKEN"

let page_size () =
  match Option.bind (Sys.getenv_opt "HALTSQL_DATAHUB_PAGE_SIZE") int_of_string_opt with
  | Some n when n >= 1 && n <= 1000 -> n
  | _ -> 100

let platform_urn = "urn:li:dataPlatform:postgres"

let instance_urn instance =
  Printf.sprintf "urn:li:dataPlatformInstance:(%s,%s)" platform_urn instance

let field k = function `Assoc kvs -> List.assoc_opt k kvs | _ -> None
let str k j = match field k j with Some (`String s) when s <> "" -> Some s | _ -> None
let list k j = match field k j with Some (`List l) -> l | _ -> []
let path ks j = List.fold_left (fun acc k -> Option.bind acc (field k)) (Some j) ks

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let hint e =
  if contains e "401" || contains e "403" then
    e
    ^ " (check the DataHub Personal Access Token: it must be valid for this server, and \
       metadata service authentication must be enabled for tokens to work)"
  else if contains e "404" then
    e
    ^ " (check --url: the GMS or frontend root, e.g. http://datahub-gms:8080, or a \
       GraphQL root ending in /api or /api/v2)"
  else e

(* GMS and the frontend both serve GraphQL at /api/graphql; the frontend also at
   /api/v2/graphql. *)
let graphql_path client =
  let base = Uri.path (Fetch_client.base_url client) in
  let base =
    if String.ends_with ~suffix:"/" base then String.sub base 0 (String.length base - 1)
    else base
  in
  if String.ends_with ~suffix:"/api/v2" base || String.ends_with ~suffix:"/api" base then
    "/graphql"
  else "/api/graphql"

(* ------------------------------------------------------------ queries *)

let label_fields =
  "globalTags { tags { tag { urn properties { name } } } } glossaryTerms { terms { term \
   { urn properties { name } } } }"

let dataset_query =
  String.concat " "
    [
      "query haltsqlDatasets($input: ScrollAcrossEntitiesInput!) {";
      "scrollAcrossEntities(input: $input) { nextScrollId";
      "searchResults { entity { urn type ... on Dataset {";
      "platform { urn } dataPlatformInstance { instanceId }";
      "parentContainers { containers { urn subTypes { typeNames } properties { name } } }";
      "schemaMetadata(version: 0) { fields { fieldPath nativeDataType";
      label_fields;
      "} }";
      "editableSchemaMetadata { editableSchemaFieldInfo { fieldPath";
      label_fields;
      "} } } } } } }";
    ]

let container_query =
  String.concat " "
    [
      "query haltsqlContainers($input: ScrollAcrossEntitiesInput!) {";
      "scrollAcrossEntities(input: $input) { nextScrollId";
      "searchResults { entity { urn type ... on Container {";
      "properties { name } subTypes { typeNames } platform { urn }";
      "dataPlatformInstance { instanceId }";
      "parentContainers { containers { urn subTypes { typeNames } properties { name } } }";
      "} } } } }";
    ]

let criterion k values =
  `Assoc
    [ ("field", `String k); ("values", `List (List.map (fun v -> `String v) values)) ]

(* One scrollAcrossEntities listing of [etype] matching every criterion. *)
let scroll client ~what ~query etype criteria =
  let gpath = graphql_path client in
  Fetch_client.paginate client ~what (fun cursor ->
      let input =
        [
          ("types", `List [ `String etype ]);
          ("query", `String "*");
          ("count", `Int (page_size ()));
          ("orFilters", `List [ `Assoc [ ("and", `List criteria) ] ]);
        ]
        @ match cursor with Some c -> [ ("scrollId", `String c) ] | None -> []
      in
      let body =
        `Assoc
          [ ("query", `String query); ("variables", `Assoc [ ("input", `Assoc input) ]) ]
      in
      let+ r = Fetch_client.post_json client gpath body in
      match r with
      | Error e -> Error (hint e)
      | Ok j -> (
          match list "errors" j with
          | _ :: _ as errs ->
              let msg e =
                match str "message" e with
                | Some m when String.length m > 200 -> String.sub m 0 200 ^ "..."
                | Some m -> m
                | None -> "(no message)"
              in
              Error
                (Printf.sprintf "%s: GraphQL error: %s" what
                   (String.concat "; " (List.sort_uniq compare (List.map msg errs))))
          | [] -> (
              match path [ "data"; "scrollAcrossEntities" ] j with
              | Some (`Assoc _ as s) ->
                  Ok
                    ( List.filter_map (field "entity") (list "searchResults" s),
                      str "nextScrollId" s )
              | _ ->
                  Error
                    (Printf.sprintf "%s: response has no data.scrollAcrossEntities" what))
          ))

(* ------------------------------------------------------------ scope *)

let sub_types c =
  match path [ "subTypes"; "typeNames" ] c with
  | Some (`List l) -> List.filter_map (function `String s -> Some s | _ -> None) l
  | _ -> []

let entity_name c = Option.bind (field "properties" c) (str "name")
let instance e = Option.bind (field "dataPlatformInstance" e) (str "instanceId")
let platform e = Option.bind (field "platform" e) (str "urn")

let parents e =
  match path [ "parentContainers"; "containers" ] e with Some (`List l) -> l | _ -> []

(* The name of the nearest parent container of subtype [sub]. *)
let parent_named sub e =
  List.find_map
    (fun c -> if List.mem sub (sub_types c) then entity_name c else None)
    (parents e)

let same_platform (f : Provider.filter) e =
  platform e = Some platform_urn
  && match f.service with None -> true | Some s -> instance e = Some s

let in_scope (f : Provider.filter) d =
  same_platform f d
  && (match f.database with
    | None -> true
    | Some db -> parent_named "Database" d = Some db)
  && (f.schemas = []
     ||
     match parent_named "Schema" d with
     | Some s -> List.mem s f.schemas
     | None -> false)

let base_criteria (f : Provider.filter) =
  criterion "platform" [ platform_urn ]
  ::
  (match f.service with
  | Some s -> [ criterion "platformInstance" [ instance_urn s ] ]
  | None -> [])

let scope_desc (f : Provider.filter) =
  String.concat ""
    [
      Option.fold ~none:"" ~some:(fun s -> " in platform instance " ^ s) f.service;
      Option.fold ~none:"" ~some:(fun d -> " in database " ^ d) f.database;
      (if f.schemas = [] then "" else " in schema(s) " ^ String.concat ", " f.schemas);
    ]

(* The schema containers in scope, when --database or --schema narrows it: database
   containers by name, then their schema containers (each re-checked). [None] when the
   whole platform (instance) is in scope. *)
let schema_containers client (f : Provider.filter) =
  let urn c = str "urn" c in
  let ( let*? ) r k =
    Lwt.bind r (function Error e -> Lwt.return (Error e) | Ok x -> k x)
  in
  match (f.database, f.schemas) with
  | None, [] -> Lwt.return (Ok None)
  | db, schemas ->
      let*? dbs =
        match db with
        | None -> Lwt.return (Ok None)
        | Some d ->
            let*? cs =
              scroll client ~what:"datahub database containers" ~query:container_query
                "CONTAINER"
                (base_criteria f
                @ [ criterion "typeNames" [ "Database" ]; criterion "name" [ d ] ])
            in
            let cs =
              List.filter
                (fun c ->
                  same_platform f c
                  && List.mem "Database" (sub_types c)
                  && entity_name c = Some d)
                cs
            in
            if cs = [] then
              Lwt.return
                (Error
                   (Printf.sprintf
                      "datahub: no postgres database container named %S%s (check \
                       --database and --service)"
                      d
                      (Option.fold ~none:""
                         ~some:(fun s -> " in platform instance " ^ s)
                         f.service)))
            else Lwt.return (Ok (Some (List.filter_map urn cs)))
      in
      let*? cs =
        scroll client ~what:"datahub schema containers" ~query:container_query "CONTAINER"
          (base_criteria f
          @ [ criterion "typeNames" [ "Schema" ] ]
          @ (match dbs with Some us -> [ criterion "container" us ] | None -> [])
          @ if schemas = [] then [] else [ criterion "name" schemas ])
      in
      let cs =
        List.filter
          (fun c ->
            same_platform f c
            && List.mem "Schema" (sub_types c)
            && (schemas = []
               || match entity_name c with Some n -> List.mem n schemas | None -> false)
            &&
            match dbs with
            | None -> true
            | Some us ->
                List.exists
                  (fun p ->
                    List.mem "Database" (sub_types p)
                    && Option.fold ~none:false ~some:(fun u -> List.mem u us) (urn p))
                  (parents c))
          cs
      in
      if cs = [] then
        Lwt.return
          (Error
             (Printf.sprintf "datahub: no postgres schema containers%s" (scope_desc f)))
      else Lwt.return (Ok (Some (List.filter_map urn cs)))

(* ------------------------------------------------------------ tables *)

(* Dataset name from the urn: [instance.]database.schema.table. *)
let urn_name urn =
  let prefix = "urn:li:dataset:(" in
  if not (String.starts_with ~prefix urn) then None
  else
    let inner =
      String.sub urn (String.length prefix) (String.length urn - String.length prefix)
    in
    match String.index_opt inner ',' with
    | None -> None
    | Some i -> (
        let rest = String.sub inner (i + 1) (String.length inner - i - 1) in
        match String.rindex_opt rest ',' with
        | Some j -> Some (String.sub rest 0 j)
        | None -> None)

let column_name fp =
  match
    String.split_on_char '.' fp
    |> List.filter (fun s -> s <> "" && s.[0] <> '[')
    |> List.rev
  with
  | x :: _ -> Some x
  | [] -> None

(* Schema and table as the importer derives them: the last two parts of the urn name. *)
let to_table d : Provider.table option =
  match Option.bind (str "urn" d) urn_name with
  | None -> None
  | Some n -> (
      match List.rev (String.split_on_char '.' n) with
      | table :: schema :: _ when table <> "" && schema <> "" ->
          let fields =
            match path [ "schemaMetadata"; "fields" ] d with
            | Some (`List l) -> l
            | _ -> []
          in
          let columns =
            List.filter_map
              (fun c ->
                Option.map
                  (fun name ->
                    {
                      Provider.name;
                      data_type =
                        Option.map String.lowercase_ascii (str "nativeDataType" c);
                    })
                  (Option.bind (str "fieldPath" c) column_name))
              fields
          in
          Some { Provider.schema; name = table; columns }
      | _ -> None)

let fetch client (f : Provider.filter) =
  let* scs = schema_containers client f in
  match scs with
  | Error e -> Lwt.return (Error e)
  | Ok scs -> (
      let criteria =
        base_criteria f
        @ match scs with Some us -> [ criterion "container" us ] | None -> []
      in
      let* items =
        scroll client ~what:"datahub datasets" ~query:dataset_query "DATASET" criteria
      in
      match items with
      | Error e -> Lwt.return (Error e)
      | Ok items ->
          let kept, dropped = List.partition (in_scope f) items in
          if kept = [] then
            Lwt.return
              (Error
                 (Printf.sprintf
                    "datahub: no postgres datasets found%s (check \
                     --service/--database/--schema)"
                    (scope_desc f)))
          else
            let warnings =
              if dropped = [] then []
              else
                [
                  Printf.sprintf
                    "datahub: ignored %d dataset(s) outside the requested scope returned \
                     by the server"
                    (List.length dropped);
                ]
            in
            let databases =
              List.sort_uniq compare (List.filter_map (parent_named "Database") kept)
            in
            let warnings =
              warnings
              @
              if List.length databases > 1 then
                [
                  Printf.sprintf
                    "datahub: datasets from %d databases (%s) are merged into one \
                     manifest keyed by schema.table; pass --database to pick one"
                    (List.length databases)
                    (String.concat ", " databases);
                ]
              else []
            in
            let tables, nameless =
              List.fold_left
                (fun (ok, bad) d ->
                  match to_table d with Some x -> (x :: ok, bad) | None -> (ok, bad + 1))
                ([], 0) kept
            in
            let warnings =
              warnings
              @
              if nameless = 0 then []
              else
                [
                  Printf.sprintf
                    "datahub: %d dataset(s) without a schema.table name skipped" nameless;
                ]
            in
            Lwt.return
              (Ok
                 {
                   Provider.source = Haltsql_catalog_tools.Pii_import.Datahub;
                   document = `Assoc [ ("data", `Assoc [ ("datasets", `List kept) ]) ];
                   tables = List.rev tables;
                   warnings;
                 }))
