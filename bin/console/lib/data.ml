(* Data classification from catalogs (docs/console/api.md#data-classification).

   Catalogs ([catalogs:] in the config) are read at startup, every 15 minutes and on
   POST /api/v1/data/refresh. Tags are read with the same importers as [haltsql schema
   import] and [haltsql report --pii] ([Haltsql_catalog_tools.Pii_import], [Pii]); live
   catalogs (DataHub, OpenMetadata) go through [Haltsql_catalog_fetch]. Columns are merged
   per [schema.table.column] (union of tags and sources).

   A live fetch only ever flags columns: its structure is a catalog's view, never
   authoritative, so it is marked [authoritative: false] and is never loaded as a policy
   catalog (see lib/catalog_fetch/catalog_fetch.mli).

   For each tagged column the console derives which loaded policies allow reading it
   (directly from the compiled allowlist: SELECT allowed, table listed, column listed or
   all columns), whether an approved exception covers it, and how many shadow-denied
   records read it. The resulting document is read with [columns_doc]. *)

open Lwt.Syntax
module C = Console_config
module Ct = Haltsql_catalog_tools
module Cf = Haltsql_catalog_fetch
module Policy = Haltsql.Policy
module Record = Haltsql_report.Record

type source = {
  kind : string;
  label : string;  (** the catalog's [label], else its kind; shown in column sources *)
  detail : string;
  as_of : float option;
  authoritative : bool;
  error : string option;
}

type column = {
  key : string;  (** lower-case [schema.table.column] *)
  table_key : string;  (** lower-case [schema.table] *)
  schema : string;
  table : string;
  name : string;
  tags : string list;
  sources : string list;
  authoritative : bool;  (** at least one authoritative source tags it *)
}

type state = {
  mutable catalog_sources : source list;
  mutable columns : column list;
  mutable loaded_at : float option;
  mutable last_manual : float;
  derived_columns : (string, string list) Hashtbl.t;
      (** request id -> columns re-derived from raw SQL (cache) *)
  lock : Lwt_mutex.t;
  mutable doc : Yojson.Safe.t option;
      (** the last [GET /api/v1/data/columns] document, read through [columns_doc] *)
}

(* One state per console, in the Ctx registry under a private key. *)
let key : state Ctx.Key.t = Ctx.Key.create "data"

let state (ctx : Ctx.t) =
  match Ctx.get ctx key with
  | Some s -> s
  | None ->
      let s =
        {
          catalog_sources = [];
          columns = [];
          loaded_at = None;
          last_manual = neg_infinity;
          derived_columns = Hashtbl.create 64;
          lock = Lwt_mutex.create ();
          doc = None;
        }
      in
      Ctx.set ctx key s;
      s

(** Live catalog providers by name. Tests register fakes here. *)
let providers : (module Cf.Provider.S) list ref = ref Cf.Catalog_fetch.providers

let refresh_interval = 15. *. 60.
let manual_refresh_interval = 60.

let log level fmt =
  Printf.ksprintf
    (fun m ->
      Printf.eprintf "{\"ts\":%S,\"level\":%S,\"component\":\"data\",\"msg\":%s}\n%!"
        (Api.iso8601 (Unix.gettimeofday ()))
        level
        (Yojson.Safe.to_string (`String m)))
    fmt

(* ---- reading catalogs ---- *)

let opt_str name (j : Yojson.Safe.t) =
  match Api.member name j with Some (`String s) when s <> "" -> Some s | _ -> None

let opt_strs name (j : Yojson.Safe.t) =
  match Api.member name j with
  | Some (`List l) -> List.filter_map (function `String s -> Some s | _ -> None) l
  | _ -> []

let matcher_config (j : Yojson.Safe.t) =
  let d = Ct.Pii.Matcher.default in
  let tags = opt_strs "tags" j and terms = opt_strs "terms" j in
  {
    Ct.Pii.Matcher.tags = (if tags = [] then d.tags else tags);
    terms = (if terms = [] then d.terms else terms);
  }

let mtime path = try Some (Unix.stat path).Unix.st_mtime with _ -> None

(* A URL as shown to people: no credentials, query or fragment. *)
let show_url u =
  let u = Uri.of_string u in
  Uri.to_string (Uri.with_fragment (Uri.with_query (Uri.with_userinfo u None) []) None)

exception Load_failed of string

let failf fmt = Printf.ksprintf (fun m -> raise (Load_failed m)) fmt

let import_file ~config src path =
  match Ct.Pii_import.import_file ~config src path with
  | Ok r -> r.manifest
  | Error e -> failf "%s" e

let live_fetch ~kind ~config (o : Yojson.Safe.t) url =
  match
    List.find_opt (fun (module P : Cf.Provider.S) -> String.equal P.name kind) !providers
  with
  | None ->
      failf "no live %s provider is built into this console; configure an export file"
        kind
  | Some (module P) -> (
      let auth =
        match opt_str "token" o with
        | Some t -> Cf.Fetch_client.Bearer t
        | None -> Cf.Fetch_client.No_auth
      in
      let* http_ctx =
        match opt_str "ca_file" o with
        | None -> Lwt.return Haltsql_cloud.Http.default_ctx
        | Some f -> (
            let* r = Haltsql_cloud.Http.ctx_of_ca_file f in
            match r with Ok c -> Lwt.return c | Error e -> failf "ca_file: %s" e)
      in
      let timeout =
        match Api.member "timeout_seconds" o with
        | Some (`Int n) when n > 0 -> float_of_int n
        | _ -> 30.
      in
      match Cf.Fetch_client.create ~ctx:http_ctx ~timeout ~base_url:url auth with
      | Error e -> failf "%s" e
      | Ok client -> (
          let filter =
            {
              Cf.Provider.service = opt_str "service" o;
              database = opt_str "database" o;
              schemas = opt_strs "schemas" o;
            }
          in
          let* r = Cf.Catalog_fetch.run ~config (module P) client filter in
          match r with
          | Ok r -> Lwt.return r.manifest
          | Error e -> failf "live fetch failed: %s" e))

(** Reads one catalog: its source description and its tagged columns. Never raises. *)
let load_catalog (k : C.catalog) : (source * Ct.Pii.t) Lwt.t =
  let o = k.c_options in
  let config = matcher_config o in
  let label = Option.value k.c_label ~default:k.c_kind in
  let file_source path = (path, mtime path, true) in
  let attempt () =
    match (k.c_kind, opt_str "url" o) with
    | ("datahub" | "openmetadata" | "unity"), Some url ->
        let* m = live_fetch ~kind:k.c_kind ~config o url in
        Lwt.return (("live fetch from " ^ show_url url, Some (Ctx.now ()), false), m)
    | "dbt", _ ->
        let manifest =
          match (opt_str "manifest" o, opt_str "file" o) with
          | Some p, _ | None, Some p -> p
          | None, None -> failf "dbt catalogs need manifest"
        in
        let m = import_file ~config Ct.Pii_import.Dbt manifest in
        let m =
          match opt_str "catalog" o with
          | Some c -> Ct.Pii.merge [ m; import_file ~config Ct.Pii_import.Dbt c ]
          | None -> m
        in
        Lwt.return (file_source manifest, m)
    | (("datahub" | "unity") as kind), None -> (
        match opt_str "file" o with
        | None -> failf "%s catalogs need file (an export) or url (live)" kind
        | Some p ->
            let src =
              if kind = "datahub" then Ct.Pii_import.Datahub else Ct.Pii_import.Unity
            in
            Lwt.return (file_source p, import_file ~config src p))
    | "openmetadata", None -> failf "openmetadata catalogs need url"
    | "file", _ -> (
        match (opt_str "file" o, opt_str "path" o) with
        | Some p, _ | None, Some p -> (
            match Ct.Pii.of_file p with
            | Ok m -> Lwt.return (file_source p, m)
            | Error e -> failf "%s" e)
        | None, None -> failf "file catalogs need file")
    | kind, _ ->
        failf "unknown catalog kind %S (dbt, datahub, openmetadata, unity, file)" kind
  in
  Lwt.catch
    (fun () ->
      let* (detail, as_of, authoritative), m = attempt () in
      Lwt.return
        ( {
            kind = k.c_kind;
            label;
            detail = Option.value (opt_str "detail" o) ~default:detail;
            as_of;
            authoritative;
            error = None;
          },
          m ))
    (fun e ->
      let msg =
        match e with Load_failed m -> m | Sys_error m -> m | e -> Printexc.to_string e
      in
      log "warn" "catalog %s (%s) not loaded: %s" label k.c_kind msg;
      Lwt.return
        ( {
            kind = k.c_kind;
            label;
            detail = Option.value (opt_str "detail" o) ~default:"";
            as_of = None;
            authoritative = false;
            error = Some msg;
          },
          Ct.Pii.empty ))

let lc = String.lowercase_ascii

let uniq l =
  let seen = Hashtbl.create 8 in
  List.filter
    (fun s ->
      let k = lc s in
      if Hashtbl.mem seen k then false
      else (
        Hashtbl.add seen k ();
        true))
    l

(** Merges every catalog's columns per lower-case [schema.table.column]. *)
let merge (loaded : (source * Ct.Pii.t) list) : column list =
  let tbl : (string, column) Hashtbl.t = Hashtbl.create 64 in
  List.iter
    (fun (src, m) ->
      List.iter
        (fun (e : Ct.Pii.entry) ->
          let key = lc (e.schema ^ "." ^ e.table ^ "." ^ e.column) in
          let fresh =
            {
              key;
              table_key = lc (e.schema ^ "." ^ e.table);
              schema = lc e.schema;
              table = lc e.table;
              name = lc e.column;
              tags = e.classifications;
              sources = [ src.label ];
              authoritative = src.authoritative;
            }
          in
          let merged =
            match Hashtbl.find_opt tbl key with
            | None -> fresh
            | Some c ->
                {
                  c with
                  tags = c.tags @ fresh.tags;
                  sources = c.sources @ fresh.sources;
                  authoritative = c.authoritative || fresh.authoritative;
                }
          in
          Hashtbl.replace tbl key
            { merged with tags = uniq merged.tags; sources = uniq merged.sources })
        m)
    loaded;
  Hashtbl.fold (fun _ c acc -> c :: acc) tbl []
  |> List.sort (fun a b -> compare a.key b.key)

(** Re-reads every configured catalog. *)
let reload (ctx : Ctx.t) =
  let st = state ctx in
  Lwt_mutex.with_lock st.lock (fun () ->
      let* loaded = Lwt_list.map_p load_catalog ctx.config.catalogs in
      st.catalog_sources <- List.map fst loaded;
      st.columns <- merge loaded;
      st.loaded_at <- Some (Ctx.now ());
      Lwt.return_unit)

(* ---- policies, exceptions, shadow denials ---- *)

(** True when [p]'s allowlist lets a SELECT read [col]. *)
let policy_allows (p : Policy.t) (col : column) =
  List.mem Policy.Select p.statements
  && List.exists
       (fun (t : Policy.table) ->
         lc t.schema = col.schema
         && lc t.name = col.table
         &&
         match t.columns with
         | Policy.All -> true
         | Policy.Only l -> List.exists (fun c -> lc c = col.name) l)
       p.tables

let parse_expiry s =
  match Api.parse_time s with
  | Some t -> Some t
  | None -> (
      (* A plain date: valid through the end of that day (UTC). *)
      match Api.parse_time (s ^ "T00:00:00Z") with
      | Some t -> Some (t +. 86400.)
      | None -> None)

(** An exception without a parsable expiry never expires; one with an unparsable expiry
    counts as expired (so it is reviewed rather than trusted). *)
let expired ~now (e : C.exception_) =
  match e.e_expires with
  | None -> false
  | Some s -> ( match parse_expiry s with Some t -> now >= t | None -> true)

let exception_status ~now (e : C.exception_) =
  if expired ~now e then "expired" else "active"

let exception_to_json ~now (e : C.exception_) =
  `Assoc
    [
      ("column", `String e.e_column);
      ("policy", Api.opt_string e.e_policy);
      ("owner", `String e.e_owner);
      ("ticket", Api.opt_string e.e_ticket);
      ("expires", Api.opt_string e.e_expires);
      ("expired", `Bool (expired ~now e));
    ]

(* Columns a shadow-denied record read: from the record when it says, otherwise
   re-derived from its raw SQL against the named policy (cached per request id). *)
let record_columns (ctx : Ctx.t) st (e : Index.entry) =
  if e.record.columns <> [] then e.record.columns
  else
    match Hashtbl.find_opt st.derived_columns e.request_id with
    | Some cols -> cols
    | None ->
        let cols =
          match (e.record.sql, Policy_set.find ctx e.record.policy) with
          | Some sql, Some p -> (
              try
                (Haltsql.verify p (Haltsql_report.Suggest.probe_context p) sql)
                  .Haltsql.Verdict.columns
              with _ -> [])
          | _ -> []
        in
        Hashtbl.replace st.derived_columns e.request_id cols;
        cols

let shadow_denials (ctx : Ctx.t) st =
  let counts : (string, int) Hashtbl.t = Hashtbl.create 64 in
  Index.iter ctx.index (fun e ->
      if e.record.outcome = Record.Shadow_denied then
        List.iter
          (fun c ->
            let c = lc c in
            Hashtbl.replace counts c
              (1 + Option.value (Hashtbl.find_opt counts c) ~default:0))
          (List.sort_uniq compare (record_columns ctx st e)));
  counts

let source_to_json s =
  `Assoc
    [
      ("kind", `String s.kind);
      ("label", `String s.label);
      ("detail", `String s.detail);
      ("as_of", Api.opt_time s.as_of);
      ("authoritative", `Bool s.authoritative);
      ("error", Api.opt_string s.error);
    ]

(** Builds the [GET /api/v1/data/columns] document from the loaded catalogs, the loaded
    policies, the configured exceptions and the index, and stores it in the state read by
    [columns_doc]. *)
let compute (ctx : Ctx.t) =
  let st = state ctx in
  let now = Ctx.now () in
  let denials = shadow_denials ctx st in
  let exceptions = ctx.config.exceptions in
  let n_blocked = ref 0 and n_exception = ref 0 and n_review = ref 0 in
  let columns =
    List.map
      (fun col ->
        let allowed_by =
          List.filter_map
            (fun (name, p) -> if policy_allows p col then Some name else None)
            (Policy_set.get ctx)
          |> List.sort_uniq compare
        in
        let matching =
          List.filter (fun (e : C.exception_) -> lc e.e_column = col.key) exceptions
        in
        let covers p (e : C.exception_) =
          match e.e_policy with None -> true | Some q -> q = p
        in
        let active = List.filter (fun e -> not (expired ~now e)) matching in
        let status, exc =
          if allowed_by = [] then ("blocked", None)
          else
            let covering =
              List.filter (fun e -> List.exists (fun p -> covers p e) allowed_by) active
            in
            if
              covering <> []
              && List.for_all (fun p -> List.exists (covers p) active) allowed_by
            then ("exception", Some (List.hd covering))
            else
              ( "needs_review",
                List.find_opt
                  (fun e -> List.exists (fun p -> covers p e) allowed_by)
                  matching )
        in
        (match status with
        | "blocked" -> incr n_blocked
        | "exception" -> incr n_exception
        | _ -> incr n_review);
        `Assoc
          [
            ("column", `String col.key);
            ("tags", Api.strings col.tags);
            ("sources", Api.strings col.sources);
            ("authoritative", `Bool col.authoritative);
            ("allowed_by", Api.strings allowed_by);
            ("status", `String status);
            ( "exception",
              match exc with None -> `Null | Some e -> exception_to_json ~now e );
            ( "shadow_denials",
              `Int (Option.value (Hashtbl.find_opt denials col.key) ~default:0) );
          ])
      st.columns
  in
  let tables = List.sort_uniq compare (List.map (fun c -> c.table_key) st.columns) in
  let doc =
    `Assoc
      [
        ("updated", `String (Api.iso8601 now));
        ("loaded", Api.opt_time st.loaded_at);
        ("sources", `List (List.map source_to_json st.catalog_sources));
        ( "totals",
          `Assoc
            [
              ("tagged", `Int (List.length st.columns));
              ("tables", `Int (List.length tables));
              ("blocked", `Int !n_blocked);
              ("exception", `Int !n_exception);
              ("needs_review", `Int !n_review);
            ] );
        ("columns", `List columns);
      ]
  in
  st.doc <- Some doc;
  doc

(** The last computed [GET /api/v1/data/columns] document, [None] before the first. *)
let columns_doc (ctx : Ctx.t) = (state ctx).doc

(** For tests only: replaces the stored classification document without loading catalogs.
*)
module Testing = struct
  let set_columns_doc (ctx : Ctx.t) doc = (state ctx).doc <- doc
end

(** Catalog sources and their load errors (for integrations). *)
let sources (ctx : Ctx.t) = (state ctx).catalog_sources

let loaded (ctx : Ctx.t) = (state ctx).loaded_at <> None

(* ---- HTTP ---- *)

let columns_handler (ctx : Ctx.t) _p (r : Router.req) =
  let doc = compute ctx in
  let show =
    match Router.query r "show" with
    | None | Some "" | Some "allowed" -> `Allowed
    | Some "all" -> `All
    | Some s -> Api.bad_request "show must be allowed or all (got %S)" s
  in
  let q = Option.map lc (Router.query r "q") in
  let contains ~sub s =
    let n = String.length sub and m = String.length s in
    let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
    n = 0 || go 0
  in
  let keep (c : Yojson.Safe.t) =
    let s name = match Api.member name c with Some (`String x) -> x | _ -> "" in
    (match show with `All -> true | `Allowed -> s "status" <> "blocked")
    &&
    match q with
    | None | Some "" -> true
    | Some q -> (
        contains ~sub:q (lc (s "column"))
        ||
        match Api.member "tags" c with
        | Some (`List tags) ->
            List.exists (function `String t -> contains ~sub:q (lc t) | _ -> false) tags
        | _ -> false)
  in
  let filtered =
    match doc with
    | `Assoc l ->
        `Assoc
          (List.map
             (fun (k, v) ->
               match (k, v) with
               | "columns", `List cs -> (k, `List (List.filter keep cs))
               | _ -> (k, v))
             l)
    | d -> d
  in
  Api.json filtered

let refresh_handler (ctx : Ctx.t) p _r =
  let st = state ctx in
  let now = Ctx.now () in
  let wait = st.last_manual +. manual_refresh_interval -. now in
  if wait > 0. then
    Api.fail `Too_many_requests "RATE_LIMITED"
      "catalogs were refreshed less than a minute ago; retry in %d s"
      (int_of_float (Float.ceil wait));
  st.last_manual <- now;
  let* () = reload ctx in
  let doc = compute ctx in
  let* () =
    Activity.log ctx p ~action:"data.refresh" ~target:"catalogs"
      ~detail:
        (`Assoc
           [
             ("catalogs", `Int (List.length st.catalog_sources));
             ( "errors",
               `Int
                 (List.length (List.filter (fun s -> s.error <> None) st.catalog_sources))
             );
           ])
      ()
  in
  let pick k = Option.value (Api.member k doc) ~default:`Null in
  Api.json
    (`Assoc
       [
         ("updated", pick "updated");
         ("sources", pick "sources");
         ("totals", pick "totals");
       ])

let routes : Router.route list =
  [
    Router.get "/api/v1/data/columns" columns_handler;
    Router.post "/api/v1/data/refresh" refresh_handler;
  ]

(** Loads catalogs at startup and every 15 minutes; never returns. *)
let start (ctx : Ctx.t) : unit Lwt.t =
  let rec loop () =
    let* () =
      Lwt.catch
        (fun () ->
          let* () = reload ctx in
          ignore (compute ctx);
          Lwt.return_unit)
        (fun e ->
          log "error" "catalog refresh failed: %s" (Printexc.to_string e);
          Lwt.return_unit)
    in
    let* () = Lwt_unix.sleep refresh_interval in
    loop ()
  in
  loop ()
