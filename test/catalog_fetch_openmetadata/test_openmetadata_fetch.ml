(* OpenMetadata provider against replayed live responses (see dune). The fixtures were
   captured from OpenMetadata 2.0.7 seeded by test/catalog_live/openmetadata/seed.py:
   service haltsql_lab_pg, database om_src_7341 (9 tables, 3 pages at limit=4) and an
   API-only database "lake" with a STRUCT column. *)

open Haltsql_catalog_fetch
module Ct = Haltsql_catalog_tools
module Om = Openmetadata_fetch

let fixture f =
  In_channel.with_open_bin (Filename.concat "fixtures" f) In_channel.input_all

let json f = Yojson.Safe.from_string (fixture f)
let token = "test-bot-jwt"
let service = "haltsql_lab_pg"
let db = "om_src_7341"
let db_fqn = service ^ "." ^ db

let cursor f =
  match json f with
  | `Assoc kvs -> (
      match List.assoc_opt "paging" kvs with
      | Some (`Assoc p) -> (
          match List.assoc_opt "after" p with Some (`String s) -> s | _ -> assert false)
      | _ -> assert false)
  | _ -> assert false

let after1 = cursor "tables_page1.json"
let after2 = cursor "tables_page2.json"
let empty = {|{"data":[],"paging":{"total":0}}|}

(* Replays the live server: same routing, same 401 and 400 bodies. *)
let om_server ?(ignore_scope = false) () =
  Fake_http.start (fun req _body ->
      let q k = Uri.get_query_param (Cohttp.Request.uri req) k in
      if Fake_http.header req "authorization" <> Some ("Bearer " ^ token) then
        Fake_http.respond ~status:401 (fixture "unauthorized.json")
      else if Fake_http.path req <> "/api/v1/tables" then
        Fake_http.respond ~status:404 {|{"code":404,"message":"HTTP 404 Not Found"}|}
      else if ignore_scope then Fake_http.respond (fixture "tables_service.json")
      else
        let paged () =
          match q "after" with
          | None -> Fake_http.respond (fixture "tables_page1.json")
          | Some a when a = after1 -> Fake_http.respond (fixture "tables_page2.json")
          | Some a when a = after2 -> Fake_http.respond (fixture "tables_page3.json")
          | Some _ ->
              Fake_http.respond ~status:400
                {|{"code":400,"message":"Last unit does not have enough valid bits"}|}
        in
        match (q "database", q "databaseSchema", q "service") with
        | Some d, None, None when d = db_fqn -> paged ()
        | Some d, None, None when d = service ^ ".lake" ->
            Fake_http.respond (fixture "tables_lake.json")
        | None, Some s, None when s = db_fqn ^ ".app" -> paged ()
        | None, None, Some s when s = service ->
            Fake_http.respond (fixture "tables_service.json")
        | _ -> Fake_http.respond empty)

let client ?(tok = token) srv =
  match
    Fetch_client.create ~base_url:(Fake_http.url srv "") (Fetch_client.Bearer tok)
  with
  | Ok c -> c
  | Error e -> Alcotest.fail e

let filter ?service ?database ?(schemas = []) () = { Provider.service; database; schemas }
let run p = Lwt_main.run p
let get_ok what = function Ok x -> x | Error e -> Alcotest.failf "%s: %s" what e

let get_error what = function
  | Ok _ -> Alcotest.failf "%s: expected an error" what
  | Error e -> e

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let entries (m : Ct.Pii.t) =
  List.map
    (fun (e : Ct.Pii.entry) ->
      (Printf.sprintf "%s.%s.%s" e.schema e.table e.column, e.classifications))
    m

let expected =
  [
    ("app.audit_events.ip", [ "PersonalData.Personal" ]);
    ("app.customers.email", [ "PII.Sensitive" ]);
    ("app.customers.phone", [ "PersonalData.Personal" ]);
    ("app.customers.ssn", [ "PII.Sensitive"; "PersonalData.SpecialCategory" ]);
    ("app.payments.card_last4", [ "PII.NonSensitive" ]);
    ("app.payments.card_token", [ "PII.Sensitive" ]);
    ("app.users.email", [ "PII.Sensitive" ]);
    ("app.users.full_name", [ "Business.PersonalInformation" ]);
    ("app.users.password_hash", [ "PII.Sensitive" ]);
  ]

let manifest_t = Alcotest.(list (pair string (list string)))

let table_names (f : Provider.fetched) =
  List.map (fun (t : Provider.table) -> t.name) f.tables

(* ------------------------------------------------------------ tests *)

let test_pagination () =
  let srv = om_server () in
  let c = client srv in
  let f = get_ok "fetch" (run (Om.fetch c (filter ~service ~database:db ()))) in
  srv.stop ();
  Alcotest.(check int) "requests" 3 (List.length srv.requests);
  Alcotest.(check int) "client count" 3 (Fetch_client.request_count c);
  List.iteri
    (fun i ((req : Cohttp.Request.t), _) ->
      let q k = Uri.get_query_param (Cohttp.Request.uri req) k in
      Alcotest.(check (option string))
        "auth"
        (Some ("Bearer " ^ token))
        (Fake_http.header req "authorization");
      Alcotest.(check string) "method" "GET" (Cohttp.Code.string_of_method req.meth);
      Alcotest.(check (option string)) "database" (Some db_fqn) (q "database");
      Alcotest.(check (option string)) "fields" (Some "columns,tags") (q "fields");
      Alcotest.(check (option string)) "include" (Some "non-deleted") (q "include");
      Alcotest.(check (option string)) "limit" (Some "100") (q "limit");
      Alcotest.(check (option string))
        "after"
        (match i with 0 -> None | 1 -> Some after1 | _ -> Some after2)
        (q "after"))
    srv.requests;
  Alcotest.(check int) "tables" 9 (List.length f.tables);
  Alcotest.(check (list string))
    "order"
    [
      "audit_events";
      "currencies";
      "customers";
      "invoices";
      "order_items";
      "orders";
      "orgs";
      "payments";
      "users";
    ]
    (table_names f);
  Alcotest.(check (list string)) "warnings" [] f.warnings;
  let users = List.find (fun (t : Provider.table) -> t.name = "users") f.tables in
  Alcotest.(check string) "schema" "app" users.schema;
  Alcotest.(check (list (pair string (option string))))
    "users columns"
    [
      ("id", Some "bigint");
      ("tenant_id", Some "text");
      ("email", Some "text");
      ("full_name", Some "text");
      ("role", Some "text");
      ("password_hash", Some "text");
      ("created_at", Some "timestamp with time zone");
      ("last_login_at", Some "timestamp with time zone");
    ]
    (List.map (fun (c : Provider.column) -> (c.name, c.data_type)) users.columns);
  let r = get_ok "import" (Ct.Pii_import.import f.source f.document) in
  Alcotest.(check int) "scanned" 63 r.scanned_columns;
  Alcotest.check manifest_t "manifest" expected (entries r.manifest)

let test_run () =
  let srv = om_server () in
  let r =
    get_ok "run"
      (run
         (Catalog_fetch.run
            (Option.get (Catalog_fetch.find "openmetadata"))
            (client srv)
            (filter ~service ~database:db ())))
  in
  srv.stop ();
  Alcotest.check manifest_t "manifest" expected (entries r.manifest);
  Alcotest.(check int) "scanned" 63 r.scanned_columns;
  Alcotest.(check int) "requests" 3 r.requests;
  Alcotest.(check int) "tables" 9 (List.length r.tables);
  (* Untagged, Tier.Tier1, DataDomain.Finance and description-only columns: absent. *)
  List.iter
    (fun (table, column) ->
      Alcotest.(check bool)
        (table ^ "." ^ column)
        false
        (Ct.Pii.find r.manifest ~schema:"app" ~table ~column <> None))
    [
      ("orders", "note");
      ("invoices", "amount_cents");
      ("orgs", "name");
      ("customers", "country");
      ("customers", "tenant_id");
    ]

let test_page_size_env () =
  Unix.putenv "HALTSQL_OPENMETADATA_PAGE_SIZE" "4";
  Fun.protect
    ~finally:(fun () -> Unix.putenv "HALTSQL_OPENMETADATA_PAGE_SIZE" "")
    (fun () ->
      Alcotest.(check int) "env" 4 (Om.page_size ());
      let srv = om_server () in
      ignore
        (get_ok "fetch" (run (Om.fetch (client srv) (filter ~service ~database:db ()))));
      srv.stop ();
      List.iter
        (fun ((req : Cohttp.Request.t), _) ->
          Alcotest.(check (option string))
            "limit" (Some "4")
            (Uri.get_query_param (Cohttp.Request.uri req) "limit"))
        srv.requests);
  Unix.putenv "HALTSQL_OPENMETADATA_PAGE_SIZE" "5000";
  Alcotest.(check int) "out of range" 100 (Om.page_size ());
  Unix.putenv "HALTSQL_OPENMETADATA_PAGE_SIZE" ""

let test_service_scope () =
  let srv = om_server () in
  let f = get_ok "fetch" (run (Om.fetch (client srv) (filter ~service ()))) in
  srv.stop ();
  Alcotest.(check (option string))
    "service param" (Some service)
    (Uri.get_query_param (Cohttp.Request.uri (fst (List.hd srv.requests))) "service");
  Alcotest.(check int) "tables" 10 (List.length f.tables);
  let r = get_ok "import" (Ct.Pii_import.import f.source f.document) in
  (* The STRUCT child tag flags the top-level column of the API-only lake table. *)
  Alcotest.(check (option (list string)))
    "struct child" (Some [ "PII.Sensitive" ])
    (List.assoc_opt "events.page_views.context" (entries r.manifest));
  Alcotest.(check int) "entries" 10 (List.length r.manifest)

let test_database_excludes_other () =
  (* The lake database lives in the same service: a database filter must not see it. *)
  let srv = om_server () in
  let f =
    get_ok "fetch" (run (Om.fetch (client srv) (filter ~service ~database:db ())))
  in
  srv.stop ();
  Alcotest.(check bool) "no page_views" false (List.mem "page_views" (table_names f));
  let srv = om_server () in
  let f =
    get_ok "lake" (run (Om.fetch (client srv) (filter ~service ~database:"lake" ())))
  in
  srv.stop ();
  Alcotest.(check (list string)) "lake" [ "page_views" ] (table_names f);
  let pv = List.hd f.tables in
  Alcotest.(check (list (pair string (option string))))
    "struct column types"
    [
      ("id", Some "bigint");
      ("context", Some "struct<user_email:varchar,user_agent:varchar>");
      ("url", Some "text");
    ]
    (List.map (fun (c : Provider.column) -> (c.name, c.data_type)) pv.columns)

let test_scope_recheck () =
  (* A server that ignores the scope parameters returns the whole service: the provider
     keeps only the requested database. *)
  let srv = om_server ~ignore_scope:true () in
  let f =
    get_ok "fetch" (run (Om.fetch (client srv) (filter ~service ~database:db ())))
  in
  srv.stop ();
  Alcotest.(check int) "kept" 9 (List.length f.tables);
  Alcotest.(check bool)
    "warning" true
    (List.exists (fun w -> contains w "ignored 1 table(s) outside") f.warnings);
  (match f.document with
  | `Assoc [ ("data", `List l) ] -> Alcotest.(check int) "document" 9 (List.length l)
  | _ -> Alcotest.fail "document shape");
  let srv = om_server ~ignore_scope:true () in
  let f =
    get_ok "schemas"
      (run
         (Om.fetch (client srv)
            (filter ~service ~database:"lake" ~schemas:[ "events" ] ())))
  in
  srv.stop ();
  Alcotest.(check (list string)) "lake only" [ "page_views" ] (table_names f)

let test_schemas () =
  let srv = om_server () in
  let f =
    get_ok "app"
      (run (Om.fetch (client srv) (filter ~service ~database:db ~schemas:[ "app" ] ())))
  in
  srv.stop ();
  Alcotest.(check int) "tables" 9 (List.length f.tables);
  Alcotest.(check (option string))
    "databaseSchema param"
    (Some (db_fqn ^ ".app"))
    (Uri.get_query_param
       (Cohttp.Request.uri (fst (List.hd srv.requests)))
       "databaseSchema");
  (* Unknown names: OpenMetadata answers an empty list, which is an error here. *)
  let srv = om_server () in
  let e =
    get_error "nosuch"
      (run
         (Om.fetch (client srv) (filter ~service ~database:db ~schemas:[ "nosuch" ] ())))
  in
  srv.stop ();
  Alcotest.(check bool) "no tables msg" true (contains e "no tables found");
  let srv = om_server () in
  let e =
    get_error "unknown db"
      (run (Om.fetch (client srv) (filter ~service ~database:"nosuch" ())))
  in
  srv.stop ();
  Alcotest.(check bool) "names db" true (contains e "haltsql_lab_pg.nosuch")

let test_unauthorized () =
  let srv = om_server () in
  let e =
    get_error "401"
      (run
         (Om.fetch
            (client ~tok:"expired-jwt-value" srv)
            (filter ~service ~database:db ())))
  in
  srv.stop ();
  Alcotest.(check bool) "status" true (contains e "401");
  Alcotest.(check bool) "hint" true (contains e "bot JWT");
  Alcotest.(check bool) "no token" false (contains e "expired-jwt-value");
  Alcotest.(check bool) "no body" false (contains e "Not Authorized");
  Alcotest.(check int) "one request" 1 (List.length srv.requests)

let test_bad_cursor () =
  (* A server that hands back a cursor it then rejects: the 400 is an error. *)
  let srv =
    Fake_http.start (fun req _ ->
        match Uri.get_query_param (Cohttp.Request.uri req) "after" with
        | None ->
            Fake_http.respond
              {|{"data":[{"name":"t","databaseSchema":{"name":"app"},"columns":[]}],"paging":{"after":"bogus"}}|}
        | Some _ ->
            Fake_http.respond ~status:400
              {|{"code":400,"message":"Last unit does not have enough valid bits"}|})
  in
  let e = get_error "400" (run (Om.fetch (client srv) (filter ()))) in
  srv.stop ();
  Alcotest.(check bool) "400" true (contains e "400")

let test_database_needs_service () =
  let srv = om_server () in
  let e = get_error "db only" (run (Om.fetch (client srv) (filter ~database:db ()))) in
  srv.stop ();
  Alcotest.(check bool) "msg" true (contains e "--database needs --service");
  Alcotest.(check int) "no request" 0 (List.length srv.requests)

let test_quote_name () =
  Alcotest.(check string) "plain" "app" (Om.quote_name "app");
  Alcotest.(check string) "dotted" "\"my.db\"" (Om.quote_name "my.db");
  let srv = om_server () in
  ignore (run (Om.fetch (client srv) (filter ~service ~database:"my.db" ())));
  srv.stop ();
  Alcotest.(check (option string))
    "quoted fqn"
    (Some (service ^ ".\"my.db\""))
    (Uri.get_query_param (Cohttp.Request.uri (fst (List.hd srv.requests))) "database")

let test_api_base_url () =
  (* --url may already end in /api: requests still go to /api/v1/tables. *)
  let srv = om_server () in
  let c =
    match
      Fetch_client.create ~base_url:(Fake_http.url srv "/api") (Fetch_client.Bearer token)
    with
    | Ok c -> c
    | Error e -> Alcotest.fail e
  in
  let f = get_ok "fetch" (run (Om.fetch c (filter ~service ~database:db ()))) in
  srv.stop ();
  Alcotest.(check int) "tables" 9 (List.length f.tables);
  List.iter
    (fun ((req : Cohttp.Request.t), _) ->
      Alcotest.(check string) "path" "/api/v1/tables" (Fake_http.path req))
    srv.requests

let test_registry () =
  match Catalog_fetch.find "openmetadata" with
  | Some (module P) ->
      Alcotest.(check string) "token env" "OPENMETADATA_TOKEN" P.default_token_env
  | None -> Alcotest.fail "openmetadata not registered"

let () =
  let tc n f = Alcotest.test_case n `Quick f in
  Alcotest.run "openmetadata_fetch"
    [
      ( "replay",
        [
          tc "pagination" test_pagination;
          tc "Catalog_fetch.run" test_run;
          tc "page size env" test_page_size_env;
          tc "service scope" test_service_scope;
          tc "database excludes other" test_database_excludes_other;
          tc "scope re-check" test_scope_recheck;
          tc "schemas" test_schemas;
          tc "401" test_unauthorized;
          tc "bad cursor" test_bad_cursor;
          tc "database needs service" test_database_needs_service;
          tc "quote name" test_quote_name;
          tc "api base url" test_api_base_url;
          tc "registry" test_registry;
        ] );
    ]
