(* DataHub provider against replayed live responses (see dune). The fixtures were
   captured from DataHub v1.8.0 seeded by test/catalog_live/datahub/seed.py: platform
   instance haltsql_lab, database dh_src_7719 (9 tables; 3 pages at count=4) and a decoy
   database dh_decoy_7719 (app.leads, email tagged PII) on the same instance. *)

open Haltsql_catalog_fetch
module Ct = Haltsql_catalog_tools
module Dh = Datahub_fetch

let fixture f =
  In_channel.with_open_bin (Filename.concat "fixtures" f) In_channel.input_all

let json f = Yojson.Safe.from_string (fixture f)
let token = "test-personal-access-token"
let instance = "haltsql_lab"
let db = "dh_src_7719"
let db_urn = "urn:li:container:69bc9c025457aa50c8b785da984140cb"
let schema_urn = "urn:li:container:679eb84cca04d86315cb2d5094ed2252"
let field k = function `Assoc kvs -> List.assoc_opt k kvs | _ -> None
let get path j = List.fold_left (fun acc k -> Option.bind acc (field k)) (Some j) path

let next f =
  match get [ "data"; "scrollAcrossEntities"; "nextScrollId" ] (json f) with
  | Some (`String s) -> s
  | _ -> assert false

let next1 = next "datasets_page1.json"
let next2 = next "datasets_page2.json"

(* The request's scrollAcrossEntities input. *)
let input body = Option.get (get [ "variables"; "input" ] (Yojson.Safe.from_string body))
let str_field k j = match field k j with Some (`String s) -> Some s | _ -> None

(* field name -> values of the single AND clause. *)
let criteria inp =
  match field "orFilters" inp with
  | Some (`List [ `Assoc [ ("and", `List cs) ] ]) ->
      List.map
        (fun c ->
          ( Option.get (str_field "field" c),
            match field "values" c with
            | Some (`List vs) ->
                List.filter_map (function `String s -> Some s | _ -> None) vs
            | _ -> [] ))
        cs
  | _ -> Alcotest.fail "orFilters shape"

let etype inp =
  match field "types" inp with
  | Some (`List [ `String t ]) -> t
  | _ -> Alcotest.fail "types"

(* Replays the live server: routing on the request's entity type and filters, the same
   401 and bad-cursor bodies. [ignore_scope] answers every listing with everything on
   the platform, as a server that ignores filters would. *)
let dh_server ?(ignore_scope = false) ?(gql_path = "/api/graphql") () =
  Fake_http.start (fun req body ->
      if Fake_http.header req "authorization" <> Some ("Bearer " ^ token) then
        Fake_http.respond ~status:401 (fixture "unauthorized.json")
      else if Fake_http.path req <> gql_path then
        Fake_http.respond ~status:404 {|{"status":404,"error":"Not Found"}|}
      else
        let inp = input body in
        let c = criteria inp in
        let crit k = List.assoc_opt k c in
        match etype inp with
        | "CONTAINER" when ignore_scope ->
            Fake_http.respond (fixture "containers_platform.json")
        | "CONTAINER" -> (
            match (crit "typeNames", crit "name", crit "container") with
            | Some [ "Database" ], Some [ d ], None when d = db ->
                Fake_http.respond (fixture "containers_database.json")
            | Some [ "Schema" ], (None | Some [ "app" ]), (None | Some [ _ ])
              when crit "container" = None || crit "container" = Some [ db_urn ] ->
                Fake_http.respond (fixture "containers_schema.json")
            | _ -> Fake_http.respond (fixture "containers_empty.json"))
        | "DATASET" when ignore_scope ->
            Fake_http.respond (fixture "datasets_platform.json")
        | "DATASET" -> (
            match crit "container" with
            | None -> Fake_http.respond (fixture "datasets_platform.json")
            | Some [ u ] when u = schema_urn -> (
                match str_field "scrollId" inp with
                | None -> Fake_http.respond (fixture "datasets_page1.json")
                | Some s when s = next1 ->
                    Fake_http.respond (fixture "datasets_page2.json")
                | Some s when s = next2 ->
                    Fake_http.respond (fixture "datasets_page3.json")
                | Some _ -> Fake_http.respond (fixture "bad_scroll.json"))
            | Some _ ->
                Fake_http.respond
                  {|{"data":{"scrollAcrossEntities":{"nextScrollId":null,"searchResults":[]}},"extensions":{}}|}
            )
        | _ -> Fake_http.respond ~status:400 {|{"error":"unexpected"}|})

let client ?(tok = token) ?(base = "") srv =
  match
    Fetch_client.create ~base_url:(Fake_http.url srv base) (Fetch_client.Bearer tok)
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
    ("app.audit_events.ip", [ "PersonalInformation" ]);
    ("app.customers.email", [ "PII" ]);
    ("app.customers.phone", [ "PII" ]);
    ("app.customers.ssn", [ "PII"; "Sensitive" ]);
    ("app.payments.card_last4", [ "PII" ]);
    ("app.payments.card_token", [ "PII"; "Sensitive" ]);
    ("app.users.email", [ "PII" ]);
    ("app.users.full_name", [ "PersonalInformation" ]);
    ("app.users.password_hash", [ "Sensitive" ]);
  ]

let manifest_t = Alcotest.(list (pair string (list string)))

let table_names (f : Provider.fetched) =
  List.map (fun (t : Provider.table) -> t.name) f.tables

let page_size_4 f =
  Unix.putenv "HALTSQL_DATAHUB_PAGE_SIZE" "4";
  Fun.protect ~finally:(fun () -> Unix.putenv "HALTSQL_DATAHUB_PAGE_SIZE" "") f

(* ------------------------------------------------------------ tests *)

let test_pagination () =
  page_size_4 @@ fun () ->
  let srv = dh_server () in
  let c = client srv in
  let f = get_ok "fetch" (run (Dh.fetch c (filter ~service:instance ~database:db ()))) in
  srv.stop ();
  (* database containers, schema containers, then 3 dataset pages *)
  Alcotest.(check int) "requests" 5 (List.length srv.requests);
  Alcotest.(check int) "client count" 5 (Fetch_client.request_count c);
  let inputs = List.map (fun (_, b) -> input b) srv.requests in
  List.iter
    (fun ((req : Cohttp.Request.t), _) ->
      Alcotest.(check (option string))
        "auth"
        (Some ("Bearer " ^ token))
        (Fake_http.header req "authorization");
      Alcotest.(check string) "method" "POST" (Cohttp.Code.string_of_method req.meth);
      Alcotest.(check string) "path" "/api/graphql" (Fake_http.path req))
    srv.requests;
  let platform = ("platform", [ "urn:li:dataPlatform:postgres" ]) in
  let inst =
    ( "platformInstance",
      [ "urn:li:dataPlatformInstance:(urn:li:dataPlatform:postgres,haltsql_lab)" ] )
  in
  let crit_t = Alcotest.(list (pair string (list string))) in
  (match inputs with
  | [ i1; i2; i3; i4; i5 ] ->
      Alcotest.(check string) "1 type" "CONTAINER" (etype i1);
      Alcotest.check crit_t "1 filters"
        [ platform; inst; ("typeNames", [ "Database" ]); ("name", [ db ]) ]
        (criteria i1);
      Alcotest.(check string) "2 type" "CONTAINER" (etype i2);
      Alcotest.check crit_t "2 filters"
        [ platform; inst; ("typeNames", [ "Schema" ]); ("container", [ db_urn ]) ]
        (criteria i2);
      List.iteri
        (fun k i ->
          Alcotest.(check string) "dataset type" "DATASET" (etype i);
          Alcotest.check crit_t "dataset filters"
            [ platform; inst; ("container", [ schema_urn ]) ]
            (criteria i);
          Alcotest.(check (option string))
            "scrollId"
            (match k with 0 -> None | 1 -> Some next1 | _ -> Some next2)
            (str_field "scrollId" i);
          Alcotest.(check bool) "count" true (field "count" i = Some (`Int 4)))
        [ i3; i4; i5 ]
  | _ -> Alcotest.fail "5 inputs");
  Alcotest.(check (list string))
    "order"
    [
      "customers";
      "audit_events";
      "currencies";
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
  let srv = dh_server () in
  let r =
    get_ok "run"
      (run
         (Catalog_fetch.run
            (Option.get (Catalog_fetch.find "datahub"))
            (client srv) (filter ~database:db ())))
  in
  srv.stop ();
  Alcotest.check manifest_t "manifest" expected (entries r.manifest);
  Alcotest.(check int) "scanned" 63 r.scanned_columns;
  (* the replayed dataset pages are the count=4 ones, whatever count is asked for *)
  Alcotest.(check int) "requests" 5 r.requests;
  Alcotest.(check int) "tables" 9 (List.length r.tables);
  (* Gold (column and dataset level), the Revenue term, a description mentioning email,
     untagged columns: absent. *)
  List.iter
    (fun (table, column) ->
      Alcotest.(check bool)
        (table ^ "." ^ column)
        false
        (Ct.Pii.find r.manifest ~schema:"app" ~table ~column <> None))
    [
      ("orders", "note");
      ("order_items", "description");
      ("invoices", "amount_cents");
      ("orgs", "name");
      ("customers", "name");
      ("customers", "country");
      ("customers", "tenant_id");
      ("leads", "email");
    ]

let test_page_size_env () =
  page_size_4 (fun () -> Alcotest.(check int) "env" 4 (Dh.page_size ()));
  Unix.putenv "HALTSQL_DATAHUB_PAGE_SIZE" "5000";
  Alcotest.(check int) "out of range" 100 (Dh.page_size ());
  Unix.putenv "HALTSQL_DATAHUB_PAGE_SIZE" "x";
  Alcotest.(check int) "not a number" 100 (Dh.page_size ());
  Unix.putenv "HALTSQL_DATAHUB_PAGE_SIZE" "";
  Alcotest.(check int) "default" 100 (Dh.page_size ())

let test_whole_platform () =
  (* No database: one dataset listing of the platform; both databases are merged, which
     is warned about. *)
  let srv = dh_server () in
  let f = get_ok "fetch" (run (Dh.fetch (client srv) (filter ()))) in
  srv.stop ();
  Alcotest.(check int) "one request" 1 (List.length srv.requests);
  Alcotest.(check int) "tables" 10 (List.length f.tables);
  Alcotest.(check bool)
    "merge warning" true
    (List.exists
       (fun w -> contains w "2 databases (dh_decoy_7719, dh_src_7719)")
       f.warnings);
  let r = get_ok "import" (Ct.Pii_import.import f.source f.document) in
  Alcotest.(check (option (list string)))
    "decoy" (Some [ "PII" ])
    (List.assoc_opt "app.leads.email" (entries r.manifest));
  Alcotest.(check int) "entries" 10 (List.length r.manifest)

let test_scope_recheck () =
  (* A server that ignores every filter: containers and datasets of the whole platform
     come back; only the requested database's are kept. *)
  let srv = dh_server ~ignore_scope:true () in
  let f =
    get_ok "fetch"
      (run (Dh.fetch (client srv) (filter ~service:instance ~database:db ())))
  in
  srv.stop ();
  Alcotest.(check int) "kept" 9 (List.length f.tables);
  Alcotest.(check bool) "no leads" false (List.mem "leads" (table_names f));
  Alcotest.(check bool)
    "warning" true
    (List.exists (fun w -> contains w "ignored 1 dataset(s) outside") f.warnings);
  (match get [ "data"; "datasets" ] f.document with
  | Some (`List l) -> Alcotest.(check int) "document" 9 (List.length l)
  | _ -> Alcotest.fail "document shape");
  let r = get_ok "import" (Ct.Pii_import.import f.source f.document) in
  Alcotest.check manifest_t "manifest" expected (entries r.manifest);
  (* The decoy database, through the same lying server: only app.leads. *)
  let srv = dh_server ~ignore_scope:true () in
  let f =
    get_ok "decoy"
      (run
         (Dh.fetch (client srv) (filter ~database:"dh_decoy_7719" ~schemas:[ "app" ] ())))
  in
  srv.stop ();
  Alcotest.(check (list string)) "decoy only" [ "leads" ] (table_names f);
  (* A platform instance nothing is in: every dataset is dropped, which is an error. *)
  let srv = dh_server ~ignore_scope:true () in
  let e =
    get_error "other instance" (run (Dh.fetch (client srv) (filter ~service:"other" ())))
  in
  srv.stop ();
  Alcotest.(check bool) "msg" true (contains e "no postgres datasets found")

let test_schemas () =
  let srv = dh_server () in
  let f =
    get_ok "app" (run (Dh.fetch (client srv) (filter ~database:db ~schemas:[ "app" ] ())))
  in
  srv.stop ();
  Alcotest.(check int) "tables" 9 (List.length f.tables);
  Alcotest.(check (option (list string)))
    "schema name filter" (Some [ "app" ])
    (List.assoc_opt "name" (criteria (input (snd (List.nth srv.requests 1)))));
  let srv = dh_server () in
  let e =
    get_error "nosuch"
      (run (Dh.fetch (client srv) (filter ~database:db ~schemas:[ "nosuch" ] ())))
  in
  srv.stop ();
  Alcotest.(check bool) "no schema msg" true (contains e "no postgres schema containers");
  Alcotest.(check bool) "names schema" true (contains e "nosuch");
  Alcotest.(check int) "no dataset request" 2 (List.length srv.requests)

let test_unknown_database () =
  let srv = dh_server () in
  let e =
    get_error "unknown db"
      (run (Dh.fetch (client srv) (filter ~service:instance ~database:"nosuch" ())))
  in
  srv.stop ();
  Alcotest.(check bool) "msg" true (contains e "no postgres database container named");
  Alcotest.(check bool) "names db" true (contains e "\"nosuch\"");
  Alcotest.(check bool) "names instance" true (contains e "haltsql_lab");
  Alcotest.(check int) "one request" 1 (List.length srv.requests)

let test_unauthorized () =
  let srv = dh_server () in
  let e =
    get_error "401"
      (run (Dh.fetch (client ~tok:"expired-token-value" srv) (filter ~database:db ())))
  in
  srv.stop ();
  Alcotest.(check bool) "status" true (contains e "401");
  Alcotest.(check bool) "hint" true (contains e "Personal Access Token");
  Alcotest.(check bool) "no token" false (contains e "expired-token-value");
  Alcotest.(check bool) "no body" false (contains e "Unauthorized");
  Alcotest.(check int) "one request" 1 (List.length srv.requests)

let test_bad_cursor () =
  (* A cursor the server then rejects: DataHub answers HTTP 200 with a GraphQL error. *)
  let srv =
    Fake_http.start (fun _ body ->
        match str_field "scrollId" (input body) with
        | None ->
            Fake_http.respond
              {|{"data":{"scrollAcrossEntities":{"nextScrollId":"bogus","searchResults":[]}}}|}
        | Some _ -> Fake_http.respond (fixture "bad_scroll.json"))
  in
  let e = get_error "bad scroll" (run (Dh.fetch (client srv) (filter ()))) in
  srv.stop ();
  Alcotest.(check bool) "graphql error" true (contains e "GraphQL error");
  Alcotest.(check bool)
    "message" true
    (contains e "Last unit does not have enough valid bits")

let test_repeated_cursor () =
  (* A server that hands back the same cursor forever: paginate stops it. *)
  let srv =
    Fake_http.start (fun _ _ ->
        Fake_http.respond
          {|{"data":{"scrollAcrossEntities":{"nextScrollId":"same","searchResults":[]}}}|})
  in
  let e = get_error "loop" (run (Dh.fetch (client srv) (filter ()))) in
  srv.stop ();
  Alcotest.(check bool) "names listing" true (contains e "datahub datasets");
  Alcotest.(check bool) "bounded" true (List.length srv.requests <= 3)

let test_no_data () =
  let srv = Fake_http.start (fun _ _ -> Fake_http.respond {|{"data":null}|}) in
  let e = get_error "no data" (run (Dh.fetch (client srv) (filter ()))) in
  srv.stop ();
  Alcotest.(check bool) "msg" true (contains e "no data.scrollAcrossEntities")

let test_base_urls () =
  (* The frontend's GraphQL root (/api/v2) and an /api root: requests go to .../graphql. *)
  List.iter
    (fun (base, want) ->
      let srv = dh_server ~gql_path:want () in
      let f = get_ok base (run (Dh.fetch (client ~base srv) (filter ~database:db ()))) in
      srv.stop ();
      Alcotest.(check int) (base ^ " tables") 9 (List.length f.tables);
      List.iter
        (fun ((req : Cohttp.Request.t), _) ->
          Alcotest.(check string) (base ^ " path") want (Fake_http.path req))
        srv.requests)
    [
      ("/api/v2", "/api/v2/graphql");
      ("/api/v2/", "/api/v2/graphql");
      ("/api", "/api/graphql");
      ("/gms", "/gms/api/graphql");
    ];
  (* GMS has no /api/v2/graphql: a wrong root is a 404 with a hint. *)
  let srv = dh_server ~gql_path:"/api/v2/graphql" () in
  let e = get_error "404" (run (Dh.fetch (client srv) (filter ~database:db ()))) in
  srv.stop ();
  Alcotest.(check bool) "404 hint" true (contains e "check --url")

let test_registry () =
  match Catalog_fetch.find "datahub" with
  | Some (module P) ->
      Alcotest.(check string) "token env" "DATAHUB_TOKEN" P.default_token_env
  | None -> Alcotest.fail "datahub not registered"

let () =
  let tc n f = Alcotest.test_case n `Quick f in
  Alcotest.run "datahub_fetch"
    [
      ( "replay",
        [
          tc "pagination" test_pagination;
          tc "Catalog_fetch.run" test_run;
          tc "page size env" test_page_size_env;
          tc "whole platform" test_whole_platform;
          tc "scope re-check" test_scope_recheck;
          tc "schemas" test_schemas;
          tc "unknown database" test_unknown_database;
          tc "401" test_unauthorized;
          tc "bad cursor" test_bad_cursor;
          tc "repeated cursor" test_repeated_cursor;
          tc "no data" test_no_data;
          tc "base urls" test_base_urls;
          tc "registry" test_registry;
        ] );
    ]
