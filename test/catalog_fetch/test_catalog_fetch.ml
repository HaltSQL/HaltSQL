(* Tests for haltsql.catalog_fetch: Fetch_client against an in-process fake server, and
   Catalog_fetch.run / catalog_snapshot with a locally registered fake provider. *)

open Haltsql
module Ct = Haltsql_catalog_tools
module Cf = Haltsql_catalog_fetch
module Fc = Cf.Fetch_client
module Pv = Cf.Provider

let token = "tok-S3CR3T-0123456789"

let contains s sub =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  go 0

let check_contains what s sub =
  if not (contains s sub) then Alcotest.failf "%s: %S does not contain %S" what s sub

let check_not_contains what s sub =
  if contains s sub then Alcotest.failf "%s: %S contains %S" what s sub

let get_ok what = function Ok x -> x | Error e -> Alcotest.failf "%s: %s" what e

let get_error what = function
  | Ok _ -> Alcotest.failf "%s: expected an error" what
  | Error e -> e

let client ?max_pages ?(auth = Fc.Bearer token) ?(prefix = "") srv =
  get_ok "create" (Fc.create ?max_pages ~base_url:(Fake_http.url srv prefix) auth)

let with_server handler f =
  let srv = Fake_http.start handler in
  Fun.protect ~finally:srv.stop (fun () -> Lwt_main.run (f srv))

let json_resp j = Fake_http.respond ~headers:[ ("content-type", "application/json") ] j
let query req k = Uri.get_query_param (Cohttp.Request.uri req) k

(* ------------------------------------------------------------ requests *)

let test_bearer_and_prefix () =
  with_server
    (fun _ _ -> json_resp {|{"ok": true}|})
    (fun srv ->
      let open Lwt.Syntax in
      let c = client ~prefix:"/gms/" srv in
      let* r = Fc.get_json c ~query:[ ("q", "a b&c") ] "/api/v2/datasets" in
      Alcotest.(check string)
        "body" {|{"ok":true}|}
        (Yojson.Safe.to_string (get_ok "get" r));
      let req, _ = List.hd srv.requests in
      Alcotest.(check string) "path" "/gms/api/v2/datasets" (Fake_http.path req);
      Alcotest.(check (option string)) "query" (Some "a b&c") (query req "q");
      Alcotest.(check (option string))
        "auth"
        (Some ("Bearer " ^ token))
        (Fake_http.header req "authorization");
      Alcotest.(check (option string))
        "accept" (Some "application/json")
        (Fake_http.header req "accept");
      let* r = Fc.post_json c "/graphql" (`Assoc [ ("query", `String "{ x }") ]) in
      ignore (get_ok "post" r);
      let req, body = List.nth srv.requests 1 in
      Alcotest.(check string) "post path" "/gms/graphql" (Fake_http.path req);
      Alcotest.(check string) "method" "POST" (Cohttp.Code.string_of_method req.meth);
      Alcotest.(check (option string))
        "content-type" (Some "application/json")
        (Fake_http.header req "content-type");
      Alcotest.(check string) "post body" {|{"query":"{ x }"}|} body;
      (* The path is used as given: percent-encoding is preserved. *)
      let* r = Fc.get_json c "/api/tables/name/svc.db.%22A%2Fb%22" in
      ignore (get_ok "encoded" r);
      let req, _ = List.nth srv.requests 2 in
      Alcotest.(check string)
        "encoded path" "/gms/api/tables/name/svc.db.%22A%2Fb%22"
        (Cohttp.Request.resource req);
      Alcotest.(check int) "request count" 3 (Fc.request_count c);
      Alcotest.(check string)
        "base url" (Fake_http.url srv "/gms/")
        (Uri.to_string (Fc.base_url c));
      (* No prefix, no auth: no Authorization header at all. *)
      let c = client ~auth:Fc.No_auth srv in
      let* r = Fc.get_json c "/x" in
      ignore (get_ok "no auth" r);
      let req, _ = List.nth srv.requests 3 in
      Alcotest.(check string) "plain path" "/x" (Fake_http.path req);
      Alcotest.(check (option string))
        "no auth header" None
        (Fake_http.header req "authorization");
      Lwt.return_unit)

let test_bad_paths () =
  with_server
    (fun _ _ -> json_resp "{}")
    (fun srv ->
      let open Lwt.Syntax in
      let c = client srv in
      let* r1 = Fc.get_json c "api/x" in
      let* r2 = Fc.get_json c "//evil.example.com/x" in
      let* r3 = Fc.get_json c "/x#frag" in
      check_contains "relative" (get_error "relative" r1) "must start with '/'";
      check_contains "authority" (get_error "authority" r2) "must not start with '//'";
      check_contains "fragment" (get_error "fragment" r3) "'#'";
      Alcotest.(check int) "nothing sent" 0 (List.length srv.requests);
      Lwt.return_unit)

(* ------------------------------------------------------------ errors *)

let test_http_error_hygiene () =
  with_server
    (fun req _ ->
      let leak =
        Printf.sprintf {|{"error": "bad token %s", "marker": "BODY-MARKER"}|} token
      in
      match Fake_http.path req with
      | "/denied" -> Fake_http.respond ~status:401 leak
      | "/html" -> Fake_http.respond ~status:200 ("<html>" ^ leak ^ "</html>")
      | "/empty" -> Fake_http.respond ~status:200 ""
      | _ -> Fake_http.respond ~status:500 leak)
    (fun srv ->
      let open Lwt.Syntax in
      let c = client srv in
      let* r = Fc.get_json c ~query:[ ("cursor", "CURSOR-X") ] "/denied" in
      let e = get_error "401" r in
      Alcotest.(check string) "401 message" "GET /denied: HTTP 401" e;
      let* r = Fc.post_json c "/boom?x=QUERY-MARKER" `Null in
      let e5 = get_error "500" r in
      Alcotest.(check string) "500 message" "POST /boom: HTTP 500" e5;
      let* r = Fc.get_json c "/html" in
      let ej = get_error "html" r in
      check_contains "not json" ej "GET /html: the response is not valid JSON";
      List.iter
        (fun e ->
          check_not_contains "no token" e token;
          check_not_contains "no body" e "BODY-MARKER";
          check_not_contains "no query" e "QUERY-MARKER";
          check_not_contains "no cursor" e "CURSOR-X";
          check_not_contains "no html" e "<html>")
        [ e; e5; ej ];
      let* r = Fc.get_json c "/empty" in
      Alcotest.(check bool) "empty body is null" true (get_ok "empty" r = `Null);
      Lwt.return_unit)

let test_transport_error () =
  (* Nothing listens on port 1. *)
  let c = get_ok "create" (Fc.create ~base_url:"http://127.0.0.1:1" (Fc.Bearer token)) in
  let e = get_error "transport" (Lwt_main.run (Fc.get_json c "/x")) in
  check_contains "names request" e "GET /x: request to 127.0.0.1:1";
  check_not_contains "no token" e token;
  Alcotest.(check int) "counted" 1 (Fc.request_count c)

let test_endpoint_checks () =
  let err base auth = get_error base (Fc.create ~base_url:base auth) in
  check_contains "http non-loopback"
    (err "http://catalog.example.com" Fc.No_auth)
    "http is only allowed for loopback hosts";
  check_contains "credentials"
    (err "https://user:pw@catalog.example.com" Fc.No_auth)
    "must not contain credentials";
  check_contains "query" (err "https://catalog.example.com/?a=1" Fc.No_auth) "query";
  check_contains "not absolute" (err "catalog.example.com" Fc.No_auth) "absolute";
  check_contains "nip.io trick"
    (err "http://127.0.0.1.nip.io/" Fc.No_auth)
    "malformed host";
  let e = err "https://catalog.example.com" (Fc.Bearer "abc def\r\nX: y") in
  check_contains "bad token" e "token";
  check_not_contains "token not echoed" e "abc def";
  ignore (err "https://catalog.example.com" (Fc.Bearer ""));
  ignore
    (get_ok "https" (Fc.create ~base_url:"https://catalog.example.com/api" Fc.No_auth));
  ignore (get_ok "loopback" (Fc.create ~base_url:"http://localhost:8080" Fc.No_auth));
  ignore
    (get_error "timeout"
       (Fc.create ~timeout:0. ~base_url:"https://catalog.example.com" Fc.No_auth));
  ignore
    (get_error "max_pages"
       (Fc.create ~max_pages:0 ~base_url:"https://catalog.example.com" Fc.No_auth))

(* ------------------------------------------------------------ pagination *)

(* Pages keyed by cursor: [None] -> items 1,2 / cursor c1, ... *)
let page_server pages =
 fun req _ ->
  let key = Option.value (query req "cursor") ~default:"" in
  match List.assoc_opt key pages with
  | Some (items, next) ->
      json_resp
        (Yojson.Safe.to_string
           (`Assoc
              [
                ("items", `List (List.map (fun i -> `Int i) items));
                ("next", match next with Some c -> `String c | None -> `Null);
              ]))
  | None -> Fake_http.respond ~status:404 "{}"

let fetch_page c cursor =
  let open Lwt.Syntax in
  let query = match cursor with Some cur -> [ ("cursor", cur) ] | None -> [] in
  let+ r = Fc.get_json c ~query "/items" in
  Result.map
    (fun j ->
      let open Yojson.Safe.Util in
      ( to_list (member "items" j),
        match member "next" j with `String s -> Some s | _ -> None ))
    r

let ints l = List.map Yojson.Safe.Util.to_int l

let test_paginate () =
  with_server
    (page_server
       [
         ("", ([ 1; 2 ], Some "c1"));
         ("c1", ([ 3 ], Some "c2"));
         ("c2", ([], Some "c3"));
         ("c3", ([ 4 ], None));
       ])
    (fun srv ->
      let open Lwt.Syntax in
      let c = client srv in
      let* r = Fc.paginate c ~what:"items" (fetch_page c) in
      Alcotest.(check (list int)) "concatenated" [ 1; 2; 3; 4 ] (ints (get_ok "pages" r));
      Alcotest.(check int) "requests" 4 (Fc.request_count c);
      Alcotest.(check (list (option string)))
        "cursors sent"
        [ None; Some "c1"; Some "c2"; Some "c3" ]
        (List.map (fun (req, _) -> query req "cursor") srv.requests);
      Lwt.return_unit)

let test_paginate_repeated_cursor () =
  with_server
    (page_server [ ("", ([ 1 ], Some "c1")); ("c1", ([ 2 ], Some "c1")) ])
    (fun _srv ->
      let open Lwt.Syntax in
      let c = client _srv in
      let* r = Fc.paginate c ~what:"datasets" (fetch_page c) in
      let e = get_error "repeat" r in
      check_contains "names what" e "datasets";
      check_contains "repeat" e "same page cursor";
      Alcotest.(check int) "stopped" 2 (Fc.request_count c);
      Lwt.return_unit)

let test_paginate_max_pages () =
  with_server
    (fun req _ ->
      let n = int_of_string (Option.value (query req "cursor") ~default:"0") in
      json_resp (Printf.sprintf {|{"items": [%d], "next": "%d"}|} n (n + 1)))
    (fun srv ->
      let open Lwt.Syntax in
      let c = client ~max_pages:3 srv in
      let* r = Fc.paginate c ~what:"tables" (fetch_page c) in
      let e = get_error "max pages" r in
      check_contains "max pages" e "tables: more than 3 pages";
      Alcotest.(check int) "only max_pages requests" 3 (Fc.request_count c);
      (* Exactly max_pages pages is fine. *)
      let c = client ~max_pages:2 srv in
      let* r =
        Fc.paginate c ~what:"tables" (fun cur ->
            Lwt.return
              (Ok ([ `Int 0 ], match cur with None -> Some "x" | Some _ -> None)))
      in
      Alcotest.(check int) "two pages ok" 2 (List.length (get_ok "2 pages" r));
      (* A page error stops the loop and is returned as is. *)
      let* r = Fc.paginate c ~what:"t" (fun _ -> Lwt.return (Error "boom")) in
      Alcotest.(check string) "page error" "boom" (get_error "page error" r);
      Lwt.return_unit)

(* ------------------------------------------------------------ provider *)

let dbt_manifest =
  {|{"nodes": {"model.x.customers": {"resource_type": "model", "schema": "app",
      "name": "customers", "columns": {
        "id": {"name": "id", "tags": []},
        "email": {"name": "email", "tags": ["pii"]},
        "tenant_id": {"name": "tenant_id"}}}}}|}

(* A fake provider, registered only here (not in Catalog_fetch.providers). *)
module Fake : Pv.S = struct
  let name = "fake"
  let description = "test provider"
  let default_token_env = "FAKE_TOKEN"

  let fetch client (filter : Pv.filter) =
    let open Lwt.Syntax in
    let* r = Fc.get_json client "/manifest" in
    Lwt.return
      (Result.map
         (fun document ->
           {
             Pv.source = Ct.Pii_import.Dbt;
             document;
             tables =
               [
                 {
                   Pv.schema = "app";
                   name = "customers";
                   columns =
                     [
                       { Pv.name = "id"; data_type = Some "bigint" };
                       { Pv.name = "tenant_id"; data_type = None };
                       { Pv.name = "email"; data_type = Some "text" };
                       { Pv.name = "id"; data_type = None };
                       { Pv.name = ""; data_type = None };
                     ];
                 };
                 { Pv.schema = "app"; name = "empty"; columns = [] };
                 {
                   Pv.schema = "app";
                   name = "customers";
                   columns = [ { Pv.name = "name"; data_type = None } ];
                 };
                 {
                   Pv.schema = "billing";
                   name = "Invoices";
                   columns = [ { Pv.name = "Total"; data_type = None } ];
                 };
               ];
             warnings =
               [ "provider warning"; "schemas: " ^ String.concat "," filter.schemas ];
           })
         r)
end

let test_run () =
  with_server
    (fun req _ ->
      match Fake_http.path req with
      | "/manifest" -> json_resp dbt_manifest
      | "/nometa" -> json_resp {|{"unrelated": true}|}
      | _ -> Fake_http.respond ~status:404 "{}")
    (fun srv ->
      let open Lwt.Syntax in
      let c = client srv in
      let filter = { Pv.service = None; database = Some "saas"; schemas = [ "app" ] } in
      let* r = Cf.Catalog_fetch.run (module Fake) c filter in
      let r = get_ok "run" r in
      Alcotest.(check (list (pair string (list string))))
        "manifest"
        [ ("app.customers.email", [ "pii" ]) ]
        (List.map
           (fun (e : Ct.Pii.entry) ->
             (String.concat "." [ e.schema; e.table; e.column ], e.classifications))
           r.manifest);
      Alcotest.(check int) "scanned" 3 r.scanned_columns;
      Alcotest.(check int) "requests" 1 r.requests;
      Alcotest.(check int) "tables" 4 (List.length r.tables);
      Alcotest.(check (list string))
        "provider warnings first"
        [ "provider warning"; "schemas: app" ]
        (List.filteri (fun i _ -> i < 2) r.warnings);
      (* Custom terms flow through to the importer. *)
      let* r2 =
        Cf.Catalog_fetch.run
          ~config:{ Ct.Pii.Matcher.tags = [ "gdpr" ]; terms = [] }
          (module Fake)
          c filter
      in
      Alcotest.(check int) "custom terms" 0 (List.length (get_ok "run2" r2).manifest);
      (* Provider failures and documents without column metadata are errors. *)
      let module Failing : Pv.S = struct
        include Fake

        let fetch c _ =
          let+ r = Fc.get_json c "/missing" in
          Result.map (fun _ -> assert false) r
      end
      in
      let* e = Cf.Catalog_fetch.run (module Failing) c filter in
      Alcotest.(check string) "fetch error" "GET /missing: HTTP 404" (get_error "404" e);
      let module No_meta : Pv.S = struct
        include Fake

        let fetch c f =
          let+ r = Fake.fetch c f in
          Result.map (fun (x : Pv.fetched) -> { x with document = `Assoc [] }) r
      end
      in
      let* e = Cf.Catalog_fetch.run (module No_meta) c filter in
      ignore (get_error "no metadata" e);
      let module Raising : Pv.S = struct
        include Fake

        let fetch _ _ =
          Yojson.Safe.Util.to_string (`Assoc [ ("secret", `String token) ]) |> ignore;
          assert false
      end
      in
      let* e = Cf.Catalog_fetch.run (module Raising) c filter in
      let e = get_error "raise" e in
      check_contains "internal error" e "fake: internal provider error";
      check_not_contains "no json value" e token;
      Alcotest.(check bool) "not registered" true (Cf.Catalog_fetch.find "fake" = None);
      Lwt.return_unit)

let test_catalog_snapshot () =
  let tables =
    Lwt_main.run
      (let srv = Fake_http.start (fun _ _ -> json_resp dbt_manifest) in
       let open Lwt.Syntax in
       let+ r =
         Fake.fetch (client srv) { Pv.service = None; database = None; schemas = [] }
       in
       srv.stop ();
       (get_ok "fetch" r).tables)
  in
  let snap = Cf.Catalog_fetch.catalog_snapshot ~database:(Some "saas") tables in
  Alcotest.(check bool) "non-authoritative" false snap.authoritative;
  Alcotest.(check (list string)) "schemas" [ "app"; "billing" ] snap.schemas;
  Alcotest.(check (list (pair (pair string string) (list (pair string (option string))))))
    "tables: merged, de-duplicated, untyped, sorted"
    [
      ( ("app", "customers"),
        [ ("id", None); ("tenant_id", None); ("email", None); ("name", None) ] );
      (("billing", "Invoices"), [ ("Total", None) ]);
    ]
    (List.map
       (fun (t : Catalog.table) ->
         ( (t.schema, t.name),
           List.map (fun (c : Catalog.column) -> (c.col_name, c.col_type)) t.columns ))
       snap.catalog.tables);
  Alcotest.(check (option string))
    "relkind" (Some "table")
    (Option.map Ct.Snapshot.relkind_to_string
       (Ct.Snapshot.relkind snap ~schema:"billing" ~name:"Invoices"));
  let j = Ct.Snapshot.to_json snap in
  let s = Yojson.Safe.to_string j in
  check_contains "metadata" s
    {|"metadata":{"source":"haltsql schema fetch","authoritative":false,"database":"saas"|};
  (* The policy catalog loader refuses it ... *)
  (match Catalog_load.of_json j with
  | Ok _ -> Alcotest.fail "non-authoritative snapshot loaded as a catalog"
  | Error es ->
      let m = String.concat "; " (List.map Load_error.to_string es) in
      check_contains "refused" m "not authoritative";
      check_contains "hint" m "haltsql schema pull");
  (match Ct.Snapshot.of_json j with
  | Ok _ -> Alcotest.fail "Snapshot.of_json accepted it by default"
  | Error _ -> ());
  (* ... and the drafter can read it back unchanged. *)
  let back = get_ok "of_json" (Ct.Snapshot.of_json ~allow_non_authoritative:true j) in
  Alcotest.(check bool) "still non-authoritative" false back.authoritative;
  Alcotest.(check string) "roundtrip" s (Yojson.Safe.to_string (Ct.Snapshot.to_json back));
  (* An empty provider view gives an empty (but loadable) snapshot. *)
  let empty = Cf.Catalog_fetch.catalog_snapshot ~database:None [] in
  Alcotest.(check int) "empty" 0 (List.length empty.catalog.tables)

let () =
  let tc name f = Alcotest.test_case name `Quick f in
  Alcotest.run "catalog_fetch"
    [
      ( "fetch_client",
        [
          tc "bearer, prefix, post" test_bearer_and_prefix;
          tc "bad paths" test_bad_paths;
          tc "error hygiene" test_http_error_hygiene;
          tc "transport error" test_transport_error;
          tc "endpoint checks" test_endpoint_checks;
        ] );
      ( "paginate",
        [
          tc "concatenates" test_paginate;
          tc "repeated cursor" test_paginate_repeated_cursor;
          tc "max pages" test_paginate_max_pages;
        ] );
      ("catalog_fetch", [ tc "run" test_run; tc "catalog_snapshot" test_catalog_snapshot ]);
    ]
