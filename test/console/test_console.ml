(* Scaffold tests: config validation, RBAC matrix, router, store, index, authentication,
   health and the /me, /access/roles, /integrations and /activity endpoints. *)

open Lwt.Syntax
open Helpers
module C = Haltsql_console

let invalid_config name doc =
  ( name,
    `Quick,
    fun () ->
      match C.Console_config.of_json doc with
      | _ -> Alcotest.failf "%s: expected Invalid" name
      | exception C.Console_config.Invalid _ -> () )

let config_tests =
  [
    invalid_config "no auth" (`Assoc [ ("listen", `String "127.0.0.1:0") ]);
    invalid_config "unknown key"
      (`Assoc [ ("auth", `Assoc [ ("dev", `Bool true) ]); ("listn", `String "x") ]);
    invalid_config "bad role"
      (`Assoc [ ("auth", `Assoc [ ("dev", `Assoc [ ("role", `String "root") ]) ]) ]);
    invalid_config "duplicate verifier"
      (`Assoc
         [
           ("auth", `Assoc [ ("dev", `Bool true) ]);
           ( "verifiers",
             `List
               [
                 `Assoc [ ("name", `String "a"); ("url", `String "http://x") ];
                 `Assoc [ ("name", `String "a"); ("url", `String "http://y") ];
               ] );
         ]);
    ( "defaults",
      `Quick,
      fun () ->
        let c =
          C.Console_config.of_json (`Assoc [ ("auth", `Assoc [ ("dev", `Bool true) ]) ])
        in
        Alcotest.(check string) "listen" "127.0.0.1:8090" c.listen;
        Alcotest.(check int) "retention" 168 c.audit.retention_hours;
        Alcotest.(check bool)
          "dev role" true
          (match c.auth.dev with Some d -> d.dev_role = C.Rbac.Dev | None -> false) );
    ( "placeholders",
      `Quick,
      fun () ->
        let env = function "TOKEN" -> Some "s3cret" | _ -> None in
        let doc =
          `Assoc
            [
              ("auth", `Assoc [ ("dev", `Bool true) ]);
              ( "verifiers",
                `List
                  [
                    `Assoc
                      [
                        ("name", `String "a");
                        ("url", `String "https://x/");
                        ("token", `String "${env:TOKEN}");
                      ];
                  ] );
            ]
        in
        let resolve = C.Console_config.env_resolver ~env () in
        let c = C.Console_config.of_json (C.Console_config.substitute ~resolve doc) in
        let v = List.hd c.verifiers in
        Alcotest.(check (option string)) "token" (Some "s3cret") v.v_token;
        Alcotest.(check string) "url trimmed" "https://x" v.v_url );
  ]

let example_config_test =
  ( "example config parses",
    `Quick,
    fun () ->
      match Haltsql.Docload.of_file "../../deploy/console/console.example.yaml" with
      | Error _ -> Alcotest.fail "example config is not valid YAML"
      | Ok doc ->
          let resolve = C.Console_config.env_resolver ~env:(fun _ -> Some "x") () in
          let c = C.Console_config.of_json (C.Console_config.substitute ~resolve doc) in
          Alcotest.(check int) "one verifier" 1 (List.length c.verifiers) )

let config_tests = config_tests @ [ example_config_test ]

let rbac_tests =
  let open C.Rbac in
  [
    ( "matrix",
      `Quick,
      fun () ->
        Alcotest.(check bool)
          "analyst raw sql with reason" true
          (grant Analyst See_raw_sql = With_reason);
        Alcotest.(check bool)
          "admin cannot see raw sql" true
          (grant Admin See_raw_sql = No);
        Alcotest.(check bool)
          "only owner approves" true
          (List.for_all (fun r -> grant r Approve_change = Yes = (r = Owner)) all_roles);
        Alcotest.(check bool) "audit no playground" true (grant Audit Use_playground = No);
        Alcotest.(check bool)
          "only admin restarts" true
          (List.for_all
             (fun r -> grant r Restart_verifiers = With_reason = (r = Admin))
             all_roles) );
  ]

let router_tests =
  [
    ( "params and methods",
      `Quick,
      fun () ->
        let h _ _ _ = C.Api.json `Null in
        let routes =
          [ C.Router.get "/api/v1/cases/:id" h; C.Router.post "/api/v1/cases" h ]
        in
        (match C.Router.lookup routes `GET "/api/v1/cases/CASE-1%2F2" with
        | C.Router.Found (_, ps) ->
            Alcotest.(check (list (pair string string))) "param" [ ("id", "CASE-1/2") ] ps
        | _ -> Alcotest.fail "expected a match");
        Alcotest.(check bool)
          "405" true
          (C.Router.lookup routes `DELETE "/api/v1/cases" = C.Router.Method_not_allowed);
        Alcotest.(check bool)
          "404" true
          (C.Router.lookup routes `GET "/api/v1/nope" = C.Router.No_route) );
  ]

let store_tests =
  [
    ( "put update counter persist",
      `Quick,
      fun () ->
        let d = temp_dir "store" in
        let s = C.Store.create d in
        Lwt_main.run
          (let* () = C.Store.put s "cases" "a" (`Int 1) in
           let* _ =
             C.Store.update s "cases" "a" (function
               | Some (`Int n) -> Some (`Int (n + 1))
               | _ -> None)
           in
           let* n1 = C.Store.next_counter s "case" ~start:1000 in
           let* n2 = C.Store.next_counter s "case" ~start:1000 in
           Alcotest.(check int) "first" 1000 n1;
           Alcotest.(check int) "second" 1001 n2;
           Lwt.return_unit);
        let s' = C.Store.create d in
        Alcotest.(check bool) "persisted" true (C.Store.get s' "cases" "a" = Some (`Int 2))
    );
  ]

let index_tests =
  [
    ( "add search expire",
      `Quick,
      fun () ->
        let idx = C.Index.create ~max_records:3 ~retention_seconds:100. () in
        let now = 1_000_000. in
        let add i ts allowed =
          let j =
            server_record ~request_id:(Printf.sprintf "r%d" i) ~ts ~allowed
              ~codes:(if allowed then [] else [ "E_TENANT_MISMATCH" ])
              ()
          in
          match C.Index.entry_of_json ~verifier:"v" ~location:"f" ~seq:i ~now j with
          | Some e -> C.Index.add idx e
          | None -> Alcotest.fail "entry"
        in
        add 1 (now -. 200.) true;
        add 2 (now -. 50.) false;
        add 3 (now -. 10.) true;
        add 4 (now -. 5.) false;
        Alcotest.(check int) "capped" 3 (C.Index.size idx);
        C.Index.expire idx ~now;
        Alcotest.(check int) "expired none left old" 3 (C.Index.size idx);
        let denied =
          C.Index.search idx
            { C.Index.no_filter with outcome = Some Haltsql_report.Record.Denied }
        in
        Alcotest.(check (list string))
          "newest first" [ "r4"; "r2" ]
          (List.map (fun e -> e.C.Index.request_id) denied);
        Alcotest.(check bool) "find" true (C.Index.find idx "r3" <> None);
        Alcotest.(check bool) "evicted" true (C.Index.find idx "r1" = None) );
  ]

let http_tests =
  [
    ( "health and me",
      `Quick,
      fun () ->
        with_console (config ~role:"analyst" ()) (fun r ->
            let* h = get r "/healthz" in
            check_status "healthz" 200 h;
            let* rd = get r "/readyz" in
            check_status "readyz" 200 rd;
            let* code, me = get r "/api/v1/me" in
            Alcotest.(check int) "me" 200 code;
            Alcotest.(check string)
              "role" "\"analyst\""
              (Yojson.Safe.to_string (member "role" me));
            Alcotest.(check string)
              "raw sql grant" "\"reason\""
              (Yojson.Safe.to_string (member "permissions.see_raw_sql" me));
            let* nf = get r "/api/v1/does-not-exist" in
            check_status "404" 404 nf;
            Lwt.return_unit) );
    ( "service token and unknown token",
      `Quick,
      fun () ->
        let cfg =
          C.Console_config.of_json
            (`Assoc
               [
                 ("listen", `String "127.0.0.1:0");
                 ("state_dir", `String (temp_dir "st"));
                 ( "auth",
                   `Assoc
                     [
                       ( "tokens",
                         `List
                           [
                             `Assoc
                               [
                                 ("name", `String "ci");
                                 ("sha256", `String (Haltsql.sha256_hex "tok"));
                                 ("role", `String "audit");
                               ];
                           ] );
                     ] );
               ])
        in
        with_console cfg (fun r ->
            let* anon = get r "/api/v1/me" in
            check_status "anonymous" 401 anon;
            let* bad = get ~token:"nope" r "/api/v1/me" in
            check_status "unknown token" 401 bad;
            let* code, me = get ~token:"tok" r "/api/v1/me" in
            Alcotest.(check int) "token" 200 code;
            Alcotest.(check string)
              "role" "\"audit\""
              (Yojson.Safe.to_string (member "role" me));
            Lwt.return_unit) );
    ( "proxy headers map groups to roles",
      `Quick,
      fun () ->
        let cfg =
          C.Console_config.of_json
            (`Assoc
               [
                 ("listen", `String "127.0.0.1:0");
                 ("state_dir", `String (temp_dir "st"));
                 ( "auth",
                   `Assoc
                     [
                       ( "proxy",
                         `Assoc
                           [
                             ("user_header", `String "X-Auth-Request-Email");
                             ("groups_header", `String "X-Auth-Request-Groups");
                             ("secret_header", `String "X-Proxy-Secret");
                             ("secret_sha256", `String (Haltsql.sha256_hex "proxy-secret"));
                           ] );
                       ( "roles",
                         `Assoc
                           [
                             ("owner", `List [ `String "policy-owners" ]);
                             ("dev", `List [ `String "eng" ]);
                           ] );
                     ] );
               ])
        in
        with_console cfg (fun r ->
            let* code, me =
              get
                ~headers:
                  [
                    ("x-auth-request-email", "lee@acme.test");
                    ("x-auth-request-groups", "eng, policy-owners");
                    ("x-proxy-secret", "proxy-secret");
                  ]
                r "/api/v1/me"
            in
            Alcotest.(check int) "proxy" 200 code;
            Alcotest.(check string)
              "highest role wins" "\"owner\""
              (Yojson.Safe.to_string (member "role" me));
            let* nogroup =
              get
                ~headers:
                  [
                    ("x-auth-request-email", "x@acme.test");
                    ("x-proxy-secret", "proxy-secret");
                  ]
                r "/api/v1/me"
            in
            check_status "no mapped group" 401 nogroup;
            Lwt.return_unit) );
    ( "roles, integrations, activity",
      `Quick,
      fun () ->
        with_console (config ()) (fun r ->
            let* roles = get r "/api/v1/access/roles" in
            check_status "roles" 200 roles;
            let* ints = get r "/api/v1/integrations" in
            check_status "integrations" 200 ints;
            let p =
              {
                C.Ctx.id = "a@b";
                name = "a";
                auth = "dev";
                groups = [];
                roles = [ C.Rbac.Admin ];
                role = C.Rbac.Admin;
              }
            in
            let* () =
              C.Activity.log r.ctx p ~reason:"because" ~action:"test.action" ~target:"x"
                ()
            in
            let* code, a = get r "/api/v1/activity?action=test" in
            Alcotest.(check int) "activity" 200 code;
            Alcotest.(check int)
              "one entry" 1
              (match member "entries" a with `List l -> List.length l | _ -> -1);
            Lwt.return_unit) );
  ]

let () =
  Alcotest.run "console"
    [
      ("config", config_tests);
      ("rbac", rbac_tests);
      ("router", router_tests);
      ("store", store_tests);
      ("index", index_tests);
      ("http", http_tests);
    ]
