(* RBAC tests: the full permission matrix, the union of several roles' grants,
   Ctx.require, the typed per-feature state registry, and /access/roles visibility. *)

open Helpers
module C = Haltsql_console
open C.Rbac

let grant_t =
  Alcotest.testable (fun f g -> Format.pp_print_string f (grant_to_string g)) ( = )

(* The documented table (docs/console/api.md#roles), columns dev, analyst, owner, audit,
   admin. Keep the two in sync. *)
let documented =
  [
    ("use_playground", [ "yes"; "yes"; "yes"; "no"; "yes" ]);
    ("search_queries", [ "yes"; "yes"; "yes"; "yes"; "yes" ]);
    ("see_raw_sql", [ "no"; "reason"; "reason"; "reason"; "no" ]);
    ("pause_caller", [ "no"; "reason"; "no"; "no"; "reason" ]);
    ("propose_changes", [ "yes"; "yes"; "yes"; "no"; "yes" ]);
    ("approve_change", [ "no"; "no"; "yes"; "no"; "no" ]);
    ("approve_exception", [ "no"; "no"; "yes"; "no"; "no" ]);
    ("build_evidence", [ "no"; "yes"; "yes"; "yes"; "no" ]);
    ("restart_verifiers", [ "no"; "no"; "no"; "no"; "reason" ]);
    ("manage_access", [ "no"; "no"; "no"; "no"; "yes" ]);
    ("write_cases", [ "no"; "yes"; "yes"; "no"; "yes" ]);
    ("view_activity", [ "no"; "yes"; "yes"; "yes"; "yes" ]);
  ]

let matrix_tests =
  [
    ( "full matrix matches docs",
      `Quick,
      fun () ->
        Alcotest.(check (list string))
          "permission ids in order" (List.map fst documented)
          (List.map permission_id all_permissions);
        Alcotest.(check (list string))
          "role columns"
          [ "dev"; "analyst"; "owner"; "audit"; "admin" ]
          (List.map role_to_string all_roles);
        List.iter
          (fun p ->
            Alcotest.(check (list string))
              (permission_id p)
              (List.assoc (permission_id p) documented)
              (List.map (fun r -> grant_to_string (grant r p)) all_roles))
          all_permissions );
    ( "view_activity name",
      `Quick,
      fun () ->
        Alcotest.(check string)
          "name" "See the activity log"
          (permission_name View_activity) );
    ( "primary role is display precedence",
      `Quick,
      fun () ->
        Alcotest.(check string)
          "owner+admin" "admin"
          (role_to_string (primary [ Owner; Admin ]));
        Alcotest.(check string)
          "dev+audit+analyst" "audit"
          (role_to_string (primary [ Dev; Audit; Analyst ])) );
  ]

let union_tests =
  [
    ( "owner+admin",
      `Quick,
      fun () ->
        let rs = [ Owner; Admin ] in
        Alcotest.check grant_t "approve_change" Yes (grant_union rs Approve_change);
        Alcotest.check grant_t "restart_verifiers" With_reason
          (grant_union rs Restart_verifiers);
        Alcotest.check grant_t "manage_access" Yes (grant_union rs Manage_access);
        Alcotest.check grant_t "see_raw_sql" With_reason (grant_union rs See_raw_sql) );
    ( "analyst+audit",
      `Quick,
      fun () ->
        let rs = [ Analyst; Audit ] in
        Alcotest.check grant_t "pause_caller" With_reason (grant_union rs Pause_caller);
        Alcotest.check grant_t "write_cases" Yes (grant_union rs Write_cases);
        Alcotest.check grant_t "use_playground" Yes (grant_union rs Use_playground);
        Alcotest.check grant_t "restart_verifiers" No (grant_union rs Restart_verifiers)
    );
    ( "yes beats reason beats no",
      `Quick,
      fun () ->
        Alcotest.check grant_t "reason over no" With_reason
          (grant_union [ Dev; Owner ] See_raw_sql);
        Alcotest.check grant_t "yes over reason" Yes
          (grant_union [ Analyst; Admin ] Use_playground);
        Alcotest.check grant_t "empty" No (grant_union [] Search_queries);
        Alcotest.(check string)
          "permissions_json_union" "\"yes\""
          (Yojson.Safe.to_string
             (member "approve_change" (permissions_json_union [ Admin; Owner ]))) );
  ]

let principal roles =
  {
    C.Ctx.id = "p@acme.test";
    name = "p";
    auth = "dev";
    groups = [];
    roles;
    role = primary roles;
  }

let request ?reason () =
  let headers =
    match reason with
    | Some r -> Cohttp.Header.of_list [ ("x-haltsql-reason", r) ]
    | None -> Cohttp.Header.init ()
  in
  Cohttp.Request.make ~headers (Uri.of_string "http://localhost/x")

let error_code f =
  match f () with _ -> "ok" | exception C.Api.Error (_, code, _) -> code

let require_tests =
  [
    ( "multiple roles",
      `Quick,
      fun () ->
        let p = principal [ Analyst; Audit ] in
        Alcotest.(check (option string))
          "write_cases yes from analyst" None
          (C.Ctx.require p (request ()) Write_cases);
        Alcotest.(check string)
          "pause_caller needs a reason" "REASON_REQUIRED"
          (error_code (fun () -> C.Ctx.require p (request ()) Pause_caller));
        Alcotest.(check (option string))
          "pause_caller with header" (Some "CASE-1")
          (C.Ctx.require p (request ~reason:"CASE-1" ()) Pause_caller);
        Alcotest.(check string)
          "restart forbidden" "FORBIDDEN"
          (error_code (fun () -> C.Ctx.require p (request ()) Restart_verifiers));
        let oa = principal [ Owner; Admin ] in
        Alcotest.(check (option string))
          "owner+admin approves" None
          (C.Ctx.require oa (request ()) Approve_change);
        Alcotest.(check string)
          "owner+admin restart needs a reason" "REASON_REQUIRED"
          (error_code (fun () -> C.Ctx.require oa (request ()) Restart_verifiers));
        Alcotest.(check (option string))
          "owner+admin restarts with a reason" (Some "INC-7")
          (C.Ctx.require oa (request ~reason:"INC-7" ()) Restart_verifiers);
        Alcotest.(check string)
          "dev cannot view activity" "FORBIDDEN"
          (error_code (fun () ->
               C.Ctx.require (principal [ Dev ]) (request ()) View_activity)) );
  ]

let make_ctx ?(role = "admin") ?(extra = []) () =
  let cfg = config ~role ~extra () in
  let store = C.Store.create cfg.state_dir in
  C.Ctx.create ~config:cfg ~store ~index:(C.Index.create ())

let registry_tests =
  [
    ( "typed keys",
      `Quick,
      fun () ->
        let ctx = make_ctx () in
        let ki : int C.Ctx.Key.t = C.Ctx.Key.create "same" in
        let ks : string list C.Ctx.Key.t = C.Ctx.Key.create "same" in
        Alcotest.(check (option int)) "get before set" None (C.Ctx.get ctx ki);
        C.Ctx.set ctx ki 42;
        Alcotest.(check (option (list string))) "other key unset" None (C.Ctx.get ctx ks);
        C.Ctx.set ctx ks [ "a"; "b" ];
        Alcotest.(check (option int)) "int kept" (Some 42) (C.Ctx.get ctx ki);
        Alcotest.(check (option (list string)))
          "list kept"
          (Some [ "a"; "b" ])
          (C.Ctx.get ctx ks);
        C.Ctx.set ctx ki 43;
        Alcotest.(check (option int)) "replaced" (Some 43) (C.Ctx.get ctx ki);
        let ctx2 = make_ctx () in
        Alcotest.(check (option int)) "per ctx" None (C.Ctx.get ctx2 ki) );
  ]

let roles_body ctx roles =
  let req = { C.Router.http = request (); body = Cohttp_lwt.Body.empty; params = [] } in
  Lwt_main.run
    (let open Lwt.Syntax in
     let* _resp, body = C.Access.roles ctx (principal roles) req in
     let* s = Cohttp_lwt.Body.to_string body in
     Lwt.return (Yojson.Safe.from_string s))

let has_mapping = function `Assoc l -> List.mem_assoc "mapping" l | _ -> false

let access_tests =
  [
    ( "mapping only for manage_access",
      `Quick,
      fun () ->
        let ctx =
          make_ctx
            ~extra:
              [
                ( "auth",
                  `Assoc
                    [
                      ("dev", `Assoc [ ("role", `String "admin") ]);
                      ("roles", `Assoc [ ("admin", `List [ `String "okta:admins" ]) ]);
                    ] );
              ]
            ()
        in
        let admin = roles_body ctx [ Admin ] in
        Alcotest.(check bool) "admin sees mapping" true (has_mapping admin);
        Alcotest.(check string)
          "mapping content" "[\"okta:admins\"]"
          (Yojson.Safe.to_string (member "mapping.admin" admin));
        List.iter
          (fun rs ->
            let j = roles_body ctx rs in
            let name = String.concat "+" (List.map role_to_string rs) in
            Alcotest.(check bool) (name ^ " no mapping") false (has_mapping j);
            Alcotest.(check bool)
              (name ^ " sees matrix") true
              (match member "permissions" j with `List (_ :: _) -> true | _ -> false);
            Alcotest.(check bool)
              (name ^ " sees safeguards") true
              (match member "safeguards" j with `List (_ :: _) -> true | _ -> false))
          [ [ Dev ]; [ Analyst ]; [ Owner ]; [ Audit ]; [ Analyst; Owner; Audit ] ];
        Alcotest.(check bool)
          "owner+admin sees mapping" true
          (has_mapping (roles_body ctx [ Owner; Admin ])) );
  ]

let () =
  Alcotest.run "console-rbac"
    [
      ("matrix", matrix_tests);
      ("union", union_tests);
      ("require", require_tests);
      ("registry", registry_tests);
      ("access", access_tests);
    ]
