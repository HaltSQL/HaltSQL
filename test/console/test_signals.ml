(* Overview, signals (detectors, ids, auto-resolve, workflow), cases, caller pause and
   notifications (console/04-signals). *)

open Lwt.Syntax
open Helpers
module C = Haltsql_console

let dev_token = "dev-token-0123456789"
let analyst_token = "analyst-token-0123456789"
let admin_token = "admin-token-0123456789"

(* Service tokens for the admin, dev and analyst roles. Dev mode cannot be combined with
   tokens, so requests without an explicit token use the admin token (the principal
   [token:tester], standing in for the former dev user). *)
let cfg ?(extra = []) () =
  let tok name t role =
    `Assoc
      [
        ("name", `String name);
        ("sha256", `String (Haltsql.sha256_hex t));
        ("role", `String role);
      ]
  in
  config
    ~extra:
      (( "auth",
         `Assoc
           [
             ( "tokens",
               `List
                 [
                   tok "tester" admin_token "admin";
                   tok "dev" dev_token "dev";
                   tok "analyst" analyst_token "analyst";
                 ] );
           ] )
      :: extra)
    ()

let get ?(token = admin_token) ?reason ?headers r path =
  Helpers.get ~token ?reason ?headers r path

let post ?(token = admin_token) ?reason ?headers r path json =
  Helpers.post ~token ?reason ?headers r path json

let patch ?(token = admin_token) ?reason ?headers r path json =
  Helpers.patch ~token ?reason ?headers r path json

let run f = with_console ~background:false (cfg ()) f
let now () = Unix.gettimeofday ()
let lst = function `List l -> l | _ -> []
let str = function `String s -> s | j -> Yojson.Safe.to_string j
let int = function `Int i -> i | _ -> -1

let contains ~sub s =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  go 0

let check_contains msg ~sub s =
  if not (contains ~sub s) then Alcotest.failf "%s: %S does not contain %S" msg s sub

let signals r = C.Signals.all r.ctx

let of_kind r kind =
  List.filter
    (fun (l : C.Signals.live) -> C.Detectors.kind_to_string l.d.kind = kind)
    (signals r)

let sev (l : C.Signals.live) = C.Detectors.severity_to_string l.d.severity

let one_of_kind r kind =
  match of_kind r kind with
  | [ l ] -> l
  | l -> Alcotest.failf "expected one %s signal, got %d" kind (List.length l)

let err_code j = str (member "error.code" j)

(* ---- overview ---- *)

let overview_tests =
  [
    ( "totals series p99 posture",
      `Quick,
      fun () ->
        run (fun r ->
            let t = now () in
            let recs =
              List.init 10 (fun i ->
                  server_record
                    ~ts:(t -. 60. -. float_of_int (i * 60))
                    ~elapsed_us:((i + 1) * 100)
                    ())
              @ [
                  server_record ~ts:(t -. 30.) ~allowed:false ~codes:[ "E_TABLE_DENIED" ]
                    ~elapsed_us:5000 ();
                  server_record ~ts:(t -. 40.) ~allowed:false
                    ~codes:[ "E_TENANT_MISMATCH" ] ();
                  server_record ~ts:(t -. 50.) ~allowed:false
                    ~codes:[ "E_EXTERNAL_POLICY" ] ();
                  server_record ~ts:(t -. 70.) ~shadow:true ~codes:[ "E_COLUMN_DENIED" ]
                    ();
                  server_record ~ts:(t -. 80.) ~shadow:true ~codes:[ "E_COLUMN_DENIED" ]
                    ();
                  (* outside the 1h range *)
                  server_record ~ts:(t -. 7200.) ();
                ]
            in
            load_records r recs;
            let* code, o = get r "/api/v1/overview?range=1h" in
            Alcotest.(check int) "200" 200 code;
            Alcotest.(check int) "bucket" 300 (int (member "range.bucket_seconds" o));
            Alcotest.(check int) "checked" 15 (int (member "totals.checked" o));
            Alcotest.(check int) "denied" 3 (int (member "totals.denied" o));
            Alcotest.(check int) "by opa" 1 (int (member "totals.denied_by_opa" o));
            Alcotest.(check int) "shadow" 2 (int (member "totals.shadow_denied" o));
            Alcotest.(check (float 1e-9))
              "p99" 5.0
              (match member "totals.p99_ms" o with `Float f -> f | _ -> -1.);
            let series = lst (member "series" o) in
            Alcotest.(check bool)
              "12-13 buckets" true
              (List.length series >= 12 && List.length series <= 13);
            let sum k = List.fold_left (fun a b -> a + int (member k b)) 0 series in
            Alcotest.(check int) "series allowed" 10 (sum "allowed");
            Alcotest.(check int) "series denied" 3 (sum "denied");
            Alcotest.(check int) "series shadow" 2 (sum "shadow_denied");
            Alcotest.(check int)
              "reporting from records" 1
              (int (member "verifiers_reporting" o));
            let posture = lst (member "posture" o) in
            Alcotest.(check (list string))
              "posture ids"
              [
                "bundle_in_sync";
                "audit_chains";
                "pii_exposure";
                "in_process_agents";
                "restart_pending";
              ]
              (List.map (fun p -> str (member "id" p)) posture);
            Alcotest.(check (list string))
              "posture states without sources"
              [ "unknown"; "unknown"; "unknown"; "ok"; "unknown" ]
              (List.map (fun p -> str (member "state" p)) posture);
            Alcotest.(check int) "no signals" 0 (int (member "signals.open" o));
            let* _, o7 = get r "/api/v1/overview?range=7d" in
            Alcotest.(check int)
              "7d bucket" 21600
              (int (member "range.bucket_seconds" o7));
            Alcotest.(check int) "7d checked" 16 (int (member "totals.checked" o7));
            let* _, o24 = get r "/api/v1/overview" in
            Alcotest.(check int)
              "24h bucket" 3600
              (int (member "range.bucket_seconds" o24));
            let* code, _ = get r "/api/v1/overview?range=2h" in
            Alcotest.(check int) "bad range" 400 code;
            Lwt.return_unit) );
    ( "posture from fleet, chains, catalog and agents",
      `Quick,
      fun () ->
        let c =
          cfg
            ~extra:
              [
                ( "agents",
                  `List
                    [
                      `Assoc
                        [ ("name", `String "billing"); ("via", `String "in_process") ];
                    ] );
              ]
            ()
        in
        with_console ~background:false c (fun r ->
            C.Fleet.Testing.set_snapshot r.ctx
            @@ Some
                 (`Assoc
                    [
                      ( "verifiers",
                        `List
                          [
                            `Assoc
                              [
                                ("name", `String "haltsql-1"); ("state", `String "ready");
                              ];
                            `Assoc
                              [
                                ("name", `String "haltsql-2");
                                ("state", `String "restart_pending");
                                ("restart_pending", `Bool true);
                              ];
                            `Assoc
                              [
                                ("name", `String "haltsql-3");
                                ("state", `String "unreachable");
                              ];
                          ] );
                      ( "bundles",
                        `List
                          [
                            `Assoc
                              [
                                ("source", `String "prod");
                                ("version", `String "1.4.0");
                                ("verifiers", `Int 3);
                                ("in_sync", `Bool true);
                              ];
                          ] );
                    ]);
            C.Chain.Testing.set_status r.ctx
            @@ `Assoc
                 [
                   ("checked_at", `String "2026-11-07T14:00:00.000Z");
                   ( "chains",
                     `List
                       [
                         `Assoc
                           [
                             ("verifier", `String "haltsql-1"); ("state", `String "intact");
                           ];
                         `Assoc
                           [
                             ("verifier", `String "haltsql-2"); ("state", `String "broken");
                           ];
                       ] );
                 ];
            C.Data.Testing.set_columns_doc r.ctx
            @@ Some (`Assoc [ ("totals", `Assoc [ ("needs_review", `Int 2) ]) ]);
            let* _, o = get r "/api/v1/overview" in
            Alcotest.(check int)
              "reporting from fleet" 2
              (int (member "verifiers_reporting" o));
            Alcotest.(check (list string))
              "states"
              [ "ok"; "error"; "warning"; "warning"; "warning" ]
              (List.map (fun p -> str (member "state" p)) (lst (member "posture" o)));
            Lwt.return_unit) );
  ]

(* ---- detectors ---- *)

let tenant_denials ?(caller = "token:support-bot") ?(n = 10) ?sql t =
  List.init n (fun i ->
      server_record ~caller ~policy:"support"
        ~ts:(t -. 300. +. float_of_int (i * 20))
        ~allowed:false ~codes:[ "E_TENANT_MISMATCH" ]
        ?sql:(Option.map (fun f -> f i) sql)
        ())

let support_policy =
  {|apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: support }
dialect: postgres
search_path: [app]
statements: { allow: [select] }
tenancy:
  mode: literal
  keys: { tenant: "${ctx.tenant_id}" }
tables:
  tickets: { columns: [id, tenant_id, subject], tenant_column: tenant_id }
|}

let detector_tests =
  [
    ( "cross_tenant threshold",
      `Quick,
      fun () ->
        run (fun r ->
            let t = now () in
            load_records r (tenant_denials ~n:9 t);
            ignore (C.Signals.run_once ~now:t r.ctx);
            Alcotest.(check int)
              "below threshold" 0
              (List.length (of_kind r "cross_tenant"));
            load_records r
              [
                server_record ~caller:"token:support-bot" ~policy:"support" ~ts:(t -. 5.)
                  ~allowed:false ~codes:[ "E_TENANT_MISMATCH" ] ();
              ];
            let created = C.Signals.run_once ~now:t r.ctx in
            Alcotest.(check int) "created" 1 (List.length created);
            let l = one_of_kind r "cross_tenant" in
            Alcotest.(check string) "severity" "high" (sev l);
            check_contains "body" ~sub:"10 queries in" l.d.body;
            check_contains "body"
              ~sub:"All were denied at the tenancy check; none reached the database."
              l.d.body;
            Alcotest.(check string)
              "title" "token:support-bot is filtering on other tenants" l.d.title;
            check_contains "id" ~sub:"sig_cross_tenant_token-support-bot-" l.id;
            let* _, s = get r "/api/v1/signals" in
            let j = List.hd (lst (member "signals" s)) in
            Alcotest.(check string) "link" "investigation" (str (member "link.kind" j));
            Alcotest.(check string) "link target" l.id (str (member "link.target" j));
            Alcotest.(check int) "facts records" 10 (int (member "facts.records" j));
            Alcotest.(check bool)
              "no distinct values" true
              (member "facts.distinct_values" j = `Null);
            Alcotest.(check int)
              "codes" 10
              (int (member "facts.codes.E_TENANT_MISMATCH" j));
            Lwt.return_unit) );
    ( "cross_tenant distinct values by re-verification",
      `Quick,
      fun () ->
        let c =
          cfg
            ~extra:
              [
                ( "agents",
                  `List
                    [
                      `Assoc
                        [
                          ("name", `String "support-bot");
                          ("callers", `List [ `String "token:support-bot" ]);
                        ];
                    ] );
              ]
            ()
        in
        with_console ~background:false c (fun r ->
            (match Haltsql.Policy_load.of_string Haltsql.Docload.Yaml support_policy with
            | Ok p -> C.Policy_set.set r.ctx @@ [ ("support", p) ]
            | Error _ -> Alcotest.fail "policy");
            let t = now () in
            let others = [| "globex"; "initech"; "globex"; "umbrella" |] in
            load_records r
              (List.init 3 (fun i ->
                   server_record ~caller:"token:support-bot" ~policy:"support"
                     ~ts:(t -. 3000. +. float_of_int i)
                     ~sql:"SELECT id FROM tickets WHERE tenant_id = 'acme'" ())
              @ tenant_denials t ~sql:(fun i ->
                  Printf.sprintf "SELECT id, subject FROM tickets WHERE tenant_id = '%s'"
                    others.(i mod 4)));
            ignore (C.Signals.run_once ~now:t r.ctx);
            let l = one_of_kind r "cross_tenant" in
            check_contains "body" ~sub:"compared tenant_id to 3 values other than acme."
              l.d.body;
            Alcotest.(check string)
              "title" "support-bot is filtering on other tenants" l.d.title;
            check_contains "id" ~sub:"sig_cross_tenant_support-bot_" l.id;
            Alcotest.(check bool)
              "distinct" true
              (member "distinct_values" l.d.facts = `Int 3);
            (* Investigation: shapes normalized from SQL, stopped at tenancy. *)
            let* code, inv = get r ("/api/v1/signals/" ^ l.id) in
            Alcotest.(check int) "detail" 200 code;
            let shapes = lst (member "shapes" inv) in
            Alcotest.(check int) "one shape" 1 (List.length shapes);
            let sh = List.hd shapes in
            Alcotest.(check string)
              "shape" "SELECT id, subject FROM tickets WHERE tenant_id = ?"
              (str (member "example_shape" sh));
            Alcotest.(check string) "stage" "tenancy" (str (member "stopped_at" sh));
            Alcotest.(check int) "count" 10 (int (member "count" sh));
            Alcotest.(check int)
              "request ids" 10
              (List.length (lst (member "request_ids" inv)));
            Alcotest.(check int)
              "timeline bucket" 60
              (int (member "timeline.bucket_seconds" inv));
            let tl = lst (member "timeline.series" inv) in
            Alcotest.(check int)
              "timeline denied" 10
              (List.fold_left (fun a b -> a + int (member "denied" b)) 0 tl);
            Alcotest.(check string)
              "caller agent" "support-bot"
              (str (member "caller.agent" inv));
            Alcotest.(check string)
              "caller policy" "support"
              (str (member "caller.policy" inv));
            Alcotest.(check bool)
              "usual per minute" true
              (match member "caller.usual_per_minute" inv with
              | `Float f -> f > 0.
              | _ -> false);
            let* code, _ = get r "/api/v1/signals/sig_nope" in
            Alcotest.(check int) "unknown" 404 code;
            Lwt.return_unit) );
    ( "deny_spike",
      `Quick,
      fun () ->
        run (fun r ->
            let t = now () in
            let baseline =
              List.init 200 (fun i ->
                  server_record ~caller:"token:etl"
                    ~ts:(t -. 1200. -. float_of_int (i * 400))
                    ~allowed:(i <> 0)
                    ~codes:(if i = 0 then [ "E_COLUMN_DENIED" ] else [])
                    ())
            in
            let window =
              List.init 60 (fun i ->
                  server_record ~caller:"token:etl"
                    ~ts:(t -. 600. +. float_of_int (i * 10))
                    ~allowed:(i >= 40)
                    ~codes:(if i < 40 then [ "E_COLUMN_DENIED" ] else [])
                    ())
            in
            (* A steady caller with the same deny rate in both periods. *)
            let steady =
              List.init 60 (fun i ->
                  server_record ~caller:"token:steady"
                    ~ts:(t -. 600. +. float_of_int (i * 10))
                    ~allowed:(i mod 2 = 0)
                    ~codes:(if i mod 2 = 0 then [] else [ "E_LIMIT_REQUIRED" ])
                    ())
              @ List.init 100 (fun i ->
                  server_record ~caller:"token:steady"
                    ~ts:(t -. 2000. -. float_of_int (i * 600))
                    ~allowed:(i mod 2 = 0)
                    ~codes:(if i mod 2 = 0 then [] else [ "E_LIMIT_REQUIRED" ])
                    ())
            in
            load_records r (baseline @ window @ steady);
            ignore (C.Signals.run_once ~now:t r.ctx);
            let l = one_of_kind r "deny_spike" in
            Alcotest.(check (option string)) "caller" (Some "token:etl") l.d.caller;
            Alcotest.(check string) "severity" "medium" (sev l);
            check_contains "body"
              ~sub:"40 of 60 queries in the last 15 minutes were denied (67%)" l.d.body;
            check_contains "body" ~sub:"compared with 0.5% over the previous 24 hours"
              l.d.body;
            check_contains "body" ~sub:"Most common code: E_COLUMN_DENIED (40)." l.d.body;
            Alcotest.(check string) "link" "agent" l.d.link_kind;
            Lwt.return_unit) );
    ( "new_caller",
      `Quick,
      fun () ->
        let c =
          cfg
            ~extra:
              [
                ( "agents",
                  `List
                    [
                      `Assoc
                        [
                          ("name", `String "known");
                          ("callers", `List [ `String "token:known" ]);
                        ];
                    ] );
              ]
            ()
        in
        with_console ~background:false c (fun r ->
            let t = now () in
            load_records r
              [
                server_record ~caller:"token:known" ~ts:(t -. 100.) ();
                server_record ~caller:"token:stranger" ~ts:(t -. 50.) ();
              ];
            ignore (C.Signals.run_once ~now:t r.ctx);
            Alcotest.(check int)
              "no history: nothing is new" 0
              (List.length (of_kind r "new_caller"));
            load_records r
              [
                server_record ~request_id:"old-1" ~caller:"token:old" ~ts:(t -. 90000.) ();
                server_record ~request_id:"old-2" ~caller:"token:unknown-but-old"
                  ~ts:(t -. 89000.) ();
                server_record ~caller:"token:unknown-but-old" ~ts:(t -. 10.) ();
              ];
            ignore (C.Signals.run_once ~now:t r.ctx);
            let l = one_of_kind r "new_caller" in
            Alcotest.(check (option string)) "caller" (Some "token:stranger") l.d.caller;
            Alcotest.(check string) "low" "low" (sev l);
            check_contains "body" ~sub:"not listed under agents" l.d.body;
            Lwt.return_unit) );
    ( "shadow_ready",
      `Quick,
      fun () ->
        run (fun r ->
            let t = now () in
            load_records r
              (List.init 3 (fun i ->
                   server_record ~policy:"analytics-v13"
                     ~ts:(t -. float_of_int (i * 100))
                     ~shadow:true ~codes:[ "E_COLUMN_DENIED" ]
                     ~fingerprint:(if i = 0 then "aaaa" else "bbbb")
                     ()));
            ignore (C.Signals.run_once ~now:t r.ctx);
            let l = one_of_kind r "shadow_ready" in
            Alcotest.(check string)
              "title" "analytics-v13: 3 shadow denials to review" l.d.title;
            Alcotest.(check string) "rollout link" "rollout" l.d.link_kind;
            Alcotest.(check string) "target" "analytics-v13" l.d.link_target;
            check_contains "body" ~sub:"(2 query shapes, 1 caller)" l.d.body;
            Lwt.return_unit) );
    ( "fleet-derived and chain_broken",
      `Quick,
      fun () ->
        run (fun r ->
            let t = now () in
            let fleet errors =
              `Assoc
                [
                  ( "verifiers",
                    `List
                      [
                        `Assoc
                          [
                            ("name", `String "haltsql-1");
                            ("state", `String "buffering");
                            ( "unhealthy_sinks",
                              `List
                                [
                                  `Assoc
                                    [
                                      ("name", `String "kafka"); ("type", `String "kafka");
                                    ];
                                ] );
                          ];
                        `Assoc
                          [
                            ("name", `String "haltsql-2");
                            ("state", `String "ready");
                            ("restart_pending", `Bool true);
                          ];
                        `Assoc
                          [ ("name", `String "haltsql-3"); ("state", `String "ready") ];
                      ] );
                  ( "bundles",
                    `List
                      [
                        `Assoc
                          [
                            ("source", `String "prod");
                            ("version", `String "1.4.0");
                            ("verifiers", `Int 2);
                            ("in_sync", `Bool false);
                          ];
                        `Assoc
                          [
                            ("source", `String "prod");
                            ("version", `String "1.3.2");
                            ("verifiers", `Int 1);
                            ("in_sync", `Bool false);
                          ];
                      ] );
                  ( "opa",
                    `Assoc [ ("decisions", `Assoc [ ("error_denied", `Int errors) ]) ] );
                ]
            in
            C.Fleet.Testing.set_snapshot r.ctx @@ Some (fleet 5);
            C.Chain.Testing.set_status r.ctx
            @@ `Assoc
                 [
                   ( "chains",
                     `List
                       [
                         `Assoc
                           [
                             ("verifier", `String "haltsql-2");
                             ("state", `String "broken");
                             ("records", `Int 812);
                             ("first_break", `Assoc [ ("seq", `Int 412) ]);
                           ];
                         `Assoc
                           [
                             ("verifier", `String "haltsql-1"); ("state", `String "intact");
                           ];
                       ] );
                 ];
            ignore (C.Signals.run_once ~now:t r.ctx);
            let sb = one_of_kind r "sink_buffering" in
            Alcotest.(check (option string))
              "sink verifier" (Some "haltsql-1") sb.d.verifier;
            check_contains "sink body" ~sub:"to kafka" sb.d.body;
            let rp = one_of_kind r "restart_pending" in
            Alcotest.(check (option string)) "restart" (Some "haltsql-2") rp.d.verifier;
            let bd = one_of_kind r "bundle_drift" in
            check_contains "drift" ~sub:"1.4.0 (2 verifiers), 1.3.2 (1 verifier)"
              bd.d.body;
            let cb = one_of_kind r "chain_broken" in
            Alcotest.(check string) "chain high" "high" (sev cb);
            check_contains "chain body" ~sub:"broken at seq 412" cb.d.body;
            check_contains "chain body" ~sub:"812 records were checked." cb.d.body;
            Alcotest.(check int)
              "no opa yet (first sample)" 0
              (List.length (of_kind r "opa_errors"));
            C.Fleet.Testing.set_snapshot r.ctx @@ Some (fleet 9);
            ignore (C.Signals.run_once ~now:(t +. 30.) r.ctx);
            let op = one_of_kind r "opa_errors" in
            check_contains "opa body" ~sub:"Verifiers counted 4 errors calling OPA"
              op.d.body;
            (* Overview counts open signals by severity. *)
            let* _, o = get r "/api/v1/overview" in
            Alcotest.(check int) "open" 5 (int (member "signals.open" o));
            Alcotest.(check int) "high" 1 (int (member "signals.high" o));
            Alcotest.(check int) "medium" 4 (int (member "signals.medium" o));
            Lwt.return_unit) );
    ( "opa_errors from records",
      `Quick,
      fun () ->
        run (fun r ->
            let t = now () in
            load_records r
              (List.init 10 (fun i ->
                   server_record
                     ~ts:(t -. float_of_int (i * 30))
                     ~allowed:false ~codes:[ "E_EXTERNAL_POLICY" ] ()));
            ignore (C.Signals.run_once ~now:t r.ctx);
            let l = one_of_kind r "opa_errors" in
            check_contains "body"
              ~sub:
                "10 queries in the last 15 minutes were denied by the external policy \
                 engine"
              l.d.body;
            Lwt.return_unit) );
  ]

(* ---- ids, auto-resolve, workflow ---- *)

let lifecycle_tests =
  [
    ( "idempotent ids and auto-resolve",
      `Quick,
      fun () ->
        run (fun r ->
            let t = now () in
            load_records r (tenant_denials t);
            ignore (C.Signals.run_once ~now:t r.ctx);
            let id1 = (one_of_kind r "cross_tenant").id in
            let created = C.Signals.run_once ~now:(t +. 30.) r.ctx in
            Alcotest.(check int) "nothing new" 0 (List.length created);
            let l = one_of_kind r "cross_tenant" in
            Alcotest.(check string) "same id" id1 l.id;
            (* Condition clears once the window passes; resolved after 30 more minutes. *)
            ignore (C.Signals.run_once ~now:(t +. 900.) r.ctx);
            Alcotest.(check bool) "still open" false l.auto_resolved;
            ignore (C.Signals.run_once ~now:(t +. 1200.) r.ctx);
            Alcotest.(check bool) "not yet" false l.auto_resolved;
            ignore (C.Signals.run_once ~now:(t +. 30. +. 1800.) r.ctx);
            Alcotest.(check bool) "resolved" true l.auto_resolved;
            let* _, s = get r "/api/v1/signals" in
            Alcotest.(check int)
              "open list empty" 0
              (List.length (lst (member "signals" s)));
            let* _, s = get r "/api/v1/signals?status=all" in
            let j = List.hd (lst (member "signals" s)) in
            Alcotest.(check string) "resolved status" "resolved" (str (member "status" j));
            let* code, _ = get r "/api/v1/signals?status=bogus" in
            Alcotest.(check int) "bad status" 400 code;
            Lwt.return_unit) );
    ( "human status survives clearing",
      `Quick,
      fun () ->
        run (fun r ->
            let t = now () in
            load_records r (tenant_denials t);
            ignore (C.Signals.run_once ~now:t r.ctx);
            let l = one_of_kind r "cross_tenant" in
            let* code, j =
              post ~token:analyst_token r ("/api/v1/signals/" ^ l.id)
                (`Assoc
                   [
                     ("status", `String "investigating");
                     ("assignee", `String "dana@acme.test");
                   ])
            in
            Alcotest.(check int) "updated" 200 code;
            Alcotest.(check string) "status" "investigating" (str (member "status" j));
            Alcotest.(check string)
              "assignee" "dana@acme.test"
              (str (member "assignee" j));
            ignore (C.Signals.run_once ~now:(t +. 4000.) r.ctx);
            Alcotest.(check bool) "auto flag" true l.auto_resolved;
            let* _, s = get r "/api/v1/signals" in
            let j = List.hd (lst (member "signals" s)) in
            Alcotest.(check string)
              "human status kept" "investigating"
              (str (member "status" j));
            (* Persisted in the store, with kind and subject for re-attachment. *)
            let st = C.Store.create r.ctx.config.state_dir in
            let w = Option.get (C.Store.get st "signals" l.id) in
            Alcotest.(check string)
              "stored status" "investigating"
              (str (member "status" w));
            Alcotest.(check string) "stored kind" "cross_tenant" (str (member "kind" w));
            Alcotest.(check string)
              "stored by" "token:analyst"
              (str (member "updated_by" w));
            let acts = List.rev (C.Activity.recent r.ctx) in
            Alcotest.(check bool)
              "logged" true
              (List.exists (fun a -> member "action" a = `String "signal.update") acts);
            Lwt.return_unit) );
    ( "workflow permissions and validation",
      `Quick,
      fun () ->
        run (fun r ->
            let t = now () in
            load_records r (tenant_denials t);
            ignore (C.Signals.run_once ~now:t r.ctx);
            let l = one_of_kind r "cross_tenant" in
            let path = "/api/v1/signals/" ^ l.id in
            let* c, j =
              post ~token:dev_token r path (`Assoc [ ("status", `String "contained") ])
            in
            Alcotest.(check int) "dev 403" 403 c;
            Alcotest.(check string) "forbidden" "FORBIDDEN" (err_code j);
            let* c, _ = post r path (`Assoc [ ("status", `String "nope") ]) in
            Alcotest.(check int) "bad status" 400 c;
            let* c, _ = post r path (`Assoc [ ("status", `String "acknowledged") ]) in
            Alcotest.(check int) "ack only low" 400 c;
            let* c, _ = post r path (`Assoc []) in
            Alcotest.(check int) "empty" 400 c;
            let* c, _ =
              post r "/api/v1/signals/sig_nope" (`Assoc [ ("status", `String "open") ])
            in
            Alcotest.(check int) "unknown" 404 c;
            let* c, j = post r path (`Assoc [ ("assignee", `Null) ]) in
            Alcotest.(check int) "clear assignee" 200 c;
            Alcotest.(check bool) "null" true (member "assignee" j = `Null);
            let* c, _ = get ~token:dev_token r "/api/v1/signals" in
            Alcotest.(check int) "dev reads" 200 c;
            Lwt.return_unit) );
  ]

(* ---- cases ---- *)

let case_tests =
  [
    ( "lifecycle",
      `Quick,
      fun () ->
        run (fun r ->
            let* c, j =
              post r "/api/v1/cases" (`Assoc [ ("title", `String "Look at etl") ])
            in
            Alcotest.(check int) "201" 201 c;
            Alcotest.(check string) "id" "CASE-1000" (str (member "id" j));
            Alcotest.(check string) "open" "open" (str (member "status" j));
            Alcotest.(check string)
              "created_by" "token:tester"
              (str (member "created_by" j));
            let* _, j2 =
              post r "/api/v1/cases"
                (`Assoc
                   [
                     ("title", `String "Second");
                     ("assignee", `String "token:tester");
                     ("request_ids", `List [ `String "a"; `String "a"; `String "b" ]);
                   ])
            in
            Alcotest.(check string) "next id" "CASE-1001" (str (member "id" j2));
            Alcotest.(check int)
              "deduped ids" 2
              (List.length (lst (member "request_ids" j2)));
            let* _, l = get r "/api/v1/cases?assignee=me" in
            Alcotest.(check (list string))
              "mine" [ "CASE-1001" ]
              (List.map (fun c -> str (member "id" c)) (lst (member "cases" l)));
            let* c, p =
              patch r "/api/v1/cases/CASE-1000"
                (`Assoc
                   [
                     ("status", `String "contained");
                     ("assignee", `String "lee@acme.test");
                     ("note", `String "Paused at IdP");
                   ])
            in
            Alcotest.(check int) "patch" 200 c;
            Alcotest.(check string) "contained" "contained" (str (member "status" p));
            Alcotest.(check string)
              "note" "Paused at IdP"
              (str (member "text" (List.hd (lst (member "notes" p)))));
            let* c, p =
              post r "/api/v1/cases/CASE-1000/records"
                (`Assoc [ ("request_ids", `List [ `String "r1"; `String "r2" ]) ])
            in
            Alcotest.(check int) "records" 200 c;
            Alcotest.(check int) "two" 2 (List.length (lst (member "request_ids" p)));
            let* c, _ =
              post r "/api/v1/cases/CASE-1000/steps/0" (`Assoc [ ("done", `Bool true) ])
            in
            Alcotest.(check int) "no steps" 404 c;
            let* c, _ =
              patch r "/api/v1/cases/CASE-1000"
                (`Assoc [ ("status", `String "resolved") ])
            in
            Alcotest.(check int) "resolve" 200 c;
            let* c, j =
              post r "/api/v1/cases/CASE-1000/records"
                (`Assoc [ ("request_ids", `List [ `String "x" ]) ])
            in
            Alcotest.(check int) "resolved conflict" 409 c;
            Alcotest.(check string) "conflict" "CONFLICT" (err_code j);
            let* c, _ =
              patch r "/api/v1/cases/CASE-1000" (`Assoc [ ("title", `String "x") ])
            in
            Alcotest.(check int) "resolved patch conflict" 409 c;
            let* _, l = get r "/api/v1/cases" in
            Alcotest.(check int)
              "open excludes resolved" 1
              (List.length (lst (member "cases" l)));
            let* _, l = get r "/api/v1/cases?status=all" in
            Alcotest.(check int) "all" 2 (List.length (lst (member "cases" l)));
            let* c, _ =
              patch r "/api/v1/cases/CASE-1000" (`Assoc [ ("status", `String "open") ])
            in
            Alcotest.(check int) "reopen" 200 c;
            let* c, _ = get r "/api/v1/cases/CASE-9" in
            Alcotest.(check int) "404" 404 c;
            let* c, _ = post r "/api/v1/cases" (`Assoc []) in
            Alcotest.(check int) "title required" 400 c;
            let* c, _ =
              patch r "/api/v1/cases/CASE-1001" (`Assoc [ ("status", `String "weird") ])
            in
            Alcotest.(check int) "bad status" 400 c;
            let acts =
              List.map
                (fun a -> str (member "action" a))
                (List.rev (C.Activity.recent r.ctx))
            in
            List.iter
              (fun a -> Alcotest.(check bool) a true (List.mem a acts))
              [ "case.create"; "case.update"; "case.add_records" ];
            Lwt.return_unit) );
    ( "permissions",
      `Quick,
      fun () ->
        run (fun r ->
            let* c, j =
              post ~token:dev_token r "/api/v1/cases" (`Assoc [ ("title", `String "x") ])
            in
            Alcotest.(check int) "dev cannot create" 403 c;
            Alcotest.(check string) "forbidden" "FORBIDDEN" (err_code j);
            let* c, _ =
              post ~token:analyst_token r "/api/v1/cases"
                (`Assoc [ ("title", `String "x") ])
            in
            Alcotest.(check int) "analyst creates" 201 c;
            let* c, _ =
              patch ~token:dev_token r "/api/v1/cases/CASE-1000"
                (`Assoc [ ("note", `String "n") ])
            in
            Alcotest.(check int) "dev cannot patch" 403 c;
            let* c, _ =
              post ~token:dev_token r "/api/v1/cases/CASE-1000/records"
                (`Assoc [ ("request_ids", `List [ `String "x" ]) ])
            in
            Alcotest.(check int) "dev cannot add" 403 c;
            let* c, _ = get ~token:dev_token r "/api/v1/cases/CASE-1000" in
            Alcotest.(check int) "dev reads" 200 c;
            let* c, _ = get ~token:dev_token r "/api/v1/cases" in
            Alcotest.(check int) "dev lists" 200 c;
            Lwt.return_unit) );
    ( "from a cross_tenant signal",
      `Quick,
      fun () ->
        run (fun r ->
            let t = now () in
            load_records r (tenant_denials t);
            ignore (C.Signals.run_once ~now:t r.ctx);
            let l = one_of_kind r "cross_tenant" in
            let* c, j =
              post r "/api/v1/cases"
                (`Assoc
                   [
                     ("title", `String "support-bot cross-tenant");
                     ("signal_id", `String l.id);
                   ])
            in
            Alcotest.(check int) "201" 201 c;
            Alcotest.(check string) "signal" l.id (str (member "signal_id" j));
            Alcotest.(check int) "four steps" 4 (List.length (lst (member "steps" j)));
            Alcotest.(check int)
              "seeded request ids" 10
              (List.length (lst (member "request_ids" j)));
            let* _, s = get r "/api/v1/signals" in
            Alcotest.(check string)
              "linked back" "CASE-1000"
              (str (member "case_id" (List.hd (lst (member "signals" s)))));
            let* c, _ =
              post r "/api/v1/cases"
                (`Assoc [ ("title", `String "again"); ("signal_id", `String l.id) ])
            in
            Alcotest.(check int) "already linked" 409 c;
            let* c, _ =
              post r "/api/v1/cases"
                (`Assoc [ ("title", `String "x"); ("signal_id", `String "sig_nope") ])
            in
            Alcotest.(check int) "unknown signal" 400 c;
            let* c, p =
              post r "/api/v1/cases/CASE-1000/steps/1" (`Assoc [ ("done", `Bool true) ])
            in
            Alcotest.(check int) "step" 200 c;
            Alcotest.(check bool)
              "done" true
              (member "done" (List.nth (lst (member "steps" p)) 1) = `Bool true);
            let* c, _ =
              post r "/api/v1/cases/CASE-1000/steps/9" (`Assoc [ ("done", `Bool true) ])
            in
            Alcotest.(check int) "no step 9" 404 c;
            let* c, _ =
              post r "/api/v1/cases/CASE-1000/steps/x" (`Assoc [ ("done", `Bool true) ])
            in
            Alcotest.(check int) "bad index" 400 c;
            Lwt.return_unit) );
  ]

(* ---- pause ---- *)

let pause_tests =
  [
    ( "pause is logged then 501",
      `Quick,
      fun () ->
        run (fun r ->
            let path = "/api/v1/callers/token%3Asupport-bot/pause" in
            let* c, j =
              post ~token:analyst_token r path (`Assoc [ ("minutes", `Int 60) ])
            in
            Alcotest.(check int) "no reason" 403 c;
            Alcotest.(check string) "reason required" "REASON_REQUIRED" (err_code j);
            let* c, j =
              post ~token:dev_token r path (`Assoc [ ("reason", `String "x") ])
            in
            Alcotest.(check int) "dev" 403 c;
            Alcotest.(check string) "forbidden" "FORBIDDEN" (err_code j);
            let* c, j =
              post ~token:analyst_token r path
                (`Assoc [ ("minutes", `Int 60); ("reason", `String "CASE-1000 triage") ])
            in
            Alcotest.(check int) "501" 501 c;
            Alcotest.(check string) "code" "NOT_IMPLEMENTED" (err_code j);
            check_contains "message" ~sub:"identity provider"
              (str (member "error.message" j));
            let e =
              List.find
                (fun a -> member "action" a = `String "caller.pause_requested")
                (List.rev (C.Activity.recent r.ctx))
            in
            Alcotest.(check string) "target" "token:support-bot" (str (member "target" e));
            Alcotest.(check string) "reason" "CASE-1000 triage" (str (member "reason" e));
            let* c, _ =
              post ~token:analyst_token ~reason:"r" r path
                (`Assoc [ ("minutes", `Int 0) ])
            in
            Alcotest.(check int) "bad minutes" 400 c;
            Lwt.return_unit) );
  ]

(* ---- notifications and Jira ---- *)

(* An in-process HTTP server recording every request (path, body). *)
let fake_server respond =
  let seen = ref [] in
  let callback _conn req body =
    let* b = Cohttp_lwt.Body.to_string body in
    let path = Uri.path (Cohttp.Request.uri req) in
    seen := (path, b, Cohttp.Request.headers req) :: !seen;
    let status, body = respond path in
    Cohttp_lwt_unix.Server.respond_string ~status ~body ()
  in
  let* addrs =
    Lwt_unix.getaddrinfo "127.0.0.1" "0" [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ]
  in
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true;
  let* () = Lwt_unix.bind fd (List.hd addrs).Unix.ai_addr in
  Lwt_unix.listen fd 16;
  let port = match Lwt_unix.getsockname fd with Unix.ADDR_INET (_, p) -> p | _ -> 0 in
  let stop, wake = Lwt.wait () in
  Lwt.async (fun () ->
      Cohttp_lwt_unix.Server.create ~stop
        ~mode:(`TCP (`Socket fd))
        (Cohttp_lwt_unix.Server.make ~callback ()));
  Lwt.return (port, seen, fun () -> Lwt.wakeup_later wake ())

let rec wait_for ?(tries = 50) p =
  if p () || tries = 0 then Lwt.return_unit
  else
    let* () = Lwt_unix.sleep 0.05 in
    wait_for ~tries:(tries - 1) p

let notify_tests =
  [
    ( "slack and pagerduty once per new high signal",
      `Quick,
      fun () ->
        Lwt_main.run
          (let* port, seen, stop_fake = fake_server (fun _ -> (`OK, "{}")) in
           let base = Printf.sprintf "http://127.0.0.1:%d" port in
           let c =
             cfg
               ~extra:
                 [
                   ( "integrations",
                     `Assoc
                       [
                         ( "slack",
                           `Assoc [ ("webhook", `String (base ^ "/slack/T000/secret")) ]
                         );
                         ( "pagerduty",
                           `Assoc
                             [
                               ("routing_key", `String "rk-secret");
                               ("events_url", `String (base ^ "/v2/enqueue"));
                             ] );
                       ] );
                 ]
               ()
           in
           let* r = start ~background:false c in
           Lwt.finalize
             (fun () ->
               let t = now () in
               load_records r (tenant_denials t);
               load_records r
                 [
                   server_record ~shadow:true ~codes:[ "E_COLUMN_DENIED" ] ~ts:t
                     ~policy:"p2" ();
                 ];
               ignore (C.Signals.run_once ~now:t r.ctx);
               let* () = wait_for (fun () -> List.length !seen >= 2) in
               ignore (C.Signals.run_once ~now:(t +. 30.) r.ctx);
               let* () = Lwt_unix.sleep 0.2 in
               let paths = List.map (fun (p, _, _) -> p) !seen in
               Alcotest.(check (list string))
                 "one slack, one pagerduty (low shadow_ready not sent)"
                 [ "/slack/T000/secret"; "/v2/enqueue" ]
                 (List.sort compare paths);
               let _, pd, _ = List.find (fun (p, _, _) -> p = "/v2/enqueue") !seen in
               let pd = Yojson.Safe.from_string pd in
               Alcotest.(check string)
                 "routing key" "rk-secret"
                 (str (member "routing_key" pd));
               Alcotest.(check string)
                 "trigger" "trigger"
                 (str (member "event_action" pd));
               Alcotest.(check string)
                 "critical" "critical"
                 (str (member "payload.severity" pd));
               let _, sl, _ =
                 List.find (fun (p, _, _) -> p = "/slack/T000/secret") !seen
               in
               check_contains "slack text" ~sub:"is filtering on other tenants"
                 (str (member "text" (Yojson.Safe.from_string sl)));
               Lwt.return_unit)
             (fun () ->
               stop r;
               stop_fake ();
               Lwt.return_unit)) );
    ( "jira issue on case creation",
      `Quick,
      fun () ->
        Lwt_main.run
          (let* port, seen, stop_fake =
             fake_server (fun _ -> (`Created, {|{"id":"1","key":"SEC-77"}|}))
           in
           let base = Printf.sprintf "http://127.0.0.1:%d" port in
           let c =
             cfg
               ~extra:
                 [
                   ( "integrations",
                     `Assoc
                       [
                         ( "jira",
                           `Assoc
                             [
                               ("url", `String base);
                               ("project", `String "SEC");
                               ("email", `String "bot@acme.test");
                               ("token", `String "jira-secret");
                             ] );
                       ] );
                 ]
               ()
           in
           let* r = start ~background:false c in
           Lwt.finalize
             (fun () ->
               let* code, j =
                 post r "/api/v1/cases" (`Assoc [ ("title", `String "Ticketed") ])
               in
               Alcotest.(check int) "201" 201 code;
               Alcotest.(check string) "key" "SEC-77" (str (member "jira.key" j));
               Alcotest.(check string)
                 "url" (base ^ "/browse/SEC-77")
                 (str (member "jira.url" j));
               let path, body, headers = List.hd !seen in
               Alcotest.(check string) "path" "/rest/api/2/issue" path;
               Alcotest.(check string)
                 "project" "SEC"
                 (str (member "fields.project.key" (Yojson.Safe.from_string body)));
               Alcotest.(check (option string))
                 "basic auth"
                 (Some ("Basic " ^ C.Notify.base64 "bot@acme.test:jira-secret"))
                 (Cohttp.Header.get headers "authorization");
               let* _, g = get r "/api/v1/cases/CASE-1000" in
               Alcotest.(check string) "stored" "SEC-77" (str (member "jira.key" g));
               Lwt.return_unit)
             (fun () ->
               stop r;
               stop_fake ();
               Lwt.return_unit)) );
    ( "unreachable jira does not fail the case",
      `Quick,
      fun () ->
        let c =
          cfg
            ~extra:
              [
                ( "integrations",
                  `Assoc
                    [
                      ( "jira",
                        `Assoc
                          [
                            ("url", `String "http://127.0.0.1:1");
                            ("project", `String "SEC");
                            ("token", `String "t");
                          ] );
                    ] );
              ]
            ()
        in
        with_console ~background:false c (fun r ->
            let* code, j = post r "/api/v1/cases" (`Assoc [ ("title", `String "x") ]) in
            Alcotest.(check int) "201" 201 code;
            Alcotest.(check bool) "no key" true (member "jira" j = `Null);
            Lwt.return_unit) );
  ]

(* ---- review fixes (#30) ---- *)

let pd_integration base =
  ( "integrations",
    `Assoc
      [
        ( "pagerduty",
          `Assoc
            [
              ("routing_key", `String "rk"); ("events_url", `String (base ^ "/v2/enqueue"));
            ] );
      ] )

(* PagerDuty events seen by a fake server, oldest first: (event_action, dedup_key). *)
let pd_events seen =
  List.rev !seen
  |> List.filter (fun (p, _, _) -> p = "/v2/enqueue")
  |> List.map (fun (_, b, _) ->
      let j = Yojson.Safe.from_string b in
      (str (member "event_action" j), str (member "dedup_key" j)))

let with_fake respond f =
  Lwt_main.run
    (let* port, seen, stop_fake = fake_server respond in
     Lwt.finalize
       (fun () -> f (Printf.sprintf "http://127.0.0.1:%d" port) seen)
       (fun () ->
         stop_fake ();
         Lwt.return_unit))

let raw_post ?token r path body =
  let headers = headers_of ?token [ ("content-type", "application/json") ] in
  let* resp, b =
    Cohttp_lwt_unix.Client.call ~headers
      ~body:(Cohttp_lwt.Body.of_string body)
      `POST (uri r path)
  in
  let* j = body_json b in
  Lwt.return (Cohttp.Code.code_of_status (Cohttp.Response.status resp), j)

let fix_tests =
  [
    ( "SIG-1/NOT-2: a recurrence after auto-resolve of a case-linked signal is new",
      `Quick,
      fun () ->
        with_fake
          (fun _ -> (`OK, "{}"))
          (fun base seen ->
            let* r = start ~background:false (cfg ~extra:[ pd_integration base ] ()) in
            Lwt.finalize
              (fun () ->
                let t = now () in
                load_records r (tenant_denials t);
                ignore (C.Signals.run_once ~now:t r.ctx);
                let a = one_of_kind r "cross_tenant" in
                let* c, _ =
                  post r "/api/v1/cases"
                    (`Assoc [ ("title", `String "first"); ("signal_id", `String a.id) ])
                in
                Alcotest.(check int) "case" 201 c;
                ignore (C.Signals.run_once ~now:(t +. 30. +. 1800.) r.ctx);
                let* () = C.Signals.flush r.ctx in
                Alcotest.(check bool) "auto-resolved" true a.auto_resolved;
                let* () = wait_for (fun () -> List.length (pd_events seen) >= 2) in
                Alcotest.(check (list (pair string string)))
                  "trigger then resolve"
                  [ ("trigger", a.id); ("resolve", a.id) ]
                  (pd_events seen);
                (* the condition comes back later: a new signal, paged again *)
                let t2 = t +. 4000. in
                load_records r (tenant_denials t2);
                let created = C.Signals.run_once ~now:t2 r.ctx in
                Alcotest.(check int) "one new signal" 1 (List.length created);
                let b = List.hd created in
                Alcotest.(check bool) "new id" true (b.id <> a.id);
                Alcotest.(check bool) "old one stays resolved" true a.auto_resolved;
                let* () = wait_for (fun () -> List.length (pd_events seen) >= 3) in
                Alcotest.(check (list (pair string string)))
                  "paged for the recurrence"
                  [ ("trigger", a.id); ("resolve", a.id); ("trigger", b.id) ]
                  (pd_events seen);
                let* c, _ =
                  post r "/api/v1/cases"
                    (`Assoc [ ("title", `String "second"); ("signal_id", `String b.id) ])
                in
                Alcotest.(check int) "a case for the recurrence" 201 c;
                Lwt.return_unit)
              (fun () ->
                stop r;
                Lwt.return_unit)) );
    ( "SIG-1/SIG-5: after a restart a closed workflow is not reused; old signal still \
       served",
      `Quick,
      fun () ->
        let c = cfg () in
        let t = now () in
        let a_id =
          with_console ~background:false c (fun r ->
              load_records r (tenant_denials t);
              ignore (C.Signals.run_once ~now:t r.ctx);
              let a = one_of_kind r "cross_tenant" in
              let* code, _ =
                post r ("/api/v1/signals/" ^ a.id)
                  (`Assoc [ ("assignee", `String "dana@acme.test") ])
              in
              Alcotest.(check int) "assigned" 200 code;
              ignore (C.Signals.run_once ~now:(t +. 1900.) r.ctx);
              let* () = C.Signals.flush r.ctx in
              Lwt.return a.id)
        in
        with_console ~background:false c (fun r ->
            (* nothing re-detected yet: the old signal is served from its snapshot *)
            let* code, j = get r ("/api/v1/signals/" ^ a_id) in
            Alcotest.(check int) "get after restart" 200 code;
            Alcotest.(check string) "kind" "cross_tenant" (str (member "signal.kind" j));
            Alcotest.(check string) "resolved" "resolved" (str (member "signal.status" j));
            Alcotest.(check string)
              "assignee" "dana@acme.test"
              (str (member "signal.assignee" j));
            let* _, l = get r "/api/v1/signals?status=all" in
            Alcotest.(check (list string))
              "listed" [ a_id ]
              (List.map (fun s -> str (member "id" s)) (lst (member "signals" l)));
            let t2 = t +. 4000. in
            load_records r (tenant_denials t2);
            let created = C.Signals.run_once ~now:t2 r.ctx in
            Alcotest.(check int) "new signal" 1 (List.length created);
            Alcotest.(check bool) "new id" true ((List.hd created).id <> a_id);
            Lwt.return_unit) );
    ( "SIG-1: an open workflow is re-attached after a restart",
      `Quick,
      fun () ->
        let c = cfg () in
        let t = now () in
        let a_id =
          with_console ~background:false c (fun r ->
              load_records r (tenant_denials t);
              ignore (C.Signals.run_once ~now:t r.ctx);
              let a = one_of_kind r "cross_tenant" in
              let* _ =
                post r ("/api/v1/signals/" ^ a.id)
                  (`Assoc [ ("assignee", `String "dana@acme.test") ])
              in
              Lwt.return a.id)
        in
        with_console ~background:false c (fun r ->
            load_records r (tenant_denials t);
            let created = C.Signals.run_once ~now:(t +. 30.) r.ctx in
            Alcotest.(check int) "not new" 0 (List.length created);
            Alcotest.(check string) "same id" a_id (one_of_kind r "cross_tenant").id;
            Lwt.return_unit) );
    ( "SIG-2: the background pass yields and gives the same result",
      `Quick,
      fun () ->
        run (fun r ->
            let t = now () in
            load_records r (tenant_denials t);
            let ticks = ref 0 in
            let rec ticker () =
              if !ticks < 1000 then (
                incr ticks;
                let* () = Lwt.pause () in
                ticker ())
              else Lwt.return_unit
            in
            Lwt.async ticker;
            let* created = C.Signals.run_once_lwt ~now:t r.ctx in
            Alcotest.(check int) "created" 1 (List.length created);
            Alcotest.(check bool) "other promises ran meanwhile" true (!ticks > 1);
            Lwt.return_unit) );
    ( "SIG-3: shapes never carry literal text",
      `Quick,
      fun () ->
        let shape = C.Signals.shape_of_sql in
        let check name expected sql =
          Alcotest.(check (option string)) name expected (shape sql)
        in
        let q = "SELECT * FROM t WHERE a = ?" in
        check "dollar" (Some q) "SELECT * FROM t WHERE a = $$alice@acme.com$$";
        check "dollar tag" (Some q) "SELECT * FROM t WHERE a = $x$it's $$ secret$x$";
        check "E string" (Some q) "SELECT * FROM t WHERE a = E'it\\'s secret'";
        check "E string backslash" (Some q) "SELECT * FROM t WHERE a = e'a\\\\'";
        check "U& string" (Some q) "SELECT * FROM t WHERE a = U&'d\\0061t\\+000061'";
        check "bit string" (Some q) "SELECT * FROM t WHERE a = B'1010'";
        check "nested comment" (Some "SELECT ?") "SELECT /* a /* nested */ secret */ 1";
        check "numbers" (Some "INSERT INTO t1 (c2) VALUES (?), (?), (?)")
          "INSERT INTO t1 (c2) VALUES (1e-3), (0x1F), (.5)";
        check "identifiers kept" (Some "SELECT col_1, \"Na\"\"me\" FROM s.t2")
          "SELECT col_1, \"Na\"\"me\" FROM s.t2";
        check "unterminated" None "SELECT * FROM t WHERE a = 'secret";
        check "not sql" None "hello alice@acme.com";
        List.iter
          (fun sql ->
            match shape sql with
            | Some s when contains ~sub:"secret" s -> Alcotest.failf "leaked: %s" s
            | _ -> ())
          [
            "SELECT 'secret'";
            "SELECT E'\\'secret'";
            "SELECT $$secret$$";
            "SELECT $a$secret$a$";
            "SELECT /* /* */ secret */ 1";
            "SELECT U&'secret'";
            "SELECT X'5ec' AS h";
          ] );
    ( "OV-1: an unbounded explicit range is capped",
      `Quick,
      fun () ->
        run (fun r ->
            load_records r [ server_record () ];
            let* code, o =
              get r
                "/api/v1/overview?since=0000-01-01T00:00:00Z&until=9999-12-31T23:59:59Z"
            in
            Alcotest.(check int) "200" 200 code;
            let n = List.length (lst (member "series" o)) in
            Alcotest.(check bool)
              (Printf.sprintf "at most %d buckets (got %d)" C.Detectors.max_buckets n)
              true
              (n >= 1 && n <= C.Detectors.max_buckets + 1);
            Alcotest.(check int) "checked" 1 (int (member "totals.checked" o));
            let sum =
              List.fold_left
                (fun a b -> a + int (member "allowed" b))
                0
                (lst (member "series" o))
            in
            Alcotest.(check int) "record counted" 1 sum;
            Lwt.return_unit) );
    ( "OV-2: bucket widening",
      `Quick,
      fun () ->
        Alcotest.(check int) "fits" 60 (C.Detectors.fit_bucket ~since:0. ~until:3600. 60);
        let b = C.Detectors.fit_bucket ~since:0. ~until:(30. *. 86400.) 60 in
        Alcotest.(check bool) "multiple of 60" true (b mod 60 = 0);
        Alcotest.(check bool)
          "at most max_buckets" true
          (30. *. 86400. /. float_of_int b <= float_of_int C.Detectors.max_buckets) );
    ( "CASE-1: request id and note limits",
      `Quick,
      fun () ->
        run (fun r ->
            let ids n prefix =
              `List (List.init n (fun i -> `String (Printf.sprintf "%s-%d" prefix i)))
            in
            let* c, _ =
              post r "/api/v1/cases"
                (`Assoc [ ("title", `String "big"); ("request_ids", ids 1001 "x") ])
            in
            Alcotest.(check int) "too many ids per request" 400 c;
            let* c, _ =
              post r "/api/v1/cases"
                (`Assoc
                   [
                     ("title", `String "long");
                     ("request_ids", `List [ `String (String.make 201 'a') ]);
                   ])
            in
            Alcotest.(check int) "id too long" 400 c;
            let* c, _ =
              post r "/api/v1/cases" (`Assoc [ ("title", `String (String.make 501 't')) ])
            in
            Alcotest.(check int) "title too long" 400 c;
            let* c, j =
              post r "/api/v1/cases"
                (`Assoc [ ("title", `String "ok"); ("request_ids", ids 1000 "a") ])
            in
            Alcotest.(check int) "1000 ids" 201 c;
            let id = str (member "id" j) in
            let path = "/api/v1/cases/" ^ id ^ "/records" in
            let rec add k =
              if k > 9 then Lwt.return_unit
              else
                let* c, _ =
                  post r path
                    (`Assoc [ ("request_ids", ids 1000 (Printf.sprintf "b%d" k)) ])
                in
                Alcotest.(check int) (Printf.sprintf "batch %d" k) 200 c;
                add (k + 1)
            in
            let* () = add 1 in
            let* c, j = post r path (`Assoc [ ("request_ids", ids 1000 "b1") ]) in
            Alcotest.(check int) "duplicates are free" 200 c;
            Alcotest.(check int)
              "10000 ids" 10000
              (List.length (lst (member "request_ids" j)));
            let* c, _ = post r path (`Assoc [ ("request_ids", ids 1 "over") ]) in
            Alcotest.(check int) "per-case cap" 400 c;
            let* _, g = get r ("/api/v1/cases/" ^ id) in
            Alcotest.(check int)
              "unchanged" 10000
              (List.length (lst (member "request_ids" g)));
            let* c, _ =
              patch r ("/api/v1/cases/" ^ id)
                (`Assoc [ ("note", `String (String.make 10_001 'n')) ])
            in
            Alcotest.(check int) "note too long" 400 c;
            Alcotest.(check (list string))
              "dedupe keeps order" [ "b"; "a"; "c" ]
              (C.Cases.dedupe [ "b"; "a"; "b"; "c"; "a" ]);
            Lwt.return_unit) );
    ( "SIG-4: cases and signals are paginated",
      `Quick,
      fun () ->
        run (fun r ->
            let* _ = post r "/api/v1/cases" (`Assoc [ ("title", `String "one") ]) in
            let* _ = post r "/api/v1/cases" (`Assoc [ ("title", `String "two") ]) in
            let* _, p1 = get r "/api/v1/cases?limit=1" in
            Alcotest.(check (list string))
              "newest first" [ "CASE-1001" ]
              (List.map (fun c -> str (member "id" c)) (lst (member "cases" p1)));
            let cursor = str (member "next_cursor" p1) in
            let* _, p2 = get r ("/api/v1/cases?limit=1&cursor=" ^ cursor) in
            Alcotest.(check (list string))
              "then older" [ "CASE-1000" ]
              (List.map (fun c -> str (member "id" c)) (lst (member "cases" p2)));
            Alcotest.(check bool) "end" true (member "next_cursor" p2 = `Null);
            let t = now () in
            load_records r (tenant_denials t);
            load_records r (tenant_denials ~caller:"token:other" t);
            ignore (C.Signals.run_once ~now:t r.ctx);
            let* _, s1 = get r "/api/v1/signals?limit=1" in
            Alcotest.(check int) "one signal" 1 (List.length (lst (member "signals" s1)));
            let cursor = str (member "next_cursor" s1) in
            let* _, s2 = get r ("/api/v1/signals?limit=1&cursor=" ^ cursor) in
            Alcotest.(check int) "next signal" 1 (List.length (lst (member "signals" s2)));
            Alcotest.(check bool)
              "different" true
              (member "signals" s1 <> member "signals" s2);
            Alcotest.(check bool) "last page" true (member "next_cursor" s2 = `Null);
            Lwt.return_unit) );
    ( "NOT-1/NOT-3: placeholder secrets resolve on use; Slack text is escaped",
      `Quick,
      fun () ->
        with_fake
          (fun p ->
            if p = "/rest/api/2/issue" then (`Created, {|{"key":"SEC-9"}|})
            else (`OK, "{}"))
          (fun base seen ->
            Unix.putenv "HALTSQL_TEST_SLACK_HOOK" (base ^ "/slack/hook");
            Unix.putenv "HALTSQL_TEST_PD_KEY" "rk-from-env";
            Unix.putenv "HALTSQL_TEST_JIRA_URL" base;
            Unix.putenv "HALTSQL_TEST_JIRA_TOKEN" "jt-from-env";
            let c =
              cfg
                ~extra:
                  [
                    ( "integrations",
                      `Assoc
                        [
                          ( "slack",
                            `Assoc
                              [ ("webhook", `String "${env:HALTSQL_TEST_SLACK_HOOK}") ] );
                          ( "pagerduty",
                            `Assoc
                              [
                                ("routing_key", `String "${env:HALTSQL_TEST_PD_KEY}");
                                ("events_url", `String (base ^ "/v2/enqueue"));
                              ] );
                          ( "jira",
                            `Assoc
                              [
                                ("url", `String "${env:HALTSQL_TEST_JIRA_URL}");
                                ("project", `String "SEC");
                                ("token", `String "${env:HALTSQL_TEST_JIRA_TOKEN}");
                              ] );
                        ] );
                  ]
                ()
            in
            let* r = start ~background:false c in
            Lwt.finalize
              (fun () ->
                let t = now () in
                load_records r (tenant_denials ~caller:"token:<!channel>" t);
                ignore (C.Signals.run_once ~now:t r.ctx);
                let* () = wait_for (fun () -> List.length !seen >= 2) in
                let body p =
                  List.find_map (fun (q, b, _) -> if q = p then Some b else None) !seen
                in
                let pd = Yojson.Safe.from_string (Option.get (body "/v2/enqueue")) in
                Alcotest.(check string)
                  "resolved key" "rk-from-env"
                  (str (member "routing_key" pd));
                let text =
                  str
                    (member "text"
                       (Yojson.Safe.from_string (Option.get (body "/slack/hook"))))
                in
                check_contains "escaped" ~sub:"token:&lt;!channel&gt;" text;
                Alcotest.(check bool)
                  "no raw mention" false
                  (contains ~sub:"<!channel>" text);
                let* code, j =
                  post r "/api/v1/cases" (`Assoc [ ("title", `String "x") ])
                in
                Alcotest.(check int) "201" 201 code;
                Alcotest.(check string) "jira key" "SEC-9" (str (member "jira.key" j));
                Alcotest.(check string)
                  "browse url from the resolved base" (base ^ "/browse/SEC-9")
                  (str (member "jira.url" j));
                let _, _, h =
                  List.find (fun (q, _, _) -> q = "/rest/api/2/issue") !seen
                in
                Alcotest.(check (option string))
                  "resolved token" (Some "Bearer jt-from-env")
                  (Cohttp.Header.get h "authorization");
                Lwt.return_unit)
              (fun () ->
                stop r;
                Lwt.return_unit)) );
    ( "NOT-2: PagerDuty retries 5xx",
      `Quick,
      fun () ->
        let calls = ref 0 in
        (C.Notify.retry_delay := fun _ -> 0.01);
        with_fake
          (fun _ ->
            incr calls;
            if !calls = 1 then (`Service_unavailable, "busy") else (`Accepted, "{}"))
          (fun base seen ->
            let* r = start ~background:false (cfg ~extra:[ pd_integration base ] ()) in
            Lwt.finalize
              (fun () ->
                let t = now () in
                load_records r (tenant_denials t);
                ignore (C.Signals.run_once ~now:t r.ctx);
                let* () = wait_for (fun () -> List.length (pd_events seen) >= 2) in
                Alcotest.(check int) "retried once" 2 (List.length (pd_events seen));
                Lwt.return_unit)
              (fun () ->
                stop r;
                Lwt.return_unit)) );
    ( "SIG-6: permission is checked before the body",
      `Quick,
      fun () ->
        run (fun r ->
            let* c, j = raw_post ~token:dev_token r "/api/v1/cases" "{not json" in
            Alcotest.(check int) "403 not 400" 403 c;
            Alcotest.(check string) "forbidden" "FORBIDDEN" (err_code j);
            let* c, _ = raw_post ~token:dev_token r "/api/v1/signals/sig_x" "{not json" in
            Alcotest.(check int) "signal update" 403 c;
            let* c, _ =
              raw_post ~token:dev_token r "/api/v1/callers/token%3Ax/pause" "{not json"
            in
            Alcotest.(check int) "pause" 403 c;
            let* c, _ = raw_post ~token:admin_token r "/api/v1/cases" "{not json" in
            Alcotest.(check int) "authorized: 400" 400 c;
            Lwt.return_unit) );
    ( "DET-3/SIG-8: signals settings are validated and tunable",
      `Quick,
      fun () ->
        let bad name j =
          match cfg ~extra:[ ("signals", j) ] () with
          | _ -> Alcotest.failf "%s: accepted" name
          | exception C.Console_config.Invalid _ -> ()
        in
        bad "zero window"
          (`Assoc [ ("cross_tenant", `Assoc [ ("window_minutes", `Int 0) ]) ]);
        bad "negative factor"
          (`Assoc [ ("deny_spike", `Assoc [ ("factor", `Float (-1.)) ]) ]);
        bad "rate over 1"
          (`Assoc [ ("deny_spike", `Assoc [ ("min_baseline_rate", `Int 2) ]) ]);
        bad "typo" (`Assoc [ ("cross_tenant", `Assoc [ ("min_record", `Int 3) ]) ]);
        bad "unknown section" (`Assoc [ ("cross-tenant", `Assoc []) ]);
        bad "float count"
          (`Assoc [ ("opa_errors", `Assoc [ ("min_records", `Float 2.5) ]) ]);
        bad "string" (`Assoc [ ("interval_seconds", `String "30") ]);
        bad "interval" (`Assoc [ ("interval_seconds", `Int 1) ]);
        let j =
          `Assoc
            [
              ("cross_tenant", `Assoc [ ("window_minutes", `Int 6) ]);
              ("interval_seconds", `Int 10);
              ("resolve_after_minutes", `Int 1);
              ("forget_after_days", `Int 2);
              ("max_reverify", `Int 7);
              ("notify_timeout_seconds", `Float 2.5);
            ]
        in
        let c = cfg ~extra:[ ("signals", j) ] () in
        let s = C.Detectors.settings_of_json c.signals in
        Alcotest.(check (float 0.)) "interval" 10. s.interval;
        Alcotest.(check (float 0.)) "resolve" 60. s.resolve_after;
        Alcotest.(check (float 0.)) "forget" 172800. s.forget_after;
        Alcotest.(check int) "reverify" 7 s.max_reverify;
        Alcotest.(check (float 0.)) "timeout" 2.5 s.notify_timeout;
        let d = C.Detectors.settings_of_json `Null in
        Alcotest.(check (float 0.)) "default resolve" 1800. d.resolve_after;
        with_console ~background:false c (fun r ->
            let t = now () in
            load_records r (tenant_denials t);
            ignore (C.Signals.run_once ~now:t r.ctx);
            let l = one_of_kind r "cross_tenant" in
            ignore (C.Signals.run_once ~now:(t +. 61.) r.ctx);
            Alcotest.(check bool) "resolved after one minute" true l.auto_resolved;
            Lwt.return_unit) );
    ( "DET-2: kinds and severities round-trip",
      `Quick,
      fun () ->
        List.iter
          (fun k ->
            Alcotest.(check bool)
              (C.Detectors.kind_to_string k)
              true
              (C.Detectors.kind_of_string (C.Detectors.kind_to_string k) = Some k))
          C.Detectors.all_kinds;
        Alcotest.(check bool) "unknown" true (C.Detectors.kind_of_string "nope" = None);
        Alcotest.(check bool)
          "severity" true
          (C.Detectors.severity_of_string "high" = Some C.Detectors.High) );
  ]

(* ---- units ---- *)

let unit_tests =
  [
    ( "shape_of_sql",
      `Quick,
      fun () ->
        Alcotest.(check (option string))
          "literals"
          (Some "SELECT a1, \"T 2\" FROM t WHERE x = ? AND y IN (?, ?) LIMIT ?")
          (C.Signals.shape_of_sql
             "SELECT a1,  \"T 2\" FROM t -- note\n\
             \ WHERE x = 'it''s' AND y IN (1, 2.5) LIMIT 10");
        Alcotest.(check (option string))
          "params kept" (Some "SELECT * FROM t WHERE id = $1")
          (C.Signals.shape_of_sql "SELECT * FROM t WHERE id = $1 /* c */") );
    ( "base64",
      `Quick,
      fun () ->
        Alcotest.(check (list string))
          "rfc4648"
          [ ""; "Zg=="; "Zm8="; "Zm9v"; "Zm9vYg==" ]
          (List.map C.Notify.base64 [ ""; "f"; "fo"; "foo"; "foob" ]) );
    ( "parse_mismatch",
      `Quick,
      fun () ->
        Alcotest.(check (option (pair string (list string))))
          "list"
          (Some ("tenant_id", [ "globex"; "a, b"; "42" ]))
          (C.Detectors.parse_mismatch
             "app.t.tenant_id is compared to 'globex', 'a, b', 42, which is not the \
              caller's tenant value (table app.t)") );
    ( "settings",
      `Quick,
      fun () ->
        let s =
          C.Detectors.settings_of_json
            (`Assoc
               [
                 ( "cross_tenant",
                   `Assoc [ ("window_minutes", `Int 5); ("min_records", `Int 3) ] );
                 ("deny_spike", `Assoc [ ("factor", `Float 2.5) ]);
               ])
        in
        Alcotest.(check (float 0.)) "window" 300. s.ct_window;
        Alcotest.(check int) "min" 3 s.ct_min;
        Alcotest.(check (float 0.)) "factor" 2.5 s.ds_factor;
        Alcotest.(check int) "default min" 50 s.ds_min );
  ]

let () =
  Alcotest.run "console-signals"
    [
      ("overview", overview_tests);
      ("detectors", detector_tests);
      ("lifecycle", lifecycle_tests);
      ("cases", case_tests);
      ("pause", pause_tests);
      ("notify", notify_tests);
      ("units", unit_tests);
      ("fixes", fix_tests);
    ]
