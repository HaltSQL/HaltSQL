(* Fleet: polling fake verifiers (admin status, readyz, metrics), state derivation, rates
   across polls, bundle drift, sink buffering, unreachable verifiers, the proxy TCP check,
   and restarts through a fake Kubernetes API. *)

open Lwt.Syntax
open Helpers
module C = Haltsql_console

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

(* ---- an in-process HTTP server ---- *)

type server = { port : int; stop : unit Lwt.u }

let serve callback =
  let* addrs =
    Lwt_unix.getaddrinfo "127.0.0.1" "0" [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ]
  in
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true;
  let* () = Lwt_unix.bind fd (List.hd addrs).Unix.ai_addr in
  Lwt_unix.listen fd 16;
  let port =
    match Lwt_unix.getsockname fd with Unix.ADDR_INET (_, p) -> p | _ -> assert false
  in
  let stop_p, stop = Lwt.wait () in
  let server = Cohttp_lwt_unix.Server.make ~callback () in
  Lwt.async (fun () ->
      Cohttp_lwt_unix.Server.create ~stop:stop_p ~mode:(`TCP (`Socket fd)) server);
  Lwt.return { port; stop }

let stop_server s = Lwt.wakeup_later s.stop ()

(* A port nothing listens on. *)
let closed_port () =
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind fd (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let port =
    match Unix.getsockname fd with Unix.ADDR_INET (_, p) -> p | _ -> assert false
  in
  Unix.close fd;
  port

let respond ?(status = `OK) ?(content_type = "application/json") body =
  Cohttp_lwt_unix.Server.respond_string ~status
    ~headers:(Cohttp.Header.of_list [ ("content-type", content_type) ])
    ~body ()

(* ---- a fake verifier ---- *)

type fake = {
  mutable status : Yojson.Safe.t option;  (** None = 404 (admin API disabled) *)
  mutable ready : int * Yojson.Safe.t;
  mutable metrics : string option;
  mutable token : string;  (** the admin token the fake accepts *)
  mutable server : server option;
}

let status_doc ?(generation = 3) ?(restart_pending = false) ?(version = "1.4.0")
    ?(revision = "sha256:rev1") ?(sinks = [ ("kafka://k1:9093/audit", "kafka", true) ])
    ?(opa = true) () =
  `Assoc
    [
      ("version", `String "0.1.0");
      ("started", `String "2026-11-07T09:12:03.120Z");
      ("uptime_seconds", `Int 5400);
      ("config_generation", `Int generation);
      ("default_policy", `Null);
      ( "policies",
        `List
          [
            `Assoc
              [
                ("name", `String "analytics");
                ("version", `String "sha256:4f1c");
                ("mode", `String "enforce");
                ("origin", `String "bundle_source");
              ];
          ] );
      ( "bundle_sources",
        `List
          [
            `Assoc
              [
                ("source", `String "oci:ghcr.io/acme/policies:prod");
                ( "current",
                  `Assoc
                    [
                      ("bundle", `String "prod");
                      ("version", `String version);
                      ("signed_by", `String "sha256:a1b2");
                      ("revision", `String revision);
                      ("origin", `String "source");
                      ("policies", `List [ `String "analytics" ]);
                    ] );
                ("checks", `Int 87);
                ("last_success", `String "2026-11-07T10:42:01.004Z");
                ("last_error", `Null);
              ];
          ] );
      ( "audit_sinks",
        `List
          (List.map
             (fun (n, t, h) ->
               `Assoc [ ("name", `String n); ("type", `String t); ("healthy", `Bool h) ])
             sinks) );
      ("audit_restart_pending", `Bool restart_pending);
      ( "opa",
        if opa then
          `Assoc
            [
              ("host", `String "127.0.0.1");
              ("decision_path", `String "haltsql/decision");
              ("timeout_ms", `Int 500);
              ("on_error", `String "deny");
            ]
        else `Null );
      ("report", `Assoc [ ("tracked_queries", `Int 1) ]);
    ]

let metrics_text ?(verify_allowed = 100) ?(verify_denied = 0) ?(opa_allowed = 10)
    ?(opa_error_denied = 0) ?(ext_policy = 0) ?(buffered = []) ?(connections = 4) () =
  String.concat ""
    ([
       "# HELP haltsql_verify_total Verify requests.\n";
       "# TYPE haltsql_verify_total counter\n";
       Printf.sprintf "haltsql_verify_total{policy=\"analytics\",result=\"allowed\"} %d\n"
         verify_allowed;
       Printf.sprintf "haltsql_verify_total{policy=\"analytics\",result=\"denied\"} %d\n"
         verify_denied;
       Printf.sprintf "haltsql_opa_decisions_total{outcome=\"allowed\"} %d\n" opa_allowed;
       Printf.sprintf "haltsql_opa_decisions_total{outcome=\"error_denied\"} %d\n"
         opa_error_denied;
       Printf.sprintf "haltsql_reasons_total{code=\"E_EXTERNAL_POLICY\"} %d\n" ext_policy;
       "haltsql_reasons_total{code=\"E_TABLE_DENIED\"} 7\n";
       Printf.sprintf "haltsql_http_open_connections %d\n" connections;
     ]
    @ List.map
        (fun (sink, n) ->
          Printf.sprintf
            "haltsql_audit_stream_sink_buffered_records{sink=\"%s\",type=\"kafka\"} %d\n"
            sink n)
        buffered)

let new_fake () =
  {
    status = Some (status_doc ());
    ready = (200, `Assoc [ ("status", `String "ready"); ("policies", `Int 1) ]);
    metrics = Some (metrics_text ());
    token = "admin-token";
    server = None;
  }

let start_fake f =
  let callback _conn req _body =
    let path = Uri.path (Cohttp.Request.uri req) in
    let auth = Cohttp.Header.get (Cohttp.Request.headers req) "authorization" in
    match path with
    | "/v1/admin/status" -> (
        match f.status with
        | None -> respond ~status:`Not_found {|{"error":{"code":"NOT_FOUND"}}|}
        | Some j ->
            if auth <> Some ("Bearer " ^ f.token) then
              respond ~status:`Forbidden {|{"error":{"code":"FORBIDDEN"}}|}
            else respond (Yojson.Safe.to_string j))
    | "/readyz" ->
        let code, j = f.ready in
        respond ~status:(Cohttp.Code.status_of_code code) (Yojson.Safe.to_string j)
    | "/metrics" -> (
        match f.metrics with
        | None -> respond ~status:`Not_found "{}"
        | Some m -> respond ~content_type:"text/plain; version=0.0.4" m)
    | _ -> respond ~status:`Not_found "{}"
  in
  let+ s = serve callback in
  f.server <- Some s;
  s.port

let stop_fake f = Option.iter stop_server f.server

let verifier_cfg ?(kind = "server") ?(token = "admin-token") ?workload name url =
  `Assoc
    ([
       ("name", `String name);
       ("url", `String url);
       ("kind", `String kind);
       ("location", `String "zone a");
       ("token", `String token);
     ]
    @ match workload with Some w -> [ ("workload", `String w) ] | None -> [])

let fleet_config ?role ?kubernetes verifiers =
  config ?role
    ~extra:
      ([ ("verifiers", `List verifiers) ]
      @
      match kubernetes with
      | Some k -> [ ("fleet", `Assoc [ ("kubernetes", k) ]) ]
      | None -> [])
    ()

let url port = Printf.sprintf "http://127.0.0.1:%d" port

(* Runs [f] with fakes started and a console (no background loops) configured for them. *)
let with_fakes ?role ?kubernetes ?(kinds = []) ?(tokens = []) ?(workloads = []) fakes f =
  Lwt_main.run
    (let* ports = Lwt_list.map_s start_fake fakes in
     let verifiers =
       List.mapi
         (fun i port ->
           let name = Printf.sprintf "haltsql-%d" (i + 1) in
           verifier_cfg ?kind:(List.assoc_opt name kinds)
             ?token:(List.assoc_opt name tokens)
             ?workload:(List.assoc_opt name workloads)
             name (url port))
         ports
     in
     let cfg = fleet_config ?role ?kubernetes verifiers in
     let* r = start ~background:false cfg in
     Lwt.finalize
       (fun () -> f r)
       (fun () ->
         stop r;
         List.iter stop_fake fakes;
         Lwt.return_unit))

let verifier doc name =
  match member "verifiers" doc with
  | `List l -> (
      match List.find_opt (fun v -> member "name" v = `String name) l with
      | Some v -> v
      | None -> Alcotest.failf "no verifier %s in %s" name (Yojson.Safe.to_string doc))
  | _ -> Alcotest.fail "no verifiers"

let str_of = function `String s -> s | j -> Yojson.Safe.to_string j
let check_str msg expected j = Alcotest.(check string) msg expected (str_of j)
let list_len = function `List l -> List.length l | _ -> -1

(* ---- Prometheus parser ---- *)

let prom_tests =
  [
    ( "parses labels, escapes and skips comments",
      `Quick,
      fun () ->
        let s =
          C.Prom.parse
            "# HELP x y\n\
             # TYPE x counter\n\
             x{a=\"1\",b=\"q\\\"uote\"} 3\n\
             y 4.5 1700000000\n\n\
             bad line here\n\
             z{sink=\"s3://b/k\"} +Inf\n"
        in
        Alcotest.(check int) "samples" 3 (List.length s);
        Alcotest.(check (option (float 0.))) "x" (Some 3.) (C.Prom.sum s "x");
        Alcotest.(check (option (float 0.)))
          "label filter" (Some 3.)
          (C.Prom.sum ~labels:[ ("b", "q\"uote") ] s "x");
        Alcotest.(check (option (float 0.))) "missing" None (C.Prom.sum s "nope");
        Alcotest.(check (option (float 0.)))
          "timestamp ignored" (Some 4.5) (C.Prom.sum s "y") );
    ( "workload parsing",
      `Quick,
      fun () ->
        let p s = Option.map C.K8s.workload_to_string (C.K8s.parse_workload s) in
        Alcotest.(check (option string))
          "deploy" (Some "deployment/haltsql-1") (p "deploy/haltsql-1");
        Alcotest.(check (option string)) "sts" (Some "statefulset/h") (p "sts/h");
        Alcotest.(check (option string)) "bad kind" None (p "daemonset/h");
        Alcotest.(check (option string)) "bad name" None (p "deployment/../x");
        Alcotest.(check (option string)) "upper" None (p "deployment/Haltsql") );
  ]

(* ---- polling ---- *)

let poll_tests =
  [
    ( "empty fleet before the first poll",
      `Quick,
      fun () ->
        with_fakes
          [ new_fake () ]
          (fun r ->
            let* code, doc = get r "/api/v1/fleet" in
            Alcotest.(check int) "200" 200 code;
            Alcotest.(check bool) "updated null" true (member "updated" doc = `Null);
            Alcotest.(check int) "no verifiers" 0 (list_len (member "verifiers" doc));
            Lwt.return_unit) );
    ( "ready verifier, document shape and rate across polls",
      `Quick,
      fun () ->
        let f = new_fake () in
        with_fakes [ f ] (fun r ->
            let t0 = 1_800_000_000. in
            let* _ = C.Fleet.poll_once ~now:t0 r.ctx in
            f.metrics <-
              Some
                (metrics_text ~verify_allowed:180 ~verify_denied:20 ~opa_allowed:25
                   ~opa_error_denied:3 ~ext_policy:2 ());
            let* _ = C.Fleet.poll_once ~now:(t0 +. 10.) r.ctx in
            let* code, doc = get ~reason:"x" r "/api/v1/fleet" in
            Alcotest.(check int) "200" 200 code;
            let v = verifier doc "haltsql-1" in
            check_str "state" "ready" (member "state" v);
            check_str "kind" "server" (member "kind" v);
            check_str "location" "zone a" (member "location" v);
            check_str "version" "0.1.0" (member "version" v);
            Alcotest.(check bool) "uptime" true (member "uptime_seconds" v = `Int 5400);
            Alcotest.(check bool)
              "rate 10/s" true
              (member "verifies_per_second" v = `Float 10.);
            Alcotest.(check bool) "connections" true (member "connections" v = `Int 4);
            Alcotest.(check bool)
              "opa configured" true
              (member "opa.configured" v = `Bool true);
            Alcotest.(check bool) "opa timeouts" true (member "opa.timeouts" v = `Int 3);
            Alcotest.(check bool)
              "external denials" true
              (member "opa.external_policy_denials" v = `Int 2);
            check_str "bundle version" "1.4.0" (member "bundle.version" v);
            check_str "policy" "analytics"
              (match member "policies" v with
              | `List (p :: _) -> member "name" p
              | _ -> `Null);
            Alcotest.(check bool) "no error" true (member "error" v = `Null);
            check_str "note" "Ready: 1 policy, bundle prod 1.4.0." (member "note" v);
            Alcotest.(check bool)
              "generation" true
              (member "config_generation" doc = `Int 3);
            Alcotest.(check bool) "updated" true (member "updated" doc <> `Null);
            (* aggregates *)
            check_str "opa path" "haltsql/decision" (member "opa.decision_path" doc);
            check_str "opa endpoint" "127.0.0.1" (member "opa.endpoint" doc);
            Alcotest.(check bool)
              "opa allowed delta" true
              (member "opa.decisions.allowed" doc = `Int 15);
            Alcotest.(check bool)
              "opa error_denied delta" true
              (member "opa.decisions.error_denied" doc = `Int 3);
            (match member "bundles" doc with
            | `List [ b ] ->
                Alcotest.(check bool) "in sync" true (member "in_sync" b = `Bool true);
                Alcotest.(check bool) "count" true (member "verifiers" b = `Int 1)
            | _ -> Alcotest.fail "one bundle");
            (match member "sinks" doc with
            | `List [ s ] ->
                check_str "sink state" "healthy" (member "state" s);
                check_str "sink type" "kafka" (member "type" s)
            | _ -> Alcotest.fail "one sink");
            (* the token never appears in the document *)
            Alcotest.(check bool)
              "no token" false
              (contains (Yojson.Safe.to_string doc) "admin-token");
            Lwt.return_unit) );
    ( "counter reset is not a negative rate",
      `Quick,
      fun () ->
        let f = new_fake () in
        f.metrics <- Some (metrics_text ~verify_allowed:1000 ());
        with_fakes [ f ] (fun r ->
            let* _ = C.Fleet.poll_once ~now:100. r.ctx in
            f.metrics <- Some (metrics_text ~verify_allowed:50 ());
            let* doc = C.Fleet.poll_once ~now:110. r.ctx in
            Alcotest.(check bool)
              "rate after reset" true
              (member "verifies_per_second" (verifier doc "haltsql-1") = `Float 5.);
            Lwt.return_unit) );
    ( "bundle drift",
      `Quick,
      fun () ->
        let a = new_fake () and b = new_fake () and c = new_fake () in
        b.status <- Some (status_doc ~version:"1.3.0" ~revision:"sha256:old" ());
        with_fakes [ a; b; c ] (fun r ->
            let* doc = C.Fleet.poll_once r.ctx in
            (match member "bundles" doc with
            | `List [ bd ] ->
                Alcotest.(check bool) "drift" true (member "in_sync" bd = `Bool false);
                check_str "majority version" "1.4.0" (member "version" bd);
                Alcotest.(check bool) "3 verifiers" true (member "verifiers" bd = `Int 3);
                Alcotest.(check int) "2 versions" 2 (list_len (member "versions" bd))
            | _ -> Alcotest.fail "one bundle source");
            b.status <- Some (status_doc ());
            let* doc = C.Fleet.poll_once r.ctx in
            (match member "bundles" doc with
            | `List [ bd ] ->
                Alcotest.(check bool) "in sync" true (member "in_sync" bd = `Bool true)
            | _ -> Alcotest.fail "one bundle source");
            Lwt.return_unit) );
    ( "sink buffering",
      `Quick,
      fun () ->
        let a = new_fake () and b = new_fake () in
        let sink = "kafka://k1:9093/audit" in
        b.status <- Some (status_doc ~sinks:[ (sink, "kafka", false) ] ());
        b.ready <-
          ( 503,
            `Assoc
              [
                ("status", `String "not_ready");
                ("policies", `Int 1);
                ("unhealthy_audit_sinks", `List [ `String sink ]);
              ] );
        b.metrics <- Some (metrics_text ~buffered:[ (sink, 1204) ] ());
        with_fakes [ a; b ] (fun r ->
            let* _ = C.Fleet.poll_once ~now:10. r.ctx in
            b.metrics <- Some (metrics_text ~buffered:[ (sink, 300) ] ());
            let* doc = C.Fleet.poll_once ~now:20. r.ctx in
            let vb = verifier doc "haltsql-2" in
            check_str "state" "buffering" (member "state" vb);
            Alcotest.(check bool)
              "unhealthy" true
              (member "unhealthy_sinks" vb = `List [ `String sink ]);
            Alcotest.(check bool) "buffered" true (member "buffered_records" vb = `Int 300);
            Alcotest.(check bool)
              "note mentions sink" true
              (contains (str_of (member "note" vb)) sink);
            check_str "other ready" "ready" (member "state" (verifier doc "haltsql-1"));
            (match member "sinks" doc with
            | `List [ s ] ->
                check_str "group state" "buffering" (member "state" s);
                Alcotest.(check bool) "2 verifiers" true (member "verifiers" s = `Int 2);
                Alcotest.(check bool)
                  "peak" true
                  (member "peak_buffered_records" s = `Int 1204);
                Alcotest.(check bool)
                  "unhealthy verifiers" true
                  (member "unhealthy_verifiers" s = `List [ `String "haltsql-2" ])
            | _ -> Alcotest.fail "one sink target");
            Lwt.return_unit) );
    ( "restart pending and not ready",
      `Quick,
      fun () ->
        let a = new_fake () and b = new_fake () and c = new_fake () in
        a.status <- Some (status_doc ~restart_pending:true ());
        b.ready <- (503, `Assoc [ ("status", `String "not_ready"); ("policies", `Int 0) ]);
        c.ready <-
          (503, `Assoc [ ("status", `String "not_ready"); ("draining", `Bool true) ]);
        with_fakes [ a; b; c ] (fun r ->
            let* doc = C.Fleet.poll_once r.ctx in
            let va = verifier doc "haltsql-1" in
            check_str "restart pending" "restart_pending" (member "state" va);
            Alcotest.(check bool) "flag" true (member "restart_pending" va = `Bool true);
            let vb = verifier doc "haltsql-2" in
            check_str "not ready" "not_ready" (member "state" vb);
            check_str "no policy note" "Not ready: no policy is loaded."
              (member "note" vb);
            check_str "draining" "Draining: shutting down."
              (member "note" (verifier doc "haltsql-3"));
            Lwt.return_unit) );
    ( "unreachable verifier",
      `Quick,
      fun () ->
        Lwt_main.run
          (let port = closed_port () in
           let cfg = fleet_config [ verifier_cfg "haltsql-9" (url port) ] in
           let* r = start ~background:false cfg in
           Lwt.finalize
             (fun () ->
               let* doc = C.Fleet.poll_once r.ctx in
               let v = verifier doc "haltsql-9" in
               check_str "state" "unreachable" (member "state" v);
               Alcotest.(check bool) "error" true (member "error" v <> `Null);
               Alcotest.(check bool)
                 "rate null" true
                 (member "verifies_per_second" v = `Null);
               Alcotest.(check bool) "version null" true (member "version" v = `Null);
               Lwt.return_unit)
             (fun () ->
               stop r;
               Lwt.return_unit)) );
    ( "wrong admin token is reported, state from readyz",
      `Quick,
      fun () ->
        let f = new_fake () in
        with_fakes
          ~tokens:[ ("haltsql-1", "wrong") ]
          [ f ]
          (fun r ->
            let* doc = C.Fleet.poll_once r.ctx in
            let v = verifier doc "haltsql-1" in
            check_str "state" "ready" (member "state" v);
            Alcotest.(check bool)
              "403 error" true
              (contains (str_of (member "error" v)) "HTTP 403");
            Alcotest.(check bool)
              "no secret" false
              (contains (Yojson.Safe.to_string doc) "wrong");
            Lwt.return_unit) );
    ( "mcp without admin status or metrics",
      `Quick,
      fun () ->
        let f = new_fake () in
        f.status <- None;
        f.metrics <- None;
        with_fakes
          ~kinds:[ ("haltsql-1", "mcp") ]
          [ f ]
          (fun r ->
            let* doc = C.Fleet.poll_once r.ctx in
            let v = verifier doc "haltsql-1" in
            check_str "kind" "mcp" (member "kind" v);
            check_str "state" "ready" (member "state" v);
            Alcotest.(check bool) "no error for 404" true (member "error" v = `Null);
            Alcotest.(check bool) "rate null" true (member "verifies_per_second" v = `Null);
            Alcotest.(check bool)
              "opa configured null" true
              (member "opa.configured" v = `Null);
            Lwt.return_unit) );
    ( "proxy TCP liveness",
      `Quick,
      fun () ->
        Lwt_main.run
          (let* s = serve (fun _ _ _ -> respond "{}") in
           let dead = closed_port () in
           let cfg =
             fleet_config
               [
                 verifier_cfg ~kind:"proxy" "proxy-1"
                   (Printf.sprintf "postgres://127.0.0.1:%d" s.port);
                 verifier_cfg ~kind:"proxy" "proxy-2"
                   (Printf.sprintf "tcp://127.0.0.1:%d" dead);
               ]
           in
           let* r = start ~background:false cfg in
           Lwt.finalize
             (fun () ->
               let* doc = C.Fleet.poll_once r.ctx in
               check_str "up" "ready" (member "state" (verifier doc "proxy-1"));
               check_str "down" "unreachable" (member "state" (verifier doc "proxy-2"));
               Lwt.return_unit)
             (fun () ->
               stop r;
               stop_server s;
               Lwt.return_unit)) );
    ( "background loop fills the snapshot",
      `Quick,
      fun () ->
        let f = new_fake () in
        Lwt_main.run
          (let* port = start_fake f in
           let cfg =
             config
               ~extra:
                 [
                   ("verifiers", `List [ verifier_cfg "haltsql-1" (url port) ]);
                   ("fleet", `Assoc [ ("poll_seconds", `Int 1) ]);
                 ]
               ()
           in
           let* r = start cfg in
           Lwt.finalize
             (fun () ->
               let rec wait n =
                 match r.ctx.fleet with
                 | Some _ -> Lwt.return_unit
                 | None when n = 0 -> Alcotest.fail "no fleet snapshot after 5 s"
                 | None ->
                     let* () = Lwt_unix.sleep 0.1 in
                     wait (n - 1)
               in
               let* () = wait 50 in
               let* _, doc = get r "/api/v1/fleet" in
               check_str "state" "ready" (member "state" (verifier doc "haltsql-1"));
               Lwt.return_unit)
             (fun () ->
               stop r;
               stop_fake f;
               Lwt.return_unit)) );
  ]

(* ---- restarts ---- *)

type kube = {
  mutable requests : (Cohttp.Code.meth * string * Cohttp.Header.t * string) list;
  mutable answer : int * string;
}

let start_kube k =
  serve (fun _conn req body ->
      let* b = Cohttp_lwt.Body.to_string body in
      k.requests <-
        ( Cohttp.Request.meth req,
          Uri.path (Cohttp.Request.uri req),
          Cohttp.Request.headers req,
          b )
        :: k.requests;
      let code, resp = k.answer in
      respond ~status:(Cohttp.Code.status_of_code code) resp)

let token_file () =
  let d = temp_dir "console-k8s" in
  let p = Filename.concat d "token" in
  Out_channel.with_open_bin p (fun oc -> output_string oc "sa-token-123\n");
  p

let with_kube ?role ?(workload = Some "deployment/haltsql-1") f =
  let k = { requests = []; answer = (200, "{}") } in
  let fake = new_fake () in
  Lwt_main.run
    (let* ks = start_kube k in
     let* port = start_fake fake in
     let kubernetes =
       `Assoc
         [
           ("namespace", `String "haltsql");
           ("api", `String (url ks.port));
           ("token_file", `String (token_file ()));
           ("ca_file", `String "/nonexistent/ca.crt");
         ]
     in
     let cfg =
       fleet_config ?role ~kubernetes [ verifier_cfg ?workload "haltsql-1" (url port) ]
     in
     let* r = start ~background:false cfg in
     Lwt.finalize
       (fun () -> f r k)
       (fun () ->
         stop r;
         stop_server ks;
         stop_fake fake;
         Lwt.return_unit))

let activity_actions r =
  let* _, a = get r "/api/v1/activity?action=fleet.restart" in
  Lwt.return (match member "entries" a with `List l -> l | _ -> [])

let restart_tests =
  [
    ( "restart patches the deployment",
      `Quick,
      fun () ->
        with_kube (fun r k ->
            let* code, body =
              post r "/api/v1/fleet/haltsql-1/restart"
                (`Assoc [ ("reason", `String "CASE-1 sinks changed") ])
            in
            check_status "restart" 200 (code, body);
            check_str "verifier" "haltsql-1" (member "verifier" body);
            check_str "workload" "deployment/haltsql-1" (member "workload" body);
            Alcotest.(check bool) "restarted_at" true (member "restarted_at" body <> `Null);
            (match k.requests with
            | [ (meth, path, headers, b) ] ->
                Alcotest.(check bool) "PATCH" true (meth = `PATCH);
                Alcotest.(check string)
                  "path" "/apis/apps/v1/namespaces/haltsql/deployments/haltsql-1" path;
                Alcotest.(check (option string))
                  "content-type" (Some "application/strategic-merge-patch+json")
                  (Cohttp.Header.get headers "content-type");
                Alcotest.(check (option string))
                  "bearer" (Some "Bearer sa-token-123")
                  (Cohttp.Header.get headers "authorization");
                let j = Yojson.Safe.from_string b in
                Alcotest.(check bool)
                  "annotation" true
                  (match member "spec.template.metadata.annotations" j with
                  | `Assoc [ ("kubectl.kubernetes.io/restartedAt", `String t) ] ->
                      `String t = member "restarted_at" body
                  | _ -> false)
            | l ->
                Alcotest.failf "expected one Kubernetes request, got %d" (List.length l));
            let* entries = activity_actions r in
            (match entries with
            | [ e ] ->
                check_str "reason" "CASE-1 sinks changed" (member "reason" e);
                check_str "target" "haltsql-1" (member "target" e);
                check_str "result" "ok" (member "detail.result" e)
            | _ -> Alcotest.fail "one activity entry");
            Lwt.return_unit) );
    ( "statefulset via header reason",
      `Quick,
      fun () ->
        with_kube ~workload:(Some "sts/haltsql-1") (fun r k ->
            let* code, body =
              post ~reason:"rotate" r "/api/v1/fleet/haltsql-1/restart" (`Assoc [])
            in
            check_status "restart" 200 (code, body);
            (match k.requests with
            | [ (_, path, _, _) ] ->
                Alcotest.(check string)
                  "path" "/apis/apps/v1/namespaces/haltsql/statefulsets/haltsql-1" path
            | _ -> Alcotest.fail "one request");
            Lwt.return_unit) );
    ( "permissions and reason",
      `Quick,
      fun () ->
        with_kube ~role:"analyst" (fun r k ->
            let* res = post ~reason:"x" r "/api/v1/fleet/haltsql-1/restart" (`Assoc []) in
            check_status "analyst" 403 res;
            check_str "code" "FORBIDDEN" (member "error.code" (snd res));
            Alcotest.(check int) "no request" 0 (List.length k.requests);
            Lwt.return_unit);
        with_kube (fun r k ->
            let* res = post r "/api/v1/fleet/haltsql-1/restart" (`Assoc []) in
            check_status "no reason" 403 res;
            check_str "code" "REASON_REQUIRED" (member "error.code" (snd res));
            let* res =
              post r "/api/v1/fleet/haltsql-1/restart"
                (`Assoc [ ("reason", `String " ") ])
            in
            check_str "blank reason" "REASON_REQUIRED" (member "error.code" (snd res));
            Alcotest.(check int) "no request" 0 (List.length k.requests);
            Lwt.return_unit) );
    ( "unknown verifier, missing workload, missing kubernetes",
      `Quick,
      fun () ->
        with_kube (fun r _ ->
            let* res = post ~reason:"x" r "/api/v1/fleet/nope/restart" (`Assoc []) in
            check_status "unknown" 404 res;
            Lwt.return_unit);
        with_kube ~workload:None (fun r _ ->
            let* res = post ~reason:"x" r "/api/v1/fleet/haltsql-1/restart" (`Assoc []) in
            check_status "no workload" 503 res;
            check_str "code" "NOT_CONFIGURED" (member "error.code" (snd res));
            Lwt.return_unit);
        with_kube ~workload:(Some "daemonset/x") (fun r _ ->
            let* res = post ~reason:"x" r "/api/v1/fleet/haltsql-1/restart" (`Assoc []) in
            check_status "bad workload" 503 res;
            Lwt.return_unit);
        with_fakes
          ~workloads:[ ("haltsql-1", "deployment/haltsql-1") ]
          [ new_fake () ]
          (fun r ->
            let* res = post ~reason:"x" r "/api/v1/fleet/haltsql-1/restart" (`Assoc []) in
            check_status "no kubernetes" 503 res;
            check_str "code" "NOT_CONFIGURED" (member "error.code" (snd res));
            Lwt.return_unit) );
    ( "Kubernetes API error is 502 without secrets",
      `Quick,
      fun () ->
        with_kube (fun r k ->
            k.answer <-
              ( 403,
                {|{"kind":"Status","reason":"Forbidden","message":"User system:serviceaccount:x cannot patch sa-token-123"}|}
              );
            let* code, body =
              post ~reason:"x" r "/api/v1/fleet/haltsql-1/restart" (`Assoc [])
            in
            check_status "upstream" 502 (code, body);
            check_str "code" "UPSTREAM" (member "error.code" body);
            let msg = str_of (member "error.message" body) in
            Alcotest.(check bool)
              "status in message" true
              (contains msg "HTTP 403 (Forbidden)");
            Alcotest.(check bool) "no token" false (contains msg "sa-token-123");
            let* entries = activity_actions r in
            (match entries with
            | [ e ] -> check_str "logged error" "error" (member "detail.result" e)
            | _ -> Alcotest.fail "one activity entry");
            Lwt.return_unit) );
  ]

let () =
  Alcotest.run "console-fleet"
    [ ("prom", prom_tests); ("poll", poll_tests); ("restart", restart_tests) ]
