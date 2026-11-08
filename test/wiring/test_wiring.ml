(* End-to-end wiring of haltsql-server's enterprise features, through the REAL
   haltsql-server and haltsql binaries (HALTSQL_SERVER_BIN, HALTSQL_BIN set by
   dune), configured only through config files, against real software:

   - admin API (GET /v1/admin/status, /v1/admin/report fed from the audit path),
     authorization by server.admin.callers, reload, and the `haltsql report` /
     `haltsql audit verify` commands on the server's audit file (no Docker);
   - OPA (openpolicyagent/opa, examples/opa) after verify: E_EXTERNAL_POLICY,
     audited, metrics, on_error deny when OPA is down;
   - an OCI bundle_source (registry:2), pushed with `haltsql bundle push --oci`:
     startup, update by polling, a bundle signed with the wrong key rejected (last
     good kept), restart from the verified cache with the registry down, and fail
     closed at startup without a cache; a bundle lacking a policy named by
     policy_from_groups fails startup, and on a running server is rejected with
     the last good set kept;
   - a Kafka audit sink (apache/kafka, KRaft) plugged into the audit path: records
     consumed with kafka-console-consumer, hash chain intact, /metrics and
     /readyz, fail closed while the broker is paused;
   - an elasticsearch audit sink (opensearchproject/opensearch) as the only sink:
     every verdict is indexed and queried back.

   Host ports 18400-18409; containers are named haltsql-wiring-*. Docker tests
   skip with a message when Docker is unavailable (or HALTSQL_SKIP_DOCKER=1). *)

module Http = Haltsql_cloud.Http

let run = Lwt_main.run
let server_bin () = Sys.getenv "HALTSQL_SERVER_BIN"
let cli_bin () = Sys.getenv "HALTSQL_BIN"
let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))

let contains s sub =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  n = 0 || go 0

let member k = function
  | `Assoc kv -> Option.value (List.assoc_opt k kv) ~default:`Null
  | _ -> `Null

let str = function `String s -> s | j -> Yojson.Safe.to_string j

let int = function
  | `Int i -> i
  | j -> Alcotest.failf "not an int: %s" (Yojson.Safe.to_string j)

let write_file path s = Out_channel.with_open_bin path (fun oc -> output_string oc s)
let read_file path = In_channel.with_open_bin path In_channel.input_all
let tmpdir prefix = Filename.temp_dir ("haltsql-wiring-" ^ prefix) ""

let rec reap pid =
  match Unix.waitpid [] pid with
  | _, st -> st
  | exception Unix.Unix_error (Unix.EINTR, _, _) -> reap pid

(* ---- processes ---- *)

let run_cmd ?(env = []) bin args =
  let env = Array.append (Array.of_list env) (Unix.environment ()) in
  let ic, oc, ec = Unix.open_process_args_full bin (Array.of_list (bin :: args)) env in
  close_out oc;
  let out = In_channel.input_all ic and err = In_channel.input_all ec in
  let code =
    match Unix.close_process_full (ic, oc, ec) with
    | Unix.WEXITED c -> c
    | Unix.WSIGNALED _ | Unix.WSTOPPED _ -> 255
  in
  (code, out, err)

let cli args = run_cmd (cli_bin ()) args

let cli_ok args =
  match cli args with
  | 0, out, _ -> out
  | c, out, err ->
      Alcotest.failf "haltsql %s: exit %d\n%s%s" (String.concat " " args) c out err

type server = { pid : int; port : int; log : string; dir : string }

let base port = Printf.sprintf "http://127.0.0.1:%d" port

let request ?token ?body ?(meth = `GET) port path =
  let headers =
    (match token with Some t -> [ ("authorization", "Bearer " ^ t) ] | None -> [])
    @ match body with Some _ -> [ ("content-type", "application/json") ] | None -> []
  in
  match
    run (Http.request ~timeout:20. ~headers ?body meth (Uri.of_string (base port ^ path)))
  with
  | Ok r -> r
  | Error e -> Alcotest.failf "%s: %s" path e

let starts = ref 0

let start_server ~dir ~port config =
  let cfg = Filename.concat dir "config.yaml" in
  write_file cfg config;
  incr starts;
  let log = Filename.concat dir (Printf.sprintf "server-%d.log" !starts) in
  let fd = Unix.openfile log [ O_WRONLY; O_CREAT; O_APPEND ] 0o600 in
  let bin = server_bin () in
  let pid = Unix.create_process bin [| bin; "--config"; cfg |] Unix.stdin fd fd in
  Unix.close fd;
  { pid; port; log; dir }

let stop_server s =
  (try Unix.kill s.pid Sys.sigterm with Unix.Unix_error _ -> ());
  ignore (reap s.pid)

let wait_until ?(timeout = 30.) what f =
  let deadline = Unix.gettimeofday () +. timeout in
  let rec loop () =
    if f () then ()
    else if Unix.gettimeofday () > deadline then Alcotest.failf "timed out: %s" what
    else (
      Unix.sleepf 0.25;
      loop ())
  in
  loop ()

let healthy s =
  match
    run (Http.request ~timeout:2. `GET (Uri.of_string (base s.port ^ "/healthz")))
  with
  | Ok { status = 200; _ } -> true
  | _ -> false

let wait_started s =
  let deadline = Unix.gettimeofday () +. 60. in
  let rec loop () =
    if healthy s then ()
    else
      match Unix.waitpid [ Unix.WNOHANG ] s.pid with
      | p, _ when p = s.pid ->
          Alcotest.failf "server exited during startup:\n%s" (read_file s.log)
      | _ ->
          if Unix.gettimeofday () > deadline then
            Alcotest.failf "server did not start:\n%s" (read_file s.log)
          else (
            Unix.sleepf 0.2;
            loop ())
      | exception Unix.Unix_error (Unix.EINTR, _, _) -> loop ()
  in
  loop ()

let with_server ~dir ~port config f =
  let s = start_server ~dir ~port config in
  Fun.protect
    ~finally:(fun () -> stop_server s)
    (fun () ->
      wait_started s;
      f s)

(* Exit code of a server that must fail at startup. *)
let expect_startup_failure ~dir ~port config =
  let s = start_server ~dir ~port config in
  let deadline = Unix.gettimeofday () +. 90. in
  let rec loop () =
    match Unix.waitpid [ Unix.WNOHANG ] s.pid with
    | p, Unix.WEXITED c when p = s.pid -> c
    | p, _ when p = s.pid -> 255
    | _ ->
        if Unix.gettimeofday () > deadline then begin
          stop_server s;
          Alcotest.failf "server did not fail at startup:\n%s" (read_file s.log)
        end
        else (
          Unix.sleepf 0.2;
          loop ())
    | exception Unix.Unix_error (Unix.EINTR, _, _) -> loop ()
  in
  let code = loop () in
  (code, read_file s.log)

let verify ?(token = "agent-token") port sql =
  let r =
    request ~token ~meth:`POST
      ~body:(Yojson.Safe.to_string (`Assoc [ ("sql", `String sql) ]))
      port "/v1/verify"
  in
  (r.status, try Yojson.Safe.from_string r.body with _ -> `Null)

let codes v =
  match member "reasons" v with
  | `List rs -> List.map (fun r -> str (member "code" r)) rs
  | _ -> []

(* ---- fixtures ---- *)

let policy ?(mode = "enforce") ?(extra_columns = []) name =
  Printf.sprintf
    {|apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: %s }
search_path: [app]
statements: { allow: [select] }
mode: %s
tables:
  app.orders: { columns: [%s] }
  app.invoices: { columns: [id, amount] }
|}
    name mode
    (String.concat ", " ([ "id"; "total_cents" ] @ extra_columns))

let tokens_yaml tokens =
  String.concat "\n"
    (List.map
       (fun (name, tok, pol) ->
         Printf.sprintf "      - { name: %s, token_sha256: %s, policy: %s }" name
           (sha256_hex tok) pol)
       tokens)

(* ---- docker ---- *)

let docker_skip_reason =
  lazy
    (if Sys.getenv_opt "HALTSQL_SKIP_DOCKER" = Some "1" then Some "HALTSQL_SKIP_DOCKER=1"
     else match Docker_util.available () with Ok () -> None | Error e -> Some e)

let docker_test name f () =
  match Lazy.force docker_skip_reason with
  | Some why ->
      Printf.printf "SKIP (%s needs Docker): %s\n%!" name why;
      Alcotest.skip ()
  | None -> Fun.protect ~finally:Docker_util.cleanup f

let ok_or_fail = function Ok x -> x | Error e -> Alcotest.fail e

let docker args =
  match Docker_util.run_capture args with
  | Ok s -> s
  | Error e -> Alcotest.failf "docker %s: %s" (String.concat " " args) e

(* ======================================================================= *)
(* admin API, report feed, CLI commands (no Docker)                        *)

let admin_port = 18400

let admin_config ~dir ~enabled =
  Printf.sprintf
    {|apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:%d
  auth:
    tokens:
%s
  admin:
    enabled: %b
    callers: [token:ops]
    report_window: 1h
    max_tracked_queries: 100
policies:
  - path: %s/shadow.yaml
audit:
  sinks:
    - { type: file, path: %s/audit.jsonl }
  log_raw_sql: true
|}
    admin_port
    (tokens_yaml [ ("ops", "ops-token", "shadow"); ("agent", "agent-token", "shadow") ])
    enabled dir dir

let admin_api () =
  let dir = tmpdir "admin" in
  write_file (Filename.concat dir "shadow.yaml") (policy ~mode:"shadow" "shadow");
  with_server ~dir ~port:admin_port (admin_config ~dir ~enabled:true) (fun s ->
      let p = s.port in
      Alcotest.(check int) "status: no token" 401 (request p "/v1/admin/status").status;
      Alcotest.(check int)
        "status: not an admin caller" 403
        (request ~token:"agent-token" p "/v1/admin/status").status;
      Alcotest.(check int)
        "report: not an admin caller" 403
        (request ~token:"agent-token" p "/v1/admin/report").status;
      let r = request ~token:"ops-token" p "/v1/admin/status" in
      Alcotest.(check int) "status: admin" 200 r.status;
      let st = Yojson.Safe.from_string r.body in
      (match member "policies" st with
      | `List [ pol ] ->
          Alcotest.(check string) "policy" "shadow" (str (member "name" pol));
          Alcotest.(check string) "mode" "shadow" (str (member "mode" pol));
          Alcotest.(check string) "origin" "config" (str (member "origin" pol))
      | j -> Alcotest.failf "policies: %s" (Yojson.Safe.to_string j));
      (match member "audit_sinks" st with
      | `List [ sink ] ->
          Alcotest.(check bool) "sink healthy" true (member "healthy" sink = `Bool true)
      | j -> Alcotest.failf "audit_sinks: %s" (Yojson.Safe.to_string j));
      (* shadow-mode traffic *)
      List.iter
        (fun sql ->
          let status, v = verify p sql in
          Alcotest.(check int) ("verify " ^ sql) 200 status;
          Alcotest.(check bool) "shadow: allowed" true (member "allowed" v = `Bool true))
        [
          "SELECT id, total_cents FROM orders";
          "SELECT email FROM orders";
          "SELECT email FROM orders WHERE id = 2";
          "SELECT id FROM customers";
        ];
      let r = request ~token:"ops-token" p "/v1/admin/report?since=1h" in
      Alcotest.(check int) "report: 200" 200 r.status;
      let rep = Yojson.Safe.from_string r.body in
      Alcotest.(check int) "tracked records" 4 (int (member "tracked_records" rep));
      Alcotest.(check bool)
        "column denial reported" true
        (contains r.body "E_COLUMN_DENIED");
      Alcotest.(check bool)
        "table denial reported" true
        (contains r.body "E_TABLE_DENIED");
      Alcotest.(check int)
        "report: unknown parameter" 400
        (request ~token:"ops-token" p "/v1/admin/report?nope=1").status;
      let m = (request p "/metrics").body in
      Alcotest.(check bool)
        "admin metric" true
        (contains m "haltsql_admin_requests_total{endpoint=\"report\",result=\"ok\"} 2");
      Alcotest.(check bool)
        "forbidden metric" true
        (contains m
           "haltsql_admin_requests_total{endpoint=\"status\",result=\"forbidden\"} 1");
      (* server.admin is reloadable: disable it and SIGHUP *)
      write_file (Filename.concat dir "config.yaml") (admin_config ~dir ~enabled:false);
      Unix.kill s.pid Sys.sighup;
      wait_until "admin disabled after reload" (fun () ->
          (request ~token:"ops-token" p "/v1/admin/status").status = 404));
  (* the CLI commands read the server's audit file *)
  let audit = Filename.concat dir "audit.jsonl" in
  let out = cli_ok [ "audit"; "verify"; audit ] in
  Alcotest.(check bool) "audit verify: ok" true (contains out "OK");
  let out = cli_ok [ "report"; audit; "--format"; "json" ] in
  Alcotest.(check bool) "report: column denial" true (contains out "E_COLUMN_DENIED");
  (* tamper with the file: audit verify exits 1 *)
  let lines = String.split_on_char '\n' (read_file audit) in
  let tampered =
    List.map
      (fun l ->
        if contains l "customers" then
          Str.global_replace (Str.regexp_string "customers") "suppliers" l
        else l)
      lines
  in
  write_file audit (String.concat "\n" tampered);
  let code, _, _ = cli [ "audit"; "verify"; audit ] in
  Alcotest.(check int) "audit verify: tampered" 1 code

(* ======================================================================= *)
(* OPA                                                                     *)

let opa_port = 18401
let opa_server_port = 18404
let opa_image = "openpolicyagent/opa:1.10.1"
let opa_container = "haltsql-wiring-opa"

let examples_opa () =
  (* dune copies examples/opa next to the test (source_tree dep) *)
  let candidates = [ "../../examples/opa"; "examples/opa" ] in
  match List.find_opt Sys.file_exists candidates with
  | Some d -> if Filename.is_relative d then Filename.concat (Sys.getcwd ()) d else d
  | None -> Alcotest.fail "examples/opa not found"

let opa_check () =
  ok_or_fail (Docker_util.ensure_image opa_image);
  ok_or_fail
    (Docker_util.start ~name:opa_container
       [
         "-p";
         Printf.sprintf "127.0.0.1:%d:8181" opa_port;
         "-v";
         examples_opa () ^ ":/policies:ro";
         opa_image;
         "run";
         "--server";
         "--addr";
         "0.0.0.0:8181";
         "/policies";
       ]);
  wait_until ~timeout:60. "opa to start" (fun () ->
      match
        run
          (Http.request ~timeout:2. `GET
             (Uri.of_string (base opa_port ^ "/health?bundles")))
      with
      | Ok { status = 200; _ } -> true
      | _ -> false);
  let dir = tmpdir "opa" in
  write_file (Filename.concat dir "shop.yaml") (policy "shop");
  let config =
    Printf.sprintf
      {|apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:%d
  auth:
    tokens:
%s
policies:
  - path: %s/shop.yaml
audit:
  sinks:
    - { type: file, path: %s/audit.jsonl }
opa:
  url: http://127.0.0.1:%d
  decision_path: haltsql/decision
  timeout_ms: 2000
|}
      opa_server_port
      (tokens_yaml [ ("agent", "agent-token", "shop") ])
      dir dir opa_port
  in
  with_server ~dir ~port:opa_server_port config (fun s ->
      let p = s.port in
      let status, v = verify p "SELECT id FROM invoices" in
      Alcotest.(check int) "invoices: 200" 200 status;
      Alcotest.(check bool) "invoices: denied" false (member "allowed" v = `Bool true);
      Alcotest.(check (list string))
        "invoices: OPA code" [ "E_EXTERNAL_POLICY" ] (codes v);
      Alcotest.(check bool)
        "OPA reason text" true
        (contains (Yojson.Safe.to_string v) "app.invoices");
      let _, v = verify p "SELECT id FROM orders" in
      Alcotest.(check bool) "orders: allowed" true (member "allowed" v = `Bool true);
      let _, v = verify p "SELECT secret FROM vault" in
      Alcotest.(check bool) "HaltSQL denial" false (member "allowed" v = `Bool true);
      Alcotest.(check bool)
        "OPA not asked for a HaltSQL denial" false
        (List.mem "E_EXTERNAL_POLICY" (codes v));
      let audit = read_file (Filename.concat dir "audit.jsonl") in
      Alcotest.(check bool) "audited" true (contains audit "E_EXTERNAL_POLICY");
      let m = (request p "/metrics").body in
      List.iter
        (fun o ->
          Alcotest.(check bool)
            ("metric " ^ o) true
            (contains m
               (Printf.sprintf "haltsql_opa_decisions_total{outcome=\"%s\"} 1" o)))
        [ "denied"; "allowed"; "skipped" ];
      Alcotest.(check bool)
        "reason metric" true
        (contains m "haltsql_reasons_total{code=\"E_EXTERNAL_POLICY\"} 1");
      (* OPA down: on_error deny *)
      ignore (docker [ "stop"; "-t"; "1"; opa_container ]);
      let _, v = verify p "SELECT id FROM orders" in
      Alcotest.(check bool) "OPA down: denied" false (member "allowed" v = `Bool true);
      Alcotest.(check (list string)) "OPA down: code" [ "E_EXTERNAL_POLICY" ] (codes v);
      Alcotest.(check bool)
        "error_denied metric" true
        (contains (request p "/metrics").body
           "haltsql_opa_decisions_total{outcome=\"error_denied\"} 1"))

(* ======================================================================= *)
(* OCI bundle source                                                       *)

let registry_port = 18402
let bundle_server_port = 18405
let registry_container = "haltsql-wiring-registry"
let reference = Printf.sprintf "localhost:%d/haltsql/policies:prod" registry_port

let build_and_push ~dir ~key ~version ~extra_columns =
  let pol = Filename.concat dir (Printf.sprintf "shop-%s.yaml" version) in
  write_file pol (policy ~extra_columns "shop");
  let bundle = Filename.concat dir (Printf.sprintf "prod-%s.haltsqlbundle" version) in
  ignore
    (cli_ok
       [
         "bundle";
         "build";
         pol;
         "--name";
         "prod";
         "--bundle-version";
         version;
         "-o";
         bundle;
       ]);
  ignore (cli_ok [ "bundle"; "sign"; bundle; "--key"; key ]);
  ignore (cli_ok [ "bundle"; "push"; "--oci"; reference; "--plain-http"; bundle ])

let bundle_config ~dir ~cache ~key =
  Printf.sprintf
    {|apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:%d
  auth:
    tokens:
%s
  admin: { enabled: true, callers: [token:agent] }
policies:
  - bundle_source: { oci: %s, plain_http: true }
    public_keys: [%s.pub]
    name_prefix: remote-
    poll_interval_s: 10
    cache_dir: %s
audit:
  sinks:
    - { type: file, path: %s/audit.jsonl }
|}
    bundle_server_port
    (tokens_yaml [ ("agent", "agent-token", "remote-shop") ])
    reference key cache dir

let source_status p =
  let r = request ~token:"agent-token" p "/v1/admin/status" in
  Alcotest.(check int) "status" 200 r.status;
  match member "bundle_sources" (Yojson.Safe.from_string r.body) with
  | `List [ s ] -> s
  | j -> Alcotest.failf "bundle_sources: %s" (Yojson.Safe.to_string j)

let current_version p = str (member "version" (member "current" (source_status p)))

let bundle_source () =
  ok_or_fail (Docker_util.ensure_image "registry:2");
  ok_or_fail
    (Docker_util.start ~name:registry_container
       [ "-p"; Printf.sprintf "127.0.0.1:%d:5000" registry_port; "registry:2" ]);
  wait_until "registry to start" (fun () ->
      match
        run (Http.request ~timeout:2. `GET (Uri.of_string (base registry_port ^ "/v2/")))
      with
      | Ok { status = 200; _ } -> true
      | _ -> false);
  let dir = tmpdir "bundle" in
  let key = Filename.concat dir "release.key" in
  let other = Filename.concat dir "other.key" in
  ignore (cli_ok [ "bundle"; "keygen"; "-o"; key ]);
  ignore (cli_ok [ "bundle"; "keygen"; "-o"; other ]);
  build_and_push ~dir ~key ~version:"1.0.0" ~extra_columns:[];
  let cache = Filename.concat dir "cache" in
  let config = bundle_config ~dir ~cache ~key in
  with_server ~dir ~port:bundle_server_port config (fun s ->
      let p = s.port in
      let r = request ~token:"agent-token" p "/v1/policies" in
      Alcotest.(check bool) "remote-shop loaded" true (contains r.body "remote-shop");
      Alcotest.(check string) "version 1.0.0" "1.0.0" (current_version p);
      let _, v = verify p "SELECT id FROM orders" in
      Alcotest.(check bool) "v1: allowed" true (member "allowed" v = `Bool true);
      let _, v = verify p "SELECT status FROM orders" in
      Alcotest.(check bool) "v1: status denied" false (member "allowed" v = `Bool true);
      (* a new signed version is picked up by polling and swapped in *)
      build_and_push ~dir ~key ~version:"1.1.0" ~extra_columns:[ "status" ];
      wait_until ~timeout:45. "bundle 1.1.0" (fun () -> current_version p = "1.1.0");
      let _, v = verify p "SELECT status FROM orders" in
      Alcotest.(check bool) "v1.1: status allowed" true (member "allowed" v = `Bool true);
      (* a bundle signed with an untrusted key is refused; the last good stays *)
      build_and_push ~dir ~key:other ~version:"1.2.0" ~extra_columns:[ "status"; "note" ];
      wait_until ~timeout:45. "signature refused" (fun () ->
          let st = source_status p in
          match member "last_error" st with
          | `Null -> false
          | e -> str (member "code" e) = "bundle_source_signature");
      Alcotest.(check string) "still 1.1.0" "1.1.0" (current_version p);
      let _, v = verify p "SELECT note FROM orders" in
      Alcotest.(check bool)
        "untrusted bundle not applied" false
        (member "allowed" v = `Bool true);
      Alcotest.(check bool)
        "bundle source metric" true
        (contains (request p "/metrics").body "haltsql_bundle_source_healthy{source="));
  (* registry down: a restart starts from the verified cache *)
  ignore (docker [ "stop"; "-t"; "1"; registry_container ]);
  with_server ~dir ~port:bundle_server_port config (fun s ->
      let st = source_status s.port in
      Alcotest.(check string)
        "from cache" "cache"
        (str (member "origin" (member "current" st)));
      Alcotest.(check string) "cached version" "1.1.0" (current_version s.port);
      let _, v = verify s.port "SELECT status FROM orders" in
      Alcotest.(check bool) "cached policy enforced" true (member "allowed" v = `Bool true));
  (* registry down and no cache: fail closed at startup *)
  let code, log =
    expect_startup_failure ~dir ~port:bundle_server_port
      (bundle_config ~dir ~cache:(Filename.concat dir "empty-cache") ~key)
  in
  Alcotest.(check int) "startup refused" 2 code;
  if not (contains log "no verified bundle is available") then
    Alcotest.failf "startup failure message missing (exit %d, %s):\n%s" code
      (String.concat " " (Array.to_list (Sys.readdir dir)))
      log

(* ---- policy_from_groups references re-checked after bundle sources ---- *)

let groups_reference = Printf.sprintf "localhost:%d/haltsql/groups:prod" registry_port

let push_policies ~dir ~key ~version ~extra_columns names =
  let files =
    List.map
      (fun n ->
        let f = Filename.concat dir (Printf.sprintf "%s-%s.yaml" n version) in
        write_file f (policy ~extra_columns n);
        f)
      names
  in
  let bundle = Filename.concat dir (Printf.sprintf "groups-%s.haltsqlbundle" version) in
  ignore
    (cli_ok
       (("bundle" :: "build" :: files)
       @ [ "--name"; "groups"; "--bundle-version"; version; "-o"; bundle ]));
  ignore (cli_ok [ "bundle"; "sign"; bundle; "--key"; key ]);
  ignore (cli_ok [ "bundle"; "push"; "--oci"; groups_reference; "--plain-http"; bundle ])

(* The OIDC issuer is never contacted: keys are fetched on the first token, and
   this test sends none. *)
let groups_config ~dir ~cache ~key =
  Printf.sprintf
    {|apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:%d
  auth:
    tokens:
%s
    oidc:
      - name: corp
        issuer: https://idp.haltsql.invalid/realms/corp
        audiences: [haltsql]
        policy_from_groups:
          claim: groups
          map:
            - { group: finance, policy: remote-billing }
          default: remote-shop
  admin: { enabled: true, callers: [token:agent] }
policies:
  - bundle_source: { oci: %s, plain_http: true }
    public_keys: [%s.pub]
    name_prefix: remote-
    poll_interval_s: 10
    cache_dir: %s
audit:
  sinks:
    - { type: file, path: %s/audit.jsonl }
|}
    bundle_server_port
    (tokens_yaml [ ("agent", "agent-token", "remote-shop") ])
    groups_reference key cache dir

let bundle_group_refs () =
  ok_or_fail (Docker_util.ensure_image "registry:2");
  ok_or_fail
    (Docker_util.start ~name:registry_container
       [ "-p"; Printf.sprintf "127.0.0.1:%d:5000" registry_port; "registry:2" ]);
  wait_until "registry to start" (fun () ->
      match
        run (Http.request ~timeout:2. `GET (Uri.of_string (base registry_port ^ "/v2/")))
      with
      | Ok { status = 200; _ } -> true
      | _ -> false);
  let dir = tmpdir "groups" in
  let key = Filename.concat dir "release.key" in
  ignore (cli_ok [ "bundle"; "keygen"; "-o"; key ]);
  (* startup: the bundle lacks remote-billing (named by policy_from_groups) *)
  push_policies ~dir ~key ~version:"1.0.0" ~extra_columns:[] [ "shop" ];
  let code, log =
    expect_startup_failure ~dir ~port:bundle_server_port
      (groups_config ~dir ~cache:(Filename.concat dir "cache-1") ~key)
  in
  Alcotest.(check int) "startup refused" 2 code;
  if
    not
      (contains log
         "policy_from_groups.map[0].policy) references policy \\\"remote-billing\\\", \
          which is not loaded")
  then Alcotest.failf "startup failure message missing (exit %d):\n%s" code log;
  (* a complete bundle starts; a later bundle that drops remote-billing is
     rejected and the last good set stays *)
  push_policies ~dir ~key ~version:"1.1.0" ~extra_columns:[] [ "shop"; "billing" ];
  with_server ~dir ~port:bundle_server_port
    (groups_config ~dir ~cache:(Filename.concat dir "cache-2") ~key)
    (fun s ->
      let p = s.port in
      Alcotest.(check string) "version 1.1.0" "1.1.0" (current_version p);
      push_policies ~dir ~key ~version:"1.2.0" ~extra_columns:[ "status" ] [ "shop" ];
      wait_until ~timeout:45. "bundle without remote-billing rejected" (fun () ->
          match member "last_error" (source_status p) with
          | `Null -> false
          | e -> contains (str (member "message" e)) "remote-billing");
      Alcotest.(check string) "still 1.1.0" "1.1.0" (current_version p);
      let status = request ~token:"agent-token" p "/v1/admin/status" in
      let names =
        match member "policies" (Yojson.Safe.from_string status.body) with
        | `List l -> List.map (fun j -> str (member "name" j)) l
        | j -> Alcotest.failf "policies: %s" (Yojson.Safe.to_string j)
      in
      Alcotest.(check (list string))
        "last good policies kept"
        [ "remote-shop"; "remote-billing" ]
        names;
      let _, v = verify p "SELECT status FROM orders" in
      Alcotest.(check bool)
        "rejected bundle not applied" false
        (member "allowed" v = `Bool true);
      Alcotest.(check bool)
        "reload error counted" true
        (contains (request p "/metrics").body
           "haltsql_policy_reload_total{result=\"error\"}"))

(* ======================================================================= *)
(* Kafka audit sink                                                        *)

let kafka_port = 18403
let kafka_server_port = 18406
let kafka_image = "apache/kafka:3.9.1"
let kafka_container = "haltsql-wiring-kafka"
let topic = "haltsql-audit"

let kafka_properties =
  String.concat "\n"
    [
      "process.roles=broker,controller";
      "node.id=1";
      "controller.quorum.voters=1@localhost:9093";
      Printf.sprintf "listeners=PLAINTEXT://:%d,CONTROLLER://:9093" kafka_port;
      Printf.sprintf "advertised.listeners=PLAINTEXT://127.0.0.1:%d" kafka_port;
      "controller.listener.names=CONTROLLER";
      "listener.security.protocol.map=PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT";
      "inter.broker.listener.name=PLAINTEXT";
      "log.dirs=/tmp/kraft-logs";
      "offsets.topic.replication.factor=1";
      "transaction.state.log.replication.factor=1";
      "transaction.state.log.min.isr=1";
      "num.partitions=1";
      "auto.create.topics.enable=false";
      "group.initial.rebalance.delay.ms=0";
      "";
    ]

let kafka_sh tool args =
  [ "exec"; kafka_container; "/opt/kafka/bin/" ^ tool; "--bootstrap-server" ]
  @ [ Printf.sprintf "localhost:%d" kafka_port ]
  @ args

let kafka_sink () =
  ok_or_fail (Docker_util.ensure_image kafka_image);
  let cfgdir = tmpdir "kafka-cfg" in
  let props = Filename.concat cfgdir "server.properties" in
  write_file props kafka_properties;
  (* Filename.temp_dir creates the directory 0700; the broker runs as the
     image's own user (appuser), which must be able to read the mounted
     properties file (no secrets in it). *)
  Unix.chmod cfgdir 0o755;
  Unix.chmod props 0o644;
  ok_or_fail
    (Docker_util.start ~name:kafka_container
       [
         "-p";
         Printf.sprintf "127.0.0.1:%d:%d" kafka_port kafka_port;
         "-v";
         cfgdir ^ ":/cfg:ro";
         "--entrypoint";
         "sh";
         kafka_image;
         "-c";
         "/opt/kafka/bin/kafka-storage.sh format --ignore-formatted -t \
          MkU3OEVBNTcwNTJENDM2Qk -c /cfg/server.properties && exec \
          /opt/kafka/bin/kafka-server-start.sh /cfg/server.properties";
       ]);
  wait_until ~timeout:120. "kafka to start" (fun () ->
      Result.is_ok (Docker_util.run_capture (kafka_sh "kafka-topics.sh" [ "--list" ])));
  ignore
    (docker
       (kafka_sh "kafka-topics.sh"
          [
            "--create"; "--topic"; topic; "--partitions"; "1"; "--replication-factor"; "1";
          ]));
  let dir = tmpdir "kafka" in
  write_file (Filename.concat dir "shop.yaml") (policy "shop");
  let config =
    Printf.sprintf
      {|apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:%d
  auth:
    tokens:
%s
policies:
  - path: %s/shop.yaml
audit:
  sinks:
    - type: kafka
      brokers: ["127.0.0.1:%d"]
      topic: %s
      batch: { flush_interval_ms: 50 }
|}
      kafka_server_port
      (tokens_yaml [ ("agent", "agent-token", "shop") ])
      dir kafka_port topic
  in
  with_server ~dir ~port:kafka_server_port config (fun s ->
      let p = s.port in
      List.iter
        (fun sql -> ignore (verify p sql))
        [
          "SELECT id FROM orders"; "SELECT secret FROM orders"; "SELECT id FROM invoices";
        ];
      let out =
        docker
          (kafka_sh "kafka-console-consumer.sh"
             [
               "--topic";
               topic;
               "--from-beginning";
               "--max-messages";
               "3";
               "--timeout-ms";
               "30000";
             ])
      in
      let records =
        String.split_on_char '\n' out
        |> List.filter (fun l -> String.length l > 0 && l.[0] = '{')
      in
      Alcotest.(check int) "3 records in Kafka" 3 (List.length records);
      (* the chain verifies: each prev_hash is the previous record's hash *)
      let hashes =
        List.map
          (fun l ->
            let j = Yojson.Safe.from_string l in
            (str (member "prev_hash" j), str (member "hash" j)))
          records
      in
      let rec chained = function
        | (_, h) :: ((p', _) :: _ as rest) -> h = p' && chained rest
        | _ -> true
      in
      Alcotest.(check bool) "chain links" true (chained hashes);
      Alcotest.(check string) "genesis" (String.make 64 '0') (fst (List.hd hashes));
      let tmp = Filename.concat dir "kafka.jsonl" in
      write_file tmp (String.concat "\n" records ^ "\n");
      ignore (cli_ok [ "audit"; "verify"; tmp ]);
      Alcotest.(check int) "readyz" 200 (request p "/readyz").status;
      Alcotest.(check bool)
        "stream sink metrics" true
        (contains (request p "/metrics").body
           "haltsql_audit_stream_sink_records_delivered");
      (* broker unreachable: fail closed (verify refused, /readyz 503) *)
      ignore (docker [ "pause"; kafka_container ]);
      Fun.protect
        ~finally:(fun () ->
          ignore (Docker_util.run_capture [ "unpause"; kafka_container ]))
        (fun () ->
          wait_until ~timeout:120. "sink fails closed" (fun () ->
              ignore (verify p "SELECT id FROM orders");
              (request p "/readyz").status = 503);
          let status, _ = verify p "SELECT id FROM orders" in
          Alcotest.(check int) "verify refused while failing" 503 status);
      wait_until ~timeout:120. "sink recovers" (fun () ->
          (request p "/readyz").status = 200);
      let status, _ = verify p "SELECT id FROM orders" in
      Alcotest.(check int) "verify after recovery" 200 status)

(* ======================================================================= *)
(* Elasticsearch-API audit sink as the only sink (real OpenSearch)          *)

let os_port = 18407
let os_server_port = 18408
let os_image = "opensearchproject/opensearch:2.17.1"
let os_container = "haltsql-wiring-opensearch"
let os_base = Printf.sprintf "http://127.0.0.1:%d" os_port

let os_get path =
  match run (Http.request ~timeout:10. `GET (Uri.of_string (os_base ^ path))) with
  | Ok r -> Some r
  | Error _ -> None

(* Only an elasticsearch sink (no stdout/file sink): every verdict must reach
   the cluster through the stream-sink path, never be silently dropped. *)
let opensearch_only_sink () =
  ok_or_fail (Docker_util.ensure_image os_image);
  let e k v = [ "-e"; k ^ "=" ^ v ] in
  ok_or_fail
    (Docker_util.start ~name:os_container
       ([ "-p"; Printf.sprintf "127.0.0.1:%d:9200" os_port ]
       @ e "discovery.type" "single-node"
       @ e "DISABLE_SECURITY_PLUGIN" "true"
       @ e "DISABLE_INSTALL_DEMO_CONFIG" "true"
       @ e "OPENSEARCH_JAVA_OPTS" "-Xms512m -Xmx512m"
       @ e "cluster.routing.allocation.disk.threshold_enabled" "false"
       @ [ os_image ]));
  wait_until ~timeout:240. "opensearch to start" (fun () ->
      match os_get "/_cluster/health" with
      | Some { status = 200; body; _ } ->
          let st = str (member "status" (Yojson.Safe.from_string body)) in
          st = "green" || st = "yellow"
      | _ -> false);
  let index = "haltsql-wiring-audit" in
  let dir = tmpdir "opensearch" in
  write_file (Filename.concat dir "shop.yaml") (policy "shop");
  let config =
    Printf.sprintf
      {|apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 127.0.0.1:%d
  auth:
    tokens:
%s
policies:
  - path: %s/shop.yaml
audit:
  sinks:
    - type: elasticsearch
      url: %s
      index: %s
      batch: { flush_interval_ms: 50 }
|}
      os_server_port
      (tokens_yaml [ ("agent", "agent-token", "shop") ])
      dir os_base index
  in
  with_server ~dir ~port:os_server_port config (fun s ->
      let p = s.port in
      let sqls =
        [
          "SELECT id FROM orders"; "SELECT secret FROM orders"; "SELECT id FROM invoices";
        ]
      in
      List.iter
        (fun sql ->
          let status, _ = verify p sql in
          Alcotest.(check int) ("verify " ^ sql) 200 status)
        sqls;
      let hits = ref [] in
      wait_until ~timeout:60. "3 audit documents in OpenSearch" (fun () ->
          ignore (os_get (Printf.sprintf "/%s/_refresh" index));
          match os_get (Printf.sprintf "/%s/_search?size=10" index) with
          | Some { status = 200; body; _ } -> (
              match member "hits" (member "hits" (Yojson.Safe.from_string body)) with
              | `List l when List.length l = 3 ->
                  hits := List.map (member "_source") l;
                  true
              | _ -> false)
          | _ -> false);
      let allowed =
        List.filter (fun j -> member "allowed" j = `Bool true) !hits |> List.length
      in
      Alcotest.(check int) "2 allowed, 1 denied (secret column)" 2 allowed;
      List.iter
        (fun j ->
          Alcotest.(check bool) "no raw SQL" true (member "sql" j = `Null);
          Alcotest.(check int) "sha256 hash" 64 (String.length (str (member "hash" j))))
        !hits;
      Alcotest.(check bool)
        "stream sink metrics" true
        (contains (request p "/metrics").body
           "haltsql_audit_stream_sink_records_delivered");
      Alcotest.(check int) "readyz" 200 (request p "/readyz").status)

let () =
  Mirage_crypto_rng_unix.use_default ();
  let slow n f = Alcotest.test_case n `Slow f in
  Alcotest.run "haltsql-server wiring"
    [
      ("admin", [ slow "admin API, report feed, CLI on the audit file" admin_api ]);
      ("opa", [ slow "OPA after verify (real OPA)" (docker_test "opa" opa_check) ]);
      ( "bundle_source",
        [
          slow "OCI bundle source (real registry)" (docker_test "bundle" bundle_source);
          slow "policy_from_groups refs re-checked after bundle_source (real registry)"
            (docker_test "bundle" bundle_group_refs);
        ] );
      ("kafka", [ slow "Kafka audit sink (real Kafka)" (docker_test "kafka" kafka_sink) ]);
      ( "elasticsearch",
        [
          slow "OpenSearch as the only audit sink (real OpenSearch)"
            (docker_test "elasticsearch" opensearch_only_sink);
        ] );
    ]
