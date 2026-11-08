(* Server wiring of the enterprise integrations (Integrations.install):

   - signed policy bundles: verified before parsing, name_prefix applied,
     policy references re-checked, duplicates refused, hot reload re-verifies
     (bundle and .sig are watched; a broken signature keeps the last good set);
   - secret providers: ${vault:...} resolved at startup (blocking) and on
     reload (async prefetch inside Lwt), errors never contain secret values;
   - OpenTelemetry: one span per verify request (traceparent honoured, no SQL
     exported) and mirrored metrics, against an in-process fake collector;
   - S3 audit sink: records uploaded to a fake S3, and fail-closed behaviour
     (503 AUDIT_UNAVAILABLE, /readyz not ready) once uploads fail.

   All network peers are in-process fakes on 127.0.0.1. *)

open Lwt.Syntax
open Haltsql_server
module Client = Cohttp_lwt_unix.Client
module Bundle = Haltsql_bundle

let tmpdir =
  let d =
    Filename.concat
      (Filename.get_temp_dir_name ())
      (Printf.sprintf "haltsql-integrations-test-%d" (Unix.getpid ()))
  in
  (try Unix.mkdir d 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  d

let tmp name = Filename.concat tmpdir name
let read_file f = In_channel.with_open_bin f In_channel.input_all
let write_file f s = Out_channel.with_open_bin f (fun oc -> output_string oc s)

let contains s sub =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  n = 0 || go 0

let run p = Lwt_main.run p
let sha = Auth.sha256_hex
let token = "integration-test-token"

let policy_of_yaml ?(columns = "[id, tenant_id, status]") ~name () =
  let f = tmp (name ^ ".policy.yaml") in
  write_file f
    (String.concat "\n"
       [
         "apiVersion: haltsql.dev/v1";
         "kind: Policy";
         "metadata: { name: " ^ name ^ " }";
         "dialect: postgres-17";
         "search_path: [app]";
         "statements: { allow: [select] }";
         "require_limit: { max: 100 }";
         "tenancy: { mode: bound, keys: { tenant: \"${ctx.tenant_id}\" } }";
         "tables:";
         "  app.orders:";
         "    columns: " ^ columns;
         "    tenant_column: tenant_id";
         "";
       ]);
  match Haltsql.Policy_load.of_file f with
  | Ok p -> p
  | Error e ->
      Alcotest.failf "policy: %s"
        (String.concat "; " (List.map Haltsql.Load_error.to_string e))

let key = lazy (Bundle.Key.generate ())
let other_key = lazy (Bundle.Key.generate ())
let pub k = Bundle.Key.public_to_base64 (Bundle.Key.public_of_secret (Lazy.force k))

(* Builds and signs a bundle holding [names], each policy at [version]. *)
let write_bundle ?(signer = key) ?columns ~path ~version names =
  let policies = List.map (fun n -> policy_of_yaml ?columns ~name:n ()) names in
  let bytes =
    match
      Bundle.build
        {
          name = "it-bundle";
          version;
          created_by = None;
          source = { url = None; commit = None };
        }
        ~policies ~catalogs:[]
    with
    | Ok b -> b
    | Error e -> Alcotest.failf "build: %s" (Bundle.error_to_string e)
  in
  write_file path bytes;
  write_file (path ^ ".sig")
    (Bundle.signatures_to_string [ Bundle.sign (Lazy.force signer) bytes ])

let config_file ?(extra = "") ~name ~bundles ~token_policy () =
  let f = tmp name in
  write_file f
    (String.concat "\n"
       ([
          "apiVersion: haltsql.dev/v1";
          "kind: Config";
          "server:";
          "  auth:";
          "    tokens:";
          Printf.sprintf "      - { name: agent, token_sha256: %s, policy: %s }"
            (sha token) token_policy;
          "policies:";
        ]
       @ List.map
           (fun (path, prefix) ->
             Printf.sprintf "  - { bundle: %s, public_keys: [%s]%s }" path (pub key)
               (match prefix with
               | Some p -> Printf.sprintf ", name_prefix: %s" p
               | None -> ""))
           bundles
       @ [ extra; "" ]));
  f

let sources f = { State.config_file = Some f; policy_files = []; overrides = Fun.id }

let load_ok f =
  match State.load (sources f) with
  | Ok c -> c
  | Error e -> Alcotest.failf "expected load to succeed: %s" (String.concat "; " e)

let load_err f =
  match State.load (sources f) with
  | Ok _ -> Alcotest.fail "expected load to fail"
  | Error e -> String.concat "\n" e

let check_contains what s sub =
  if not (contains s sub) then Alcotest.failf "%s: %S does not contain %S" what s sub

let () =
  Log.setup ~level:"error" ~format:"json";
  Integrations.install ()

(* ------------------------------------------------------------ bundles *)

let bundle_path = tmp "prod.haltsqlbundle"

let test_bundle_loads () =
  write_bundle ~path:bundle_path ~version:"1" [ "shop"; "billing" ];
  let f =
    config_file ~name:"b1.yaml"
      ~bundles:[ (bundle_path, Some "prod-") ]
      ~token_policy:"prod-shop" ()
  in
  let cfg = load_ok f in
  Alcotest.(check (list string))
    "prefixed names"
    [ "prod-shop"; "prod-billing" ]
    (List.map fst cfg.policies);
  Alcotest.(check (list string))
    "Policy.name carries the prefix"
    [ "prod-shop"; "prod-billing" ]
    (List.map (fun (_, (p : Haltsql.Policy.t)) -> p.name) cfg.policies);
  Alcotest.(check bool)
    "bundle and .sig are watched" true
    (List.mem bundle_path cfg.policy_files
    && List.mem (bundle_path ^ ".sig") cfg.policy_files)

let test_bundle_tampered () =
  write_bundle ~path:bundle_path ~version:"1" [ "shop" ];
  let bytes = Bytes.of_string (read_file bundle_path) in
  let i = Bytes.length bytes / 2 in
  Bytes.set bytes i (if Bytes.get bytes i = 'a' then 'b' else 'a');
  write_file bundle_path (Bytes.to_string bytes);
  let f =
    config_file ~name:"b2.yaml" ~bundles:[ (bundle_path, None) ] ~token_policy:"shop" ()
  in
  let e = load_err f in
  check_contains "tampered" e "signature"

let test_bundle_wrong_key () =
  write_bundle ~signer:other_key ~path:bundle_path ~version:"1" [ "shop" ];
  let f =
    config_file ~name:"b3.yaml" ~bundles:[ (bundle_path, None) ] ~token_policy:"shop" ()
  in
  check_contains "wrong key" (load_err f) "signature"

let test_bundle_missing_ref () =
  write_bundle ~path:bundle_path ~version:"1" [ "shop" ];
  let f =
    config_file ~name:"b4.yaml"
      ~bundles:[ (bundle_path, Some "prod-") ]
      ~token_policy:"prod-billing" ()
  in
  Alcotest.(check string)
    "missing reference"
    "token \"agent\" references policy \"prod-billing\", which is not loaded" (load_err f)

let test_bundle_duplicate () =
  write_bundle ~path:bundle_path ~version:"1" [ "shop" ];
  let second = tmp "second.haltsqlbundle" in
  write_bundle ~path:second ~version:"1" [ "shop" ];
  let f =
    config_file ~name:"b5.yaml"
      ~bundles:[ (bundle_path, None); (second, None) ]
      ~token_policy:"shop" ()
  in
  Alcotest.(check string)
    "duplicate" "bundle policy \"shop\" is defined by more than one bundle" (load_err f)

let test_bundle_without_loader () =
  write_bundle ~path:bundle_path ~version:"1" [ "shop" ];
  let f =
    config_file ~name:"b6.yaml" ~bundles:[ (bundle_path, None) ] ~token_policy:"shop" ()
  in
  let saved = !State.bundle_loader in
  State.bundle_loader := None;
  let e =
    Fun.protect ~finally:(fun () -> State.bundle_loader := saved) (fun () -> load_err f)
  in
  check_contains "fails closed" e "cannot load them"

let version_of (st : State.t) name =
  match State.find_policy st name with
  | Some p -> p.Haltsql.Policy.version
  | None -> Alcotest.failf "policy %s not loaded" name

let test_bundle_hot_reload () =
  write_bundle ~path:bundle_path ~version:"1" [ "shop" ];
  let f =
    config_file ~name:"b7.yaml" ~bundles:[ (bundle_path, None) ] ~token_policy:"shop" ()
  in
  let src = sources f in
  let cfg = load_ok f in
  let st = State.create ~sources:src cfg in
  let v1 = version_of st "shop" in
  (* A new signed bundle with a changed policy: reloaded. *)
  Unix.sleepf 1.1;
  write_bundle ~columns:"[id, tenant_id]" ~path:bundle_path ~version:"2" [ "shop" ];
  let bytes = read_file bundle_path in
  Alcotest.(check bool) "change detected" true (State.changed st);
  (match run (State.reload_lwt ~reason:"test" st) with
  | Ok () -> ()
  | Error e -> Alcotest.failf "reload: %s" (String.concat "; " e));
  let v2 = version_of st "shop" in
  Alcotest.(check bool) "new policy version" true (v1 <> v2);
  (* Only the signature is replaced (signed by an untrusted key): refused,
     the last good set stays. *)
  Unix.sleepf 1.1;
  write_file (bundle_path ^ ".sig")
    (Bundle.signatures_to_string [ Bundle.sign (Lazy.force other_key) bytes ]);
  Alcotest.(check bool) "sig change detected" true (State.changed st);
  (match run (State.reload_lwt ~reason:"test" st) with
  | Ok () -> Alcotest.fail "reload with an untrusted signature must fail"
  | Error e -> check_contains "reload error" (String.concat "; " e) "signature");
  Alcotest.(check string) "last good kept" v2 (version_of st "shop");
  State.close st

(* ------------------------------------------------------------ fakes *)

type fake = { port : int; mutable requests : (Cohttp.Request.t * string) list }

let start_fake handler =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true;
  Unix.bind (Lwt_unix.unix_file_descr fd) (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  Lwt_unix.listen fd 64;
  let port =
    match Unix.getsockname (Lwt_unix.unix_file_descr fd) with
    | Unix.ADDR_INET (_, p) -> p
    | _ -> assert false
  in
  let t = { port; requests = [] } in
  let callback _ req body =
    let* b = Cohttp_lwt.Body.to_string body in
    t.requests <- t.requests @ [ (req, b) ];
    handler req b
  in
  Lwt.async (fun () ->
      Cohttp_lwt_unix.Server.create ~on_exn:ignore
        ~mode:(`TCP (`Socket fd))
        (Cohttp_lwt_unix.Server.make ~callback ()));
  t

let respond ?(status = 200) ?(headers = []) body =
  Cohttp_lwt_unix.Server.respond_string
    ~headers:(Cohttp.Header.of_list headers)
    ~status:(Cohttp.Code.status_of_code status)
    ~body ()

let path req = Uri.path (Cohttp.Request.uri req)

(* ------------------------------------------------------------ secrets *)

let vault_value = ref "otel-token-v1"

let vault =
  lazy
    (start_fake (fun req _ ->
         match
           (Cohttp.Header.get (Cohttp.Request.headers req) "x-vault-token", path req)
         with
         | Some "vault-root-token", "/v1/secret/data/haltsql/otel" ->
             respond (Printf.sprintf {|{"data":{"data":{"token":"%s"}}}|} !vault_value)
         | Some "vault-root-token", _ -> respond ~status:404 {|{"errors":[]}|}
         | _ -> respond ~status:403 {|{"errors":["permission denied"]}|}))

let collector = lazy (start_fake (fun _ _ -> respond "{}"))

let secrets_config ~name ~secret_path =
  let v = Lazy.force vault and c = Lazy.force collector in
  let f = tmp name in
  write_file f
    (String.concat "\n"
       [
         "apiVersion: haltsql.dev/v1";
         "kind: Config";
         "server: { auth: { tokens: [] } }";
         "telemetry:";
         "  otlp:";
         Printf.sprintf "    endpoint: http://127.0.0.1:%d" c.port;
         "    headers:";
         Printf.sprintf "      authorization: \"Bearer ${vault:%s#token}\"" secret_path;
         "secrets:";
         "  vault:";
         Printf.sprintf "    address: http://127.0.0.1:%d" v.port;
         "    auth: { method: token, token: vault-root-token }";
         "";
       ]);
  f

let otlp_auth (cfg : Haltsql.Config.t) =
  match cfg.otlp with
  | Some o -> List.assoc_opt "authorization" o.otlp_headers
  | None -> None

let test_secret_startup () =
  vault_value := "otel-token-v1";
  let f = secrets_config ~name:"s1.yaml" ~secret_path:"secret/data/haltsql/otel" in
  let cfg = load_ok f in
  Alcotest.(check (option string))
    "resolved at startup" (Some "Bearer otel-token-v1") (otlp_auth cfg)

let test_secret_error_no_value () =
  vault_value := "super-secret-value";
  let f = secrets_config ~name:"s2.yaml" ~secret_path:"secret/data/haltsql/missing" in
  let e = load_err f in
  check_contains "names the reference" e "secret/data/haltsql/missing";
  Alcotest.(check bool) "no secret value" false (contains e "super-secret-value");
  Alcotest.(check bool) "no vault token" false (contains e "vault-root-token")

let test_secret_reload_prefetch () =
  vault_value := "otel-token-v1";
  let f = secrets_config ~name:"s3.yaml" ~secret_path:"secret/data/haltsql/otel" in
  let cfg = load_ok f in
  let st = State.create ~sources:(sources f) cfg in
  (match Telemetry.configure cfg.otlp with Ok () -> () | Error e -> Alcotest.fail e);
  (* Rotated in Vault: the reload (inside Lwt) prefetches a fresh value. *)
  vault_value := "otel-token-v2";
  (match run (State.reload_lwt ~reason:"test" st) with
  | Ok () -> ()
  | Error e -> Alcotest.failf "reload: %s" (String.concat "; " e));
  let rotated =
    match !Telemetry.current_cfg with
    | Some o -> List.assoc_opt "authorization" o.otlp_headers
    | None -> None
  in
  Alcotest.(check (option string)) "rotated secret" (Some "Bearer otel-token-v2") rotated;
  run (Telemetry.shutdown ());
  ignore (Telemetry.configure None);
  State.close st

(* ------------------------------------------- telemetry + S3, in-process *)

let s3_mode = ref `Ok

let s3 =
  lazy
    (start_fake (fun req _ ->
         match (Cohttp.Request.meth req, !s3_mode) with
         | `PUT, `Ok -> respond ~headers:[ ("etag", "\"x\"") ] ""
         | `PUT, `Fail -> respond ~status:500 "<Error><Code>InternalError</Code></Error>"
         | _ -> respond ~status:405 ""))

let server_config ~name ~on_error =
  let c = Lazy.force collector and s = Lazy.force s3 in
  let policy = tmp "shop.policy.yaml" in
  ignore (policy_of_yaml ~name:"shop" ());
  let f = tmp name in
  write_file f
    (String.concat "\n"
       [
         "apiVersion: haltsql.dev/v1";
         "kind: Config";
         "server:";
         "  auth:";
         "    tokens:";
         Printf.sprintf "      - { name: agent, token_sha256: %s, policy: shop }"
           (sha token);
         "policies:";
         "  - { path: " ^ policy ^ " }";
         "audit:";
         "  sinks:";
         "    - type: s3";
         "      bucket: haltsql-audit";
         "      region: us-east-1";
         Printf.sprintf "      endpoint: http://127.0.0.1:%d" s.port;
         "      prefix: it/";
         "      batch: { max_records: 1, max_seconds: 1 }";
         "      credentials: { source: static, access_key_id: AKIDEXAMPLE, \
          secret_access_key: wJalrXUtnFEMI }";
         "      on_error: " ^ on_error;
         "telemetry:";
         "  otlp:";
         Printf.sprintf "    endpoint: http://127.0.0.1:%d" c.port;
         "    export_interval_seconds: 1";
         "";
       ]);
  f

let start_server f =
  let cfg = load_ok f in
  (match Telemetry.configure cfg.otlp with Ok () -> () | Error e -> Alcotest.fail e);
  let st = State.create ~sources:(sources f) cfg in
  let fd, port = Server.bind_listen "127.0.0.1:0" in
  let stop, stopper = Lwt.wait () in
  Lwt.async (fun () -> Server.serve st fd ~stop);
  (st, port, stopper)

let request ?(meth = `GET) ?(headers = []) ?body port p =
  let headers =
    Cohttp.Header.of_list
      ([ ("authorization", "Bearer " ^ token); ("content-type", "application/json") ]
      @ headers)
  in
  let body = Option.map Cohttp_lwt.Body.of_string body in
  let* r, b =
    Client.call ~headers ?body meth
      (Uri.of_string (Printf.sprintf "http://127.0.0.1:%d%s" port p))
  in
  let* s = Cohttp_lwt.Body.to_string b in
  Lwt.return (Cohttp.Code.code_of_status (Cohttp.Response.status r), s)

let sql = "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 10"
let verify_body = Printf.sprintf {|{"sql":%S,"context":{"tenant_id":"acme"}}|} sql

let rec wait_until ?(timeout = 10.0) what f =
  if timeout <= 0. then Alcotest.failf "timed out waiting for %s" what
  else
    let* ok = f () in
    if ok then Lwt.return_unit
    else
      let* () = Lwt_unix.sleep 0.1 in
      wait_until ~timeout:(timeout -. 0.1) what f

let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"

let test_telemetry_and_s3 () =
  s3_mode := `Ok;
  let st, port, stopper =
    start_server (server_config ~name:"t1.yaml" ~on_error:"fail_closed")
  in
  let c = Lazy.force collector and s = Lazy.force s3 in
  run
    (let* status, body =
       request ~meth:`POST port "/v1/verify" ~body:verify_body
         ~headers:[ ("traceparent", Printf.sprintf "00-%s-00f067aa0ba902b7-01" trace_id) ]
     in
     Alcotest.(check int) ("verify: " ^ body) 200 status;
     let* () = Telemetry.Exporter.flush (Telemetry.exporter ()) in
     let* () =
       wait_until "an S3 upload" (fun () ->
           Lwt.return
             (List.exists (fun (r, _) -> Cohttp.Request.meth r = `PUT) s.requests))
     in
     let* status, metrics = request port "/metrics" in
     Alcotest.(check int) "metrics" 200 status;
     check_contains "sink metrics" metrics
       "haltsql_audit_sink_healthy{sink=\"s3://haltsql-audit/it/\"} 1";
     let* status, _ = request port "/readyz" in
     Alcotest.(check int) "ready" 200 status;
     Lwt.return_unit);
  (* The span: inside the caller's trace, with the SQL hash but no SQL. *)
  let traces =
    List.filter_map
      (fun (r, b) -> if path r = "/v1/traces" then Some b else None)
      c.requests
  in
  let all = String.concat "\n" traces in
  check_contains "span name" all "haltsql.verify";
  check_contains "trace id" all trace_id;
  check_contains "sql hash attribute" all "db.statement.sha256";
  check_contains "sql hash" all Digestif.SHA256.(to_hex (digest_string sql));
  Alcotest.(check bool) "no SQL exported" false (contains all "FROM orders");
  let metrics =
    List.filter_map
      (fun (r, b) -> if path r = "/v1/metrics" then Some b else None)
      c.requests
  in
  check_contains "verify metric" (String.concat "\n" metrics) "haltsql_verify_total";
  (* The uploaded object is one hash-chained audit record under the prefix. *)
  let put_req, put_body =
    List.find (fun (r, _) -> Cohttp.Request.meth r = `PUT) s.requests
  in
  check_contains "object key prefix" (path put_req) "/haltsql-audit/it/";
  let record = Yojson.Safe.from_string (String.trim put_body) in
  let field k = match record with `Assoc kv -> List.assoc_opt k kv | _ -> None in
  Alcotest.(check bool) "caller" true (field "caller" = Some (`String "agent"));
  Alcotest.(check bool) "allowed" true (field "allowed" = Some (`Bool true));
  Alcotest.(check bool) "chained" true (field "prev_hash" <> None && field "hash" <> None);
  Alcotest.(check bool) "no raw SQL" true (field "sql" = None);
  Lwt.wakeup_later stopper ();
  run (Lwt_unix.sleep 0.1);
  State.close st;
  run (Telemetry.shutdown ());
  ignore (Telemetry.configure None)

let test_s3_fail_closed () =
  s3_mode := `Fail;
  let st, port, stopper =
    start_server (server_config ~name:"t2.yaml" ~on_error:"fail_closed")
  in
  run
    (* The first record is accepted into a batch; its upload then fails. *)
    (let* status, _ = request ~meth:`POST port "/v1/verify" ~body:verify_body in
     Alcotest.(check int) "first verify accepted" 200 status;
     let* () =
       wait_until ~timeout:15.0 "/readyz to report the sink" (fun () ->
           let* status, _ = request port "/readyz" in
           Lwt.return (status = 503))
     in
     let* status, body = request port "/readyz" in
     Alcotest.(check int) "not ready" 503 status;
     check_contains "names the sink" body "s3://haltsql-audit/it/";
     let* status, body = request ~meth:`POST port "/v1/verify" ~body:verify_body in
     Alcotest.(check int) "verify fails closed" 503 status;
     check_contains "audit unavailable" body "AUDIT_UNAVAILABLE";
     Lwt.return_unit);
  s3_mode := `Ok;
  Lwt.wakeup_later stopper ();
  run (Lwt_unix.sleep 0.1);
  State.close st;
  run (Telemetry.shutdown ());
  ignore (Telemetry.configure None)

let () =
  let tc name f = Alcotest.test_case name `Quick f in
  Alcotest.run "haltsql-server-integrations"
    [
      ( "bundles",
        [
          tc "signed bundle loads with name_prefix" test_bundle_loads;
          tc "tampered bundle refused" test_bundle_tampered;
          tc "untrusted key refused" test_bundle_wrong_key;
          tc "references re-checked after loading" test_bundle_missing_ref;
          tc "duplicate bundle policy refused" test_bundle_duplicate;
          tc "no loader fails closed" test_bundle_without_loader;
          tc "hot reload re-verifies" test_bundle_hot_reload;
        ] );
      ( "secrets",
        [
          tc "vault placeholder at startup" test_secret_startup;
          tc "errors never contain secrets" test_secret_error_no_value;
          tc "reload prefetches rotated secret" test_secret_reload_prefetch;
        ] );
      ( "telemetry-and-sinks",
        [
          tc "span, metrics and S3 upload" test_telemetry_and_s3;
          tc "S3 upload failure fails closed" test_s3_fail_closed;
        ] );
    ]
