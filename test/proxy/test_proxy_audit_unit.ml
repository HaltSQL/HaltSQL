(* ProxyConfig audit/reload sections and the proxy audit writer (Paudit), no network. *)

open Haltsql_pgwire
module Config = Haltsql.Config
module Chain = Haltsql_cloud.Audit_chain

let verifier =
  Scram.verifier_to_string (Scram.make_verifier ~iterations:4096 "agent-password")

let base ?(extra = []) () : Yojson.Safe.t =
  `Assoc
    ([
       ("apiVersion", `String "haltsql.dev/v1");
       ("kind", `String "ProxyConfig");
       ("listen", `String "127.0.0.1:0");
       ( "upstream",
         `Assoc
           [
             ("host", `String "127.0.0.1");
             ("database", `String "app");
             ("user", `String "svc");
           ] );
       ("policies", `List [ `Assoc [ ("path", `String "fixtures/policy.yaml") ] ]);
       ( "auth",
         `Assoc
           [
             ("method", `String "scram");
             ( "users",
               `List
                 [
                   `Assoc
                     [
                       ("name", `String "agent");
                       ("scram_verifier", `String verifier);
                       ("policy", `String "proxy-test");
                       ("context", `Assoc [ ("tenant_id", `String "acme") ]);
                     ];
                 ] );
           ] );
     ]
    @ extra)

let env = function "MINIO_SECRET" -> Some "secret-${not-a-placeholder}" | _ -> None
let load j = Proxy_config.of_json ~base_dir:(Sys.getcwd ()) ~env j
let with_audit a = base ~extra:[ ("audit", Yojson.Safe.from_string a) ] ()

let ok j =
  match load j with
  | Ok c -> c
  | Error es ->
      Alcotest.failf "unexpected: %s"
        (String.concat "; " (List.map Haltsql.Load_error.to_string es))

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let has_error name sub j =
  match load j with
  | Ok _ -> Alcotest.failf "%s: expected an error containing %S" name sub
  | Error es ->
      let es = List.map Haltsql.Load_error.to_string es in
      if not (List.exists (fun e -> contains e sub) es) then
        Alcotest.failf "%s: no error containing %S in [%s]" name sub
          (String.concat "; " es)

let t_defaults () =
  let c = ok (base ()) in
  Alcotest.(check int) "one sink" 1 (List.length c.audit_sinks);
  (match c.audit_sinks with
  | [ { sink = Config.Sink_stdout; sink_on_error = Proxy_config.Audit_fail_closed; _ } ]
    ->
      ()
  | _ -> Alcotest.fail "default is stdout, fail_closed");
  Alcotest.(check bool) "legacy view" true (c.audit = Proxy_config.Audit_stdout);
  Alcotest.(check bool) "watch off" false c.reload.watch;
  Alcotest.(check (float 0.)) "poll" 2. c.reload.poll_interval

let t_legacy_forms () =
  let c = ok (with_audit {|{"type":"none"}|}) in
  Alcotest.(check int) "none" 0 (List.length c.audit_sinks);
  let c =
    ok
      (with_audit
         {|{"type":"file","path":"a.jsonl","on_error":"buffer","max_buffer_records":5}|})
  in
  (match c.audit_sinks with
  | [
   {
     sink = Config.Sink_file p;
     sink_on_error = Proxy_config.Audit_buffer;
     max_buffer_records = 5;
   };
  ] ->
      Alcotest.(check bool) "absolute" false (Filename.is_relative p)
  | _ -> Alcotest.fail "file/buffer");
  let c = ok (with_audit {|{"type":"stdout","on_error":"drop"}|}) in
  (match c.audit_sinks with
  | [ { sink_on_error = Proxy_config.Audit_drop; _ } ] -> ()
  | _ -> Alcotest.fail "drop");
  has_error "max_buffer without buffer"
    "max_buffer_records: only allowed with on_error: buffer"
    (with_audit {|{"type":"stdout","max_buffer_records":5}|});
  has_error "bad on_error" "invalid value \"fail\""
    (with_audit {|{"type":"stdout","on_error":"fail"}|});
  has_error "path with stdout" "only allowed with type: file"
    (with_audit {|{"type":"stdout","path":"x"}|})

let t_sinks_form () =
  let c =
    ok
      (with_audit
         {|{"sinks":[
             {"type":"file","path":"/tmp/x.jsonl"},
             {"type":"s3","bucket":"audit-bucket","region":"us-east-1",
              "endpoint":"http://127.0.0.1:9000","prefix":"proxy/",
              "credentials":{"source":"static","access_key_id":"AK",
                             "secret_access_key":"${env:MINIO_SECRET}"},
              "batch":{"max_records":2,"max_seconds":1},"on_error":"buffer"},
             {"type":"gcs","bucket":"audit-bucket-2","on_error":"drop"}],
           "log_raw_sql":true}|})
  in
  Alcotest.(check bool) "raw sql" true c.log_raw_sql;
  (match c.audit_sinks with
  | [
   {
     sink = Config.Sink_file "/tmp/x.jsonl";
     sink_on_error = Proxy_config.Audit_fail_closed;
     _;
   };
   {
     sink = Config.Sink_s3 s3;
     sink_on_error = Proxy_config.Audit_buffer;
     max_buffer_records = 100_000;
   };
   { sink = Config.Sink_gcs _; sink_on_error = Proxy_config.Audit_drop; _ };
  ] -> (
      Alcotest.(check string) "prefix" "proxy/" s3.s3_prefix;
      Alcotest.(check int) "batch" 2 s3.s3_batch.max_records;
      match s3.s3_credentials with
      | Config.S3_static { secret_access_key; _ } ->
          (* an env value containing "${" stays literal *)
          Alcotest.(check string) "secret" "secret-${not-a-placeholder}" secret_access_key
      | _ -> Alcotest.fail "static credentials")
  | _ -> Alcotest.fail "three sinks");
  Alcotest.(check bool)
    "legacy view: first file" true
    (c.audit = Proxy_config.Audit_file "/tmp/x.jsonl");
  let red = Yojson.Safe.to_string (Proxy_config.to_json_redacted c) in
  Alcotest.(check bool) "secret redacted" false (contains red "not-a-placeholder");
  Alcotest.(check bool) "sink listed" true (contains red "s3")

let t_sink_errors () =
  has_error "kafka" "audit.sinks[0].type: not supported by haltsql-proxy"
    (with_audit {|{"sinks":[{"type":"kafka","brokers":["k:9092"],"topic":"t"}]}|});
  (* errors from the shared decoder keep the proxy's index *)
  has_error "s3 region" "audit.sinks[1].region: required"
    (with_audit {|{"sinks":[{"type":"stdout"},{"type":"s3","bucket":"audit-bucket"}]}|});
  has_error "s3 endpoint" "audit.sinks[0].endpoint"
    (with_audit
       {|{"sinks":[{"type":"s3","bucket":"audit-bucket","region":"r","endpoint":"ftp://example.com"}]}|});
  has_error "empty sinks" "at least one sink is required" (with_audit {|{"sinks":[]}|});
  has_error "mixed forms" "audit.type: not allowed together with sinks"
    (with_audit {|{"type":"stdout","sinks":[{"type":"stdout"}]}|});
  has_error "same file twice" "is used by more than one audit sink"
    (with_audit
       {|{"sinks":[{"type":"file","path":"/tmp/a"},{"type":"file","path":"/tmp/a"}]}|});
  has_error "unknown key" "audit.sinks[0].bogus"
    (with_audit {|{"sinks":[{"type":"file","path":"/tmp/a","bogus":1}]}|})

let t_reload_section () =
  let c =
    ok
      (base
         ~extra:
           [
             ( "reload",
               `Assoc [ ("watch", `Bool true); ("poll_interval_seconds", `Float 0.5) ] );
           ]
         ())
  in
  Alcotest.(check bool) "watch" true c.reload.watch;
  Alcotest.(check (float 0.)) "poll" 0.5 c.reload.poll_interval;
  has_error "poll range" "out of range"
    (base ~extra:[ ("reload", `Assoc [ ("poll_interval_seconds", `Float 0.01) ]) ] ())

let t_source_files () =
  let pol = Filename.concat (Filename.concat (Sys.getcwd ()) "fixtures") "policy.yaml" in
  let j =
    match base () with
    | `Assoc kv ->
        `Assoc
          (List.map
             (fun (k, v) ->
               if k = "policies" then (k, `List [ `Assoc [ ("path", `String pol) ] ])
               else (k, v))
             kv)
    | j -> j
  in
  let path = Filename.temp_file "proxycfg" ".json" in
  Out_channel.with_open_bin path (fun oc ->
      Out_channel.output_string oc (Yojson.Safe.to_string j));
  match Proxy_config.of_file path with
  | Error es ->
      Alcotest.failf "load: %s"
        (String.concat "; " (List.map Haltsql.Load_error.to_string es))
  | Ok c ->
      Alcotest.(check bool) "config file" true (List.mem path c.source_files);
      Alcotest.(check bool) "policy file" true (List.mem pol c.source_files)

(* --------------------------------------------------------------- Paudit *)

let tmp () = Filename.temp_file "paudit" ".jsonl"
let read path = In_channel.with_open_bin path In_channel.input_all
let lines s = List.filter (fun l -> l <> "") (String.split_on_char '\n' s)

let spec ?(on_error = Proxy_config.Audit_fail_closed) sink =
  { Proxy_config.sink; sink_on_error = on_error; max_buffer_records = 10 }

let t_paudit_file_chain () =
  let path = tmp () in
  Lwt_main.run
    (let a = Paudit.open_ [ spec (Config.Sink_file path) ] in
     for i = 1 to 3 do
       match Paudit.record a [ ("n", `Int i) ] with
       | Ok () -> ()
       | Error e -> Alcotest.fail e
     done;
     Paudit.close a);
  (* a restart continues the chain from the last record *)
  Lwt_main.run
    (let a = Paudit.open_ [ spec (Config.Sink_file path) ] in
     (match Paudit.record a [ ("n", `Int 4) ] with
     | Ok () -> ()
     | Error e -> Alcotest.fail e);
     Paudit.close a);
  let ls = lines (read path) in
  Alcotest.(check (result int (pair int string))) "chain" (Ok 4) (Chain.verify_lines ls);
  let first = Yojson.Safe.from_string (List.hd ls) in
  Alcotest.(check bool)
    "ts first" true
    (match first with `Assoc (("ts", _) :: _) -> true | _ -> false)

let t_paudit_refuses_corrupt_tail () =
  let path = tmp () in
  Out_channel.with_open_bin path (fun oc -> Out_channel.output_string oc "not a record\n");
  match Paudit.open_ [ spec (Config.Sink_file path) ] with
  | _ -> Alcotest.fail "expected a failure"
  | exception Failure m ->
      Alcotest.(check bool) "message" true (contains m "refusing to continue the chain")

let t_paudit_unopenable () =
  match Paudit.open_ [ spec (Config.Sink_file "/nonexistent-dir/x/audit.jsonl") ] with
  | _ -> Alcotest.fail "expected a failure"
  | exception Failure m ->
      Alcotest.(check bool) "names the file" true (contains m "/nonexistent-dir")

let () =
  Sec.init_rng ();
  Alcotest.run "proxy-audit-unit"
    [
      ( "config",
        [
          Alcotest.test_case "defaults" `Quick t_defaults;
          Alcotest.test_case "single-sink form" `Quick t_legacy_forms;
          Alcotest.test_case "sinks form (stdout/file/s3/gcs)" `Quick t_sinks_form;
          Alcotest.test_case "sink errors" `Quick t_sink_errors;
          Alcotest.test_case "reload section" `Quick t_reload_section;
          Alcotest.test_case "source files" `Quick t_source_files;
        ] );
      ( "paudit",
        [
          Alcotest.test_case "file chain across restarts" `Quick t_paudit_file_chain;
          Alcotest.test_case "corrupt tail refused" `Quick t_paudit_refuses_corrupt_tail;
          Alcotest.test_case "unopenable file" `Quick t_paudit_unopenable;
        ] );
    ]
