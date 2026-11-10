open Haltsql_core
open Haltsql_load
open Helpers

let h1 = String.make 64 'a'
let h2 = String.make 64 'b'
let env_of l name = List.assoc_opt name l
let no_env _ = None

let cfg ?(env = no_env) ?base_dir s =
  match yaml s with Error e -> Error e | Ok j -> Config.of_json ?base_dir ~env j

let head = "apiVersion: haltsql.dev/v1\nkind: Config\n"
let inline_pol name = Printf.sprintf "  - inline:\n      metadata: {name: %s}\n" name
let c ?env extra = cfg ?env (head ^ extra)
let c_ok ?env extra = get_ok (c ?env extra)

let tmp_file contents =
  let f = Filename.temp_file "hs" ".txt" in
  let oc = open_out_bin f in
  output_string oc contents;
  close_out oc;
  f

let example_env =
  env_of
    [
      ("HALTSQL_ANALYTICS_TOKEN_HASH", h1);
      ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel:4317");
    ]

let cases =
  [
    tc "defaults" (fun () ->
        let x = c_ok "" in
        Alcotest.(check string) "listen" "127.0.0.1:8080" x.listen;
        Alcotest.(check bool) "unauth" false x.allow_unauthenticated;
        Alcotest.(check bool) "sinks" true (x.audit_sinks = [ Config.Audit_stdout ]);
        Alcotest.(check string) "level" "info" x.log_level;
        Alcotest.(check bool) "metrics" true x.metrics;
        Alcotest.(check int) "max req" 1_048_576 x.max_request_bytes);
    tc "full config" (fun () ->
        let x =
          c_ok
            ("server:\n\
             \  listen: 0.0.0.0:9000\n\
             \  tls: {cert: /c.pem, key: /k.pem}\n\
             \  auth:\n\
             \    tokens:\n\
             \      - {name: a, token_sha256: " ^ h1
           ^ ", policy: p1}\n    allow_unauthenticated: true\npolicies:\n"
           ^ inline_pol "p1"
           ^ "default_policy: p1\n\
              reload: {watch: true}\n\
              audit: {sinks: [{type: file, path: /var/log/a.jsonl}], log_raw_sql: true}\n\
              telemetry: {metrics: {prometheus: false}, otlp_endpoint: http://x}\n\
              logging: {level: debug, format: text}\n\
              limits: {max_request_bytes: 2048}\n")
        in
        Alcotest.(check string) "listen" "0.0.0.0:9000" x.listen;
        Alcotest.(check (option string)) "cert" (Some "/c.pem") x.tls_cert;
        Alcotest.(check int) "tokens" 1 (List.length x.tokens);
        Alcotest.(check bool) "unauth" true x.allow_unauthenticated;
        Alcotest.(check (list string)) "policies" [ "p1" ] (List.map fst x.policies);
        Alcotest.(check (option string)) "default" (Some "p1") x.default_policy;
        Alcotest.(check bool) "watch" true x.reload_watch;
        Alcotest.(check bool)
          "sinks" true
          (x.audit_sinks = [ Config.Audit_file "/var/log/a.jsonl" ]);
        Alcotest.(check bool) "raw" true x.log_raw_sql;
        Alcotest.(check bool) "metrics" false x.metrics;
        Alcotest.(check string) "level" "debug" x.log_level;
        Alcotest.(check string) "format" "text" x.log_format;
        Alcotest.(check int) "max" 2048 x.max_request_bytes);
    tc "env placeholder" (fun () ->
        let x =
          c_ok
            ~env:(env_of [ ("H", h1) ])
            ("server: {auth: {tokens: [{name: a, token_sha256: '${env:H}', policy: p}]}}\n\
              policies:\n" ^ inline_pol "p")
        in
        Alcotest.(check string) "hash" h1 (List.hd x.tokens).token_sha256);
    tc "embedded env placeholder" (fun () ->
        let x =
          c_ok
            ~env:(env_of [ ("HOST", "10.0.0.1") ])
            "server: {listen: '${env:HOST}:8443'}"
        in
        Alcotest.(check string) "listen" "10.0.0.1:8443" x.listen);
    tc "missing env is an error with path" (fun () ->
        check_err ~path:"server.listen" ~msg:"environment variable NOPE is not set"
          (c "server: {listen: '${env:NOPE}'}"));
    tc "file placeholder trims newline" (fun () ->
        let f = tmp_file "/etc/k.pem\n" in
        let x =
          c_ok (Printf.sprintf "server: {tls: {cert: /c.pem, key: '${file:%s}'}}" f)
        in
        Alcotest.(check (option string)) "key" (Some "/etc/k.pem") x.tls_key);
    tc "file placeholder relative to base_dir" (fun () ->
        let f = tmp_file (h2 ^ "\r\n") in
        let x =
          get_ok
            (cfg ~base_dir:(Filename.dirname f)
               (head
               ^ Printf.sprintf
                   "server: {auth: {tokens: [{name: a, token_sha256: '${file:%s}', \
                    policy: p}]}}\n\
                    policies:\n"
                   (Filename.basename f)
               ^ inline_pol "p"))
        in
        Alcotest.(check string) "hash" h2 (List.hd x.tokens).token_sha256);
    tc "missing file is an error" (fun () ->
        check_err ~path:"server.tls.key" ~msg:"cannot read file"
          (c "server: {tls: {cert: /c, key: '${file:/no/such/file}'}}"));
    tc "unknown placeholder" (fun () ->
        check_err ~path:"logging.level" ~msg:"unknown placeholder"
          (c "logging: {level: '${ctx.x}'}"));
    tc "unterminated placeholder" (fun () ->
        check_err ~msg:"unterminated placeholder" (c "server: {listen: '${env:X'}"));
    tc "escaped placeholder" (fun () ->
        let x =
          c_ok
            "telemetry: {otlp: {endpoint: 'http://c:4318', service_name: 'a$${env:X}'}}"
        in
        Alcotest.(check string) "literal" "a${env:X}" (Option.get x.otlp).service_name);
    tc "placeholders not resolved in inline policies" (fun () ->
        check_err ~path:"policies[0].inline.dialect" ~msg:"only allowed in Config"
          (c
             ~env:(env_of [ ("X", "postgres") ])
             "policies:\n\
             \  - inline:\n\
             \      metadata: {name: p}\n\
             \      dialect: '${env:X}'\n"));
    tc "env overrides beat file" (fun () ->
        let env =
          env_of
            [
              ("HALTSQL_LISTEN", "127.0.0.1:1234");
              ("HALTSQL_LOG_LEVEL", "warn");
              ("HALTSQL_LOG_FORMAT", "text");
              ("HALTSQL_ALLOW_UNAUTHENTICATED", "true");
              ("HALTSQL_DEFAULT_POLICY", "p2");
            ]
        in
        let x =
          c_ok ~env
            ("server: {listen: 0.0.0.0:80}\n\
              logging: {level: debug, format: json}\n\
              default_policy: p1\n\
              policies:\n" ^ inline_pol "p1" ^ inline_pol "p2")
        in
        Alcotest.(check string) "listen" "127.0.0.1:1234" x.listen;
        Alcotest.(check string) "level" "warn" x.log_level;
        Alcotest.(check string) "format" "text" x.log_format;
        Alcotest.(check bool) "unauth" true x.allow_unauthenticated;
        Alcotest.(check (option string)) "default" (Some "p2") x.default_policy);
    tc "env override can turn anonymous access off" (fun () ->
        let file = "server: {auth: {allow_unauthenticated: true}}" in
        Alcotest.(check bool) "file alone" true (c_ok file).allow_unauthenticated;
        Alcotest.(check bool)
          "env false wins" false
          (c_ok ~env:(env_of [ ("HALTSQL_ALLOW_UNAUTHENTICATED", "false") ]) file)
            .allow_unauthenticated);
    tc "file beats defaults when env absent" (fun () ->
        Alcotest.(check string) "level" "error" (c_ok "logging: {level: error}").log_level);
    tc "bad env override" (fun () ->
        check_err ~path:"\"env:HALTSQL_LOG_LEVEL\"" ~msg:"invalid log level"
          (c ~env:(env_of [ ("HALTSQL_LOG_LEVEL", "loud") ]) "");
        check_err ~msg:"invalid boolean"
          (c ~env:(env_of [ ("HALTSQL_ALLOW_UNAUTHENTICATED", "maybe") ]) "");
        check_err ~msg:"invalid listen"
          (c ~env:(env_of [ ("HALTSQL_LISTEN", "nope") ]) ""));
    tc "token policy must exist" (fun () ->
        check_err ~path:"server.auth.tokens[0].policy" ~msg:"unknown policy"
          (c
             ("server: {auth: {tokens: [{name: a, token_sha256: " ^ h1
            ^ ", policy: ghost}]}}")));
    tc "token hash format" (fun () ->
        check_err ~path:"server.auth.tokens[0].token_sha256" ~msg:"64 lower-case hex"
          (c
             ("server: {auth: {tokens: [{name: a, token_sha256: "
             ^ String.uppercase_ascii (String.make 64 'a')
             ^ ", policy: p}]}}\npolicies:\n" ^ inline_pol "p")));
    tc "token hash: exactly 64 hex characters" (fun () ->
        let bad h =
          check_err ~path:"server.auth.tokens[0].token_sha256" ~msg:"64 lower-case hex"
            (c
               ("server: {auth: {tokens: [{name: a, token_sha256: '" ^ h
              ^ "', policy: p}]}}\npolicies:\n" ^ inline_pol "p"))
        in
        bad (String.make 63 'a');
        bad (String.make 65 'a');
        bad "abc123";
        bad (String.make 63 'a' ^ "g");
        bad (String.make 63 '0' ^ "z"));
    tc "duplicate token names and hashes" (fun () ->
        let r =
          c
            ("server: {auth: {tokens: [{name: a, token_sha256: " ^ h1
           ^ ", policy: p}, {name: a, token_sha256: " ^ h1
           ^ ", policy: p}]}}\npolicies:\n" ^ inline_pol "p")
        in
        check_err ~msg:"duplicate token name" r;
        check_err ~msg:"same token hash" r);
    tc "duplicate policy names" (fun () ->
        check_err ~path:"policies[1]" ~msg:"duplicate policy name"
          (c ("policies:\n" ^ inline_pol "p" ^ inline_pol "p")));
    tc "default policy must exist" (fun () ->
        check_err ~path:"default_policy" ~msg:"unknown policy" (c "default_policy: nope"));
    tc "listen validation" (fun () ->
        List.iter
          (fun l -> ignore (c_ok (Printf.sprintf "server: {listen: '%s'}" l)))
          [ "localhost:80"; "[::1]:8443"; "0.0.0.0:65535" ];
        List.iter
          (fun l ->
            check_err ~path:"server.listen" ~msg:"invalid listen address"
              (c (Printf.sprintf "server: {listen: '%s'}" l)))
          [ "8080"; ":8080"; "host:"; "host:0"; "host:70000"; "::1:80"; "host:80a" ]);
    tc "tls needs both" (fun () ->
        check_err ~path:"server.tls.key" ~msg:"required when tls.cert"
          (c "server: {tls: {cert: /c}}"));
    tc "policy path and inline exclusive" (fun () ->
        check_err ~path:"policies[0]" ~msg:"not both"
          (c "policies:\n  - {path: a.yaml, inline: {metadata: {name: x}}}"));
    tc "policy entry empty" (fun () ->
        check_err ~path:"policies[0]" ~msg:"needs path or inline" (c "policies:\n  - {}"));
    tc "missing policy file" (fun () ->
        check_err ~path:"policies[0].path" ~msg:"cannot load policy"
          (c "policies:\n  - path: /no/such.yaml"));
    tc "inline policy errors have full path" (fun () ->
        check_err ~path:"policies[0].inline.mode" ~msg:"invalid value"
          (c "policies:\n  - inline: {metadata: {name: x}, mode: bad}"));
    tc "unknown keys" (fun () ->
        check_err ~path:"servr" ~msg:"did you mean \"server\"" (c "servr: {}");
        check_err ~path:"server.auth.tokenz" ~msg:"unknown key"
          (c "server: {auth: {tokenz: []}}"));
    tc "sink validation" (fun () ->
        check_err ~path:"audit.sinks[0].type" ~msg:"invalid value"
          (c "audit: {sinks: [{type: syslog}]}");
        check_err ~path:"audit.sinks[0].path" ~msg:"required"
          (c "audit: {sinks: [{type: file}]}"));
    tc "logging enum" (fun () ->
        check_err ~path:"logging.format" ~msg:"invalid value" (c "logging: {format: xml}"));
    tc "max_request_bytes range" (fun () ->
        check_err ~path:"limits.max_request_bytes" ~msg:"between"
          (c "limits: {max_request_bytes: 1}");
        check_err ~path:"limits.max_request_bytes" ~msg:"between"
          (c "limits: {max_request_bytes: 67108865}");
        Alcotest.(check int)
          "64 MiB is the largest" 67_108_864
          (c_ok "limits: {max_request_bytes: 67108864}").max_request_bytes);
    tc "kind must be Config" (fun () ->
        check_err ~path:"kind" ~msg:"expected kind \"Config\""
          (cfg "apiVersion: haltsql.dev/v1\nkind: Policy\n"));
    tc "redaction" (fun () ->
        let f = tmp_file "SECRETKEY" in
        let x =
          c_ok
            (Printf.sprintf
               "server:\n\
               \  tls: {cert: /c.pem, key: '${file:%s}'}\n\
               \  auth: {tokens: [{name: a, token_sha256: %s, policy: p}]}\n\
                policies:\n\
                %s"
               f h1 (inline_pol "p"))
        in
        let s = Yojson.Safe.to_string (Config.to_json_redacted x) in
        Alcotest.(check bool) "no hash" false (contains s h1);
        Alcotest.(check bool) "no key" false (contains s "SECRETKEY");
        Alcotest.(check bool) "redacted" true (contains s "<redacted>");
        Alcotest.(check bool) "cert kept" true (contains s "/c.pem"));
    tc "example config yaml" (fun () ->
        let x = get_ok (Config.of_file ~env:example_env (ex "config/haltsql.yaml")) in
        Alcotest.(check (list string))
          "policies"
          [ "saas-analytics"; "support-bot"; "currency-lookup" ]
          (List.map fst x.policies);
        Alcotest.(check int) "files" 2 (List.length x.policy_files);
        List.iter
          (fun f -> Alcotest.(check bool) "absolute" false (Filename.is_relative f))
          x.policy_files;
        Alcotest.(check string) "token" h1 (List.hd x.tokens).token_sha256);
    tc "example config json matches yaml" (fun () ->
        let a = get_ok (Config.of_file ~env:example_env (ex "config/haltsql.yaml")) in
        let b = get_ok (Config.of_file ~env:example_env (ex "config/haltsql.json")) in
        let versions (x : Config.t) =
          List.map (fun (n, (p : Policy.t)) -> (n, p.version)) x.policies
        in
        Alcotest.(check (list (pair string string))) "versions" (versions a) (versions b);
        Alcotest.(check bool) "same tokens" true (a.tokens = b.tokens);
        Alcotest.(check bool) "same sinks" true (a.audit_sinks = b.audit_sinks));
    tc "example config without env fails" (fun () ->
        check_err ~msg:"HALTSQL_ANALYTICS_TOKEN_HASH is not set"
          (Config.of_file ~env:no_env (ex "config/haltsql.yaml")));
  ]

let tests = [ ("config", cases) ]
