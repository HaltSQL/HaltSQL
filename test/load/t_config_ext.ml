(* Tests for the extended Config sections: server.tls (mTLS), server.auth.oidc,
   server.auth.mtls, telemetry.otlp, cloud audit sinks, secrets, secret
   provider placeholders and signed policy bundle references. *)

open Haltsql_core
open Haltsql_load
open Helpers

let h1 = String.make 64 'a'
let no_env _ = None
let env_of l name = List.assoc_opt name l
let head = "apiVersion: haltsql.dev/v1\nkind: Config\n"

let pols =
  "policies:\n  - inline: {metadata: {name: p1}}\n  - inline: {metadata: {name: p2}}\n"

let cfg ?(env = no_env) ?resolve ?(base_dir = "/etc/haltsql") s =
  match yaml (head ^ s) with
  | Error e -> Error e
  | Ok j -> Config.of_json ~base_dir ~env ?resolve j

let ok ?env ?resolve ?base_dir s = get_ok (cfg ?env ?resolve ?base_dir s)
let err ?env ?resolve ?path ~msg s = check_err ?path ~msg (cfg ?env ?resolve s)

let tmp_file contents =
  let f = Filename.temp_file "hs" ".txt" in
  Out_channel.with_open_bin f (fun oc -> output_string oc contents);
  f

let mtls_tls =
  "  tls: {cert: /c.pem, key: /k.pem, client_ca: /ca.pem, client_auth: required}\n"

let oidc_base extra =
  Printf.sprintf
    "server:\n\
    \  auth:\n\
    \    oidc:\n\
    \      - name: corp\n\
    \        issuer: https://idp.corp.example\n\
    \        audiences: [haltsql]\n\
     %s%s"
    extra pols

let oidc_path k = "server.auth.oidc[0]." ^ k

(* A fake resolver that records its calls. *)
let fake_resolver () =
  let calls = ref [] in
  let r ~scheme ~reference =
    calls := (scheme, reference) :: !calls;
    match (scheme, reference) with
    | "vault", "secret/data/otel#token" -> Ok "vault-otel-token"
    | "aws-sm", "prod/s3#secret" -> Ok "aws-secret-key"
    | "aws-sm", "prod/s3-key" -> Ok "AKIAFAKE"
    | "gcp-sm", "projects/p/secrets/hdr/versions/latest" -> Ok "gcp-header"
    | _ -> Error "no such secret"
  in
  (r, calls)

let tls_cases =
  [
    tc "tls cert+key gives typed tls with defaults" (fun () ->
        let x = ok "server: {tls: {cert: certs/c.pem, key: /k.pem}}" in
        let t = Option.get x.tls in
        Alcotest.(check bool)
          "cert absolute" true
          (t.cert = Config.Pem_path "/etc/haltsql/certs/c.pem");
        Alcotest.(check bool) "key" true (t.key = Config.Pem_path "/k.pem");
        Alcotest.(check bool) "client_ca" true (t.client_ca = None);
        Alcotest.(check bool) "client_auth" true (t.client_auth = Config.Client_auth_none);
        Alcotest.(check bool) "min" true (t.min_version = Config.Tls_1_2);
        Alcotest.(check (option string)) "legacy cert raw" (Some "certs/c.pem") x.tls_cert);
    tc "tls with mTLS options" (fun () ->
        let x =
          ok
            "server: {tls: {cert: /c.pem, key: /k.pem, client_ca: /ca.pem, client_auth: \
             optional, min_version: '1.3'}}"
        in
        let t = Option.get x.tls in
        Alcotest.(check bool) "ca" true (t.client_ca = Some (Config.Pem_path "/ca.pem"));
        Alcotest.(check bool) "auth" true (t.client_auth = Config.Client_auth_optional);
        Alcotest.(check bool) "min" true (t.min_version = Config.Tls_1_3));
    tc "tls min_version as YAML number" (fun () ->
        let x = ok "server: {tls: {cert: /c, key: /k, min_version: 1.3}}" in
        Alcotest.(check bool) "1.3" true ((Option.get x.tls).min_version = Config.Tls_1_3));
    tc "tls min_version invalid" (fun () ->
        err ~path:"server.tls.min_version" ~msg:"expected one of: \"1.2\", \"1.3\""
          "server: {tls: {cert: /c, key: /k, min_version: '1.1'}}");
    tc "client_auth required needs client_ca" (fun () ->
        err ~path:"server.tls.client_auth" ~msg:"needs server.tls.client_ca"
          "server: {tls: {cert: /c, key: /k, client_auth: required}}");
    tc "client_auth optional needs client_ca" (fun () ->
        err ~path:"server.tls.client_auth" ~msg:"needs server.tls.client_ca"
          "server: {tls: {cert: /c, key: /k, client_auth: optional}}");
    tc "client_auth enum" (fun () ->
        err ~path:"server.tls.client_auth" ~msg:"invalid value \"always\""
          "server: {tls: {cert: /c, key: /k, client_ca: /ca, client_auth: always}}");
    tc "tls options without cert/key" (fun () ->
        err ~path:"server.tls.cert" ~msg:"required (with tls.key)"
          "server: {tls: {client_ca: /ca.pem}}");
    tc "tls key without cert" (fun () ->
        err ~path:"server.tls.cert" ~msg:"required when tls.key is set"
          "server: {tls: {key: /k}}");
    tc "inline PEM key from file placeholder" (fun () ->
        let f =
          tmp_file "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        in
        let x = ok (Printf.sprintf "server: {tls: {cert: /c, key: '${file:%s}'}}" f) in
        match (Option.get x.tls).key with
        | Config.Pem_inline s ->
            Alcotest.(check bool) "pem" true (contains s "BEGIN PRIVATE KEY")
        | Config.Pem_path _ -> Alcotest.fail "expected inline PEM");
  ]

let oidc_cases =
  [
    tc "oidc pinned with defaults" (fun () ->
        let x = ok (oidc_base "        policy: p1\n") in
        let o = List.hd x.oidc in
        Alcotest.(check string) "name" "corp" o.oidc_name;
        Alcotest.(check string) "issuer" "https://idp.corp.example" o.issuer;
        Alcotest.(check (list string)) "aud" [ "haltsql" ] o.audiences;
        Alcotest.(check (option string)) "jwks" None o.jwks_uri;
        Alcotest.(check (list string))
          "algs" [ "RS256"; "ES256" ]
          (List.map Config.string_of_jwt_alg o.algorithms);
        Alcotest.(check int) "leeway" 60 o.leeway_seconds;
        Alcotest.(check int) "cache" 300 o.jwks_cache_seconds;
        Alcotest.(check bool) "policy" true (o.oidc_policy = Config.Oidc_pinned "p1");
        Alcotest.(check (list string)) "rcf" [] o.oidc_request_context_fields;
        Alcotest.(check bool) "insecure" false o.allow_insecure_http);
    tc "oidc policy_claim with claims" (fun () ->
        let x =
          ok
            (oidc_base
               "        jwks_uri: https://idp.corp.example/keys\n\
               \        algorithms: [PS256, EdDSA, ES384]\n\
               \        leeway_seconds: 300\n\
               \        jwks_cache_seconds: 60\n\
               \        policy_claim: haltsql_policy\n\
               \        allowed_policies: [p1, p2]\n\
               \        context_claims:\n\
               \          tenant_id: 'https://corp.example/tenant'\n\
               \          org_id: org.id\n\
               \        required_claims:\n\
               \          scope: [sql.verify, sql.read]\n\
               \          azp: agent-1\n\
               \        request_context_fields: [user_id]\n")
        in
        let o = List.hd x.oidc in
        Alcotest.(check (option string))
          "jwks" (Some "https://idp.corp.example/keys") o.jwks_uri;
        Alcotest.(check (list string))
          "algs" [ "PS256"; "EdDSA"; "ES384" ]
          (List.map Config.string_of_jwt_alg o.algorithms);
        Alcotest.(check int) "leeway" 300 o.leeway_seconds;
        Alcotest.(check bool)
          "binding" true
          (o.oidc_policy
          = Config.Oidc_from_claim { claim = "haltsql_policy"; allowed = [ "p1"; "p2" ] }
          );
        Alcotest.(check (list (pair string string)))
          "ctx claims"
          [ ("tenant_id", "https://corp.example/tenant"); ("org_id", "org.id") ]
          o.context_claims;
        Alcotest.(check bool)
          "required" true
          (o.required_claims
          = [
              ("scope", Config.Claim_all [ "sql.verify"; "sql.read" ]);
              ("azp", Config.Claim_one "agent-1");
            ]);
        Alcotest.(check (list string)) "rcf" [ "user_id" ] o.oidc_request_context_fields);
    tc "oidc issuer must be https" (fun () ->
        err ~path:(oidc_path "issuer") ~msg:"must use https"
          (Str_replace.replace
             (oidc_base "        policy: p1\n")
             "https://idp" "http://idp"));
    tc "oidc http issuer allowed for tests" (fun () ->
        let x =
          ok
            (Str_replace.replace
               (oidc_base "        policy: p1\n        allow_insecure_http: true\n")
               "https://idp" "http://127.0.0.1:9999/idp")
        in
        Alcotest.(check bool) "insecure" true (List.hd x.oidc).allow_insecure_http);
    tc "oidc issuer without query" (fun () ->
        err ~path:(oidc_path "issuer") ~msg:"must not contain a query"
          (Str_replace.replace
             (oidc_base "        policy: p1\n")
             "idp.corp.example" "idp.corp.example/?x=1"));
    tc "oidc issuer without credentials" (fun () ->
        err ~path:(oidc_path "issuer") ~msg:"must not contain credentials"
          (Str_replace.replace
             (oidc_base "        policy: p1\n")
             "idp.corp" "u:p@idp.corp"));
    tc "oidc audiences non-empty" (fun () ->
        err ~path:(oidc_path "audiences") ~msg:"must not be empty"
          (Str_replace.replace (oidc_base "        policy: p1\n") "[haltsql]" "[]"));
    tc "oidc audiences required" (fun () ->
        err ~path:(oidc_path "audiences") ~msg:"required"
          (Str_replace.replace
             (oidc_base "        policy: p1\n")
             "        audiences: [haltsql]\n" ""));
    tc "oidc duplicate audience" (fun () ->
        err ~path:(oidc_path "audiences[1]") ~msg:"duplicate audience \"a\""
          (Str_replace.replace (oidc_base "        policy: p1\n") "[haltsql]" "[a, a]"));
    tc "oidc alg none rejected" (fun () ->
        err ~path:(oidc_path "algorithms[0]") ~msg:"\"none\" (unsigned tokens) is never"
          (oidc_base "        policy: p1\n        algorithms: [none]\n"));
    tc "oidc HS256 rejected" (fun () ->
        err ~path:(oidc_path "algorithms[1]") ~msg:"symmetric HMAC"
          (oidc_base "        policy: p1\n        algorithms: [RS256, HS256]\n"));
    tc "oidc unknown algorithm" (fun () ->
        err ~path:(oidc_path "algorithms[0]") ~msg:"invalid algorithm \"RS1\""
          (oidc_base "        policy: p1\n        algorithms: [RS1]\n"));
    tc "oidc algorithms non-empty" (fun () ->
        err ~path:(oidc_path "algorithms") ~msg:"must not be empty"
          (oidc_base "        policy: p1\n        algorithms: []\n"));
    tc "oidc leeway max 300" (fun () ->
        err ~path:(oidc_path "leeway_seconds") ~msg:"between 0 and 300"
          (oidc_base "        policy: p1\n        leeway_seconds: 301\n"));
    tc "oidc jwks cache range" (fun () ->
        err
          ~path:(oidc_path "jwks_cache_seconds")
          ~msg:"between 10 and 86400"
          (oidc_base "        policy: p1\n        jwks_cache_seconds: 5\n"));
    tc "oidc jwks_uri must be https" (fun () ->
        err ~path:(oidc_path "jwks_uri") ~msg:"must use https"
          (oidc_base "        policy: p1\n        jwks_uri: http://idp/keys\n"));
    tc "oidc policy and policy_claim exclusive" (fun () ->
        err ~path:"server.auth.oidc[0]" ~msg:"either policy or policy_claim, not both"
          (oidc_base
             "        policy: p1\n\
             \        policy_claim: x\n\
             \        allowed_policies: [p1]\n"));
    tc "oidc needs a policy binding" (fun () ->
        err ~path:"server.auth.oidc[0]" ~msg:"needs policy (pinned) or policy_claim"
          (oidc_base ""));
    tc "oidc policy_claim needs allowed_policies" (fun () ->
        err
          ~path:(oidc_path "allowed_policies")
          ~msg:"required when policy_claim"
          (oidc_base "        policy_claim: x\n"));
    tc "oidc allowed_policies only with policy_claim" (fun () ->
        err
          ~path:(oidc_path "allowed_policies")
          ~msg:"only allowed with policy_claim"
          (oidc_base "        policy: p1\n        allowed_policies: [p1]\n"));
    tc "oidc pinned policy must exist" (fun () ->
        err ~path:(oidc_path "policy") ~msg:"unknown policy \"ghost\""
          (oidc_base "        policy: ghost\n"));
    tc "oidc allowed policy must exist" (fun () ->
        err
          ~path:(oidc_path "allowed_policies[1]")
          ~msg:"unknown policy \"ghost\""
          (oidc_base "        policy_claim: x\n        allowed_policies: [p1, ghost]\n"));
    tc "oidc provider names unique" (fun () ->
        err ~path:"server.auth.oidc[1].name" ~msg:"duplicate OIDC provider name \"corp\""
          (oidc_base
             "        policy: p1\n\
             \      - {name: corp, issuer: 'https://b.example', audiences: [x], policy: \
              p2}\n"));
    tc "oidc context_claims collide with request fields" (fun () ->
        err
          ~path:(oidc_path "request_context_fields[1]")
          ~msg:"context field \"tenant_id\" is already set by context_claims"
          (oidc_base
             "        policy: p1\n\
             \        context_claims: {tenant_id: tid}\n\
             \        request_context_fields: [user_id, tenant_id]\n"));
    tc "oidc invalid context field" (fun () ->
        err
          ~path:(oidc_path "context_claims.1x")
          ~msg:"invalid context field \"1x\""
          (oidc_base "        policy: p1\n        context_claims: {1x: tid}\n"));
    tc "oidc invalid claim path" (fun () ->
        err
          ~path:(oidc_path "context_claims.t")
          ~msg:"invalid claim path \"a..b\""
          (oidc_base "        policy: p1\n        context_claims: {t: a..b}\n"));
    tc "oidc required claim empty list" (fun () ->
        err
          ~path:(oidc_path "required_claims.scope")
          ~msg:"must not be empty"
          (oidc_base "        policy: p1\n        required_claims: {scope: []}\n"));
    tc "oidc required claim type" (fun () ->
        err
          ~path:(oidc_path "required_claims.n")
          ~msg:"expected a string or a list"
          (oidc_base "        policy: p1\n        required_claims: {n: 3}\n"));
    tc "oidc unknown key hint" (fun () ->
        err ~path:(oidc_path "audience") ~msg:"did you mean \"audiences\""
          (oidc_base "        policy: p1\n        audience: x\n"));
  ]

let mtls_cfg ?(tls = mtls_tls) idents =
  "server:\n" ^ tls ^ "  auth:\n    mtls:\n      identities:\n" ^ idents ^ pols

let ident_path k = "server.auth.mtls.identities[0]." ^ k

let mtls_cases =
  [
    tc "mtls identities" (fun () ->
        let x =
          ok
            (mtls_cfg
               "        - spiffe_id: spiffe://corp.example/ns/agents/sa/analytics\n\
               \          policy: p1\n\
               \          context: {tenant_id: acme, org: [a, 7]}\n\
               \          request_context_fields: [user_id]\n\
               \        - {subject_cn: support-bot, policy: p2}\n")
        in
        match x.mtls with
        | [ a; b ] ->
            Alcotest.(check bool)
              "spiffe" true
              (a.mtls_match
             = Config.Spiffe_id "spiffe://corp.example/ns/agents/sa/analytics");
            Alcotest.(check string) "policy" "p1" a.mtls_policy;
            Alcotest.(check bool)
              "ctx" true
              (a.mtls_context
              = [ ("tenant_id", Context.One "acme"); ("org", Context.Many [ "a"; "7" ]) ]
              );
            Alcotest.(check (list string))
              "rcf" [ "user_id" ] a.mtls_request_context_fields;
            Alcotest.(check bool)
              "cn" true
              (b.mtls_match = Config.Subject_cn "support-bot");
            Alcotest.(check bool) "empty ctx" true (b.mtls_context = [])
        | _ -> Alcotest.fail "expected two identities");
    tc "mtls requires client_ca" (fun () ->
        err ~path:"server.auth.mtls" ~msg:"requires server.tls.client_ca"
          (mtls_cfg ~tls:"  tls: {cert: /c, key: /k}\n"
             "        - {subject_cn: a, policy: p1}\n"));
    tc "mtls requires tls at all" (fun () ->
        err ~path:"server.auth.mtls" ~msg:"requires server.tls.client_ca"
          (mtls_cfg ~tls:"" "        - {subject_cn: a, policy: p1}\n"));
    tc "mtls requires client_auth" (fun () ->
        err ~path:"server.auth.mtls" ~msg:"client_auth optional or required"
          (mtls_cfg ~tls:"  tls: {cert: /c, key: /k, client_ca: /ca}\n"
             "        - {subject_cn: a, policy: p1}\n"));
    tc "mtls spiffe and cn exclusive" (fun () ->
        err ~path:"server.auth.mtls.identities[0]" ~msg:"either spiffe_id or subject_cn"
          (mtls_cfg "        - {spiffe_id: 'spiffe://a/b', subject_cn: a, policy: p1}\n"));
    tc "mtls needs a match" (fun () ->
        err ~path:"server.auth.mtls.identities[0]" ~msg:"needs spiffe_id or subject_cn"
          (mtls_cfg "        - {policy: p1}\n"));
    tc "mtls invalid spiffe id" (fun () ->
        err ~path:(ident_path "spiffe_id") ~msg:"invalid SPIFFE ID"
          (mtls_cfg "        - {spiffe_id: 'spiffe://Corp.Example/x', policy: p1}\n");
        err ~path:(ident_path "spiffe_id") ~msg:"invalid SPIFFE ID"
          (mtls_cfg "        - {spiffe_id: 'https://corp.example/x', policy: p1}\n");
        err ~path:(ident_path "spiffe_id") ~msg:"invalid SPIFFE ID"
          (mtls_cfg "        - {spiffe_id: 'spiffe://corp.example/a//b', policy: p1}\n"));
    tc "mtls duplicate identity" (fun () ->
        err ~path:"server.auth.mtls.identities[1].subject_cn"
          ~msg:"duplicate mTLS identity \"a\""
          (mtls_cfg
             "        - {subject_cn: a, policy: p1}\n\
             \        - {subject_cn: a, policy: p2}\n"));
    tc "mtls policy must exist" (fun () ->
        err ~path:(ident_path "policy") ~msg:"unknown policy \"nope\""
          (mtls_cfg "        - {subject_cn: a, policy: nope}\n"));
    tc "mtls static context collides with request fields" (fun () ->
        err
          ~path:(ident_path "request_context_fields[0]")
          ~msg:"\"tenant_id\" is already set by the static context"
          (mtls_cfg
             "        - {subject_cn: a, policy: p1, context: {tenant_id: x}, \
              request_context_fields: [tenant_id]}\n"));
    tc "mtls context value type" (fun () ->
        err ~path:(ident_path "context.t") ~msg:"expected a string or an integer"
          (mtls_cfg "        - {subject_cn: a, policy: p1, context: {t: true}}\n"));
    tc "mtls empty identities needs nothing" (fun () ->
        let x = ok ("server: {auth: {mtls: {identities: []}}}\n" ^ pols) in
        Alcotest.(check int) "none" 0 (List.length x.mtls));
  ]

let telemetry_cases =
  [
    tc "otlp full" (fun () ->
        let x =
          ok
            ~env:(env_of [ ("OTLP_KEY", "k-123") ])
            "telemetry:\n\
            \  otlp:\n\
            \    endpoint: https://collector:4318\n\
            \    headers: {x-api-key: '${env:OTLP_KEY}', X-Tenant: acme}\n\
            \    service_name: haltsql-prod\n\
            \    traces: false\n\
            \    metrics: true\n\
            \    export_interval_seconds: 30\n\
            \    timeout_seconds: 10\n"
        in
        let o = Option.get x.otlp in
        Alcotest.(check string) "endpoint" "https://collector:4318" o.otlp_endpoint;
        Alcotest.(check (list (pair string string)))
          "headers"
          [ ("x-api-key", "k-123"); ("X-Tenant", "acme") ]
          o.otlp_headers;
        Alcotest.(check string) "svc" "haltsql-prod" o.service_name;
        Alcotest.(check bool) "traces" false o.otlp_traces;
        Alcotest.(check bool) "metrics" true o.otlp_metrics;
        Alcotest.(check int) "interval" 30 o.export_interval_seconds;
        Alcotest.(check int) "timeout" 10 o.timeout_seconds);
    tc "otlp defaults" (fun () ->
        let o =
          Option.get (ok "telemetry: {otlp: {endpoint: 'http://collector:4318'}}").otlp
        in
        Alcotest.(check string) "svc" "haltsql" o.service_name;
        Alcotest.(check bool) "traces" true o.otlp_traces;
        Alcotest.(check bool) "metrics" true o.otlp_metrics;
        Alcotest.(check int) "interval" 15 o.export_interval_seconds;
        Alcotest.(check int) "timeout" 5 o.timeout_seconds;
        Alcotest.(check int) "headers" 0 (List.length o.otlp_headers));
    tc "legacy otlp_endpoint shorthand" (fun () ->
        let o = Option.get (ok "telemetry: {otlp_endpoint: 'http://otel:4317'}").otlp in
        Alcotest.(check string) "endpoint" "http://otel:4317" o.otlp_endpoint;
        Alcotest.(check string) "svc" "haltsql" o.service_name);
    tc "no telemetry means no otlp" (fun () ->
        Alcotest.(check bool) "none" true ((ok "").otlp = None));
    tc "otlp and legacy endpoint exclusive" (fun () ->
        err ~path:"telemetry.otlp_endpoint" ~msg:"not both"
          "telemetry: {otlp_endpoint: 'http://a:1', otlp: {endpoint: 'http://b:2'}}");
    tc "otlp endpoint scheme" (fun () ->
        err ~path:"telemetry.otlp.endpoint"
          ~msg:"expected an absolute http:// or https://"
          "telemetry: {otlp: {endpoint: 'ftp://collector'}}");
    tc "otlp endpoint required" (fun () ->
        err ~path:"telemetry.otlp.endpoint" ~msg:"required"
          "telemetry: {otlp: {traces: true}}");
    tc "otlp header injection rejected" (fun () ->
        err
          ~env:(env_of [ ("H", "v\r\nX-Evil: 1") ])
          ~path:"telemetry.otlp.headers.x-h" ~msg:"must not contain CR, LF"
          "telemetry: {otlp: {endpoint: 'http://c:1', headers: {x-h: '${env:H}'}}}");
    tc "otlp invalid header name" (fun () ->
        err ~path:"telemetry.otlp.headers.\"bad header\"" ~msg:"invalid HTTP header name"
          "telemetry: {otlp: {endpoint: 'http://c:1', headers: {'bad header': v}}}");
    tc "otlp interval range" (fun () ->
        err ~path:"telemetry.otlp.export_interval_seconds" ~msg:"between 1 and 3600"
          "telemetry: {otlp: {endpoint: 'http://c:1', export_interval_seconds: 0}}");
    tc "legacy otlp_endpoint validated" (fun () ->
        err ~path:"telemetry.otlp_endpoint" ~msg:"invalid URL"
          "telemetry: {otlp_endpoint: 'collector:4317'}");
  ]

let sink_path k = "audit.sinks[0]." ^ k

let audit_cases =
  [
    tc "s3 sink full" (fun () ->
        let x =
          ok
            "audit:\n\
            \  sinks:\n\
            \    - type: s3\n\
            \      bucket: corp-audit.logs\n\
            \      prefix: hs/\n\
            \      region: eu-west-1\n\
            \      endpoint: http://127.0.0.1:9000\n\
            \      object_lock: {mode: COMPLIANCE, retain_days: 365}\n\
            \      batch: {max_records: 100, max_seconds: 2}\n\
            \      credentials: {source: static, access_key_id: AK, secret_access_key: \
             SK, session_token: ST}\n\
            \      on_error: buffer\n"
        in
        match x.sinks with
        | [ { sink = Config.Sink_s3 s; on_error = Config.Buffer } ] ->
            Alcotest.(check string) "bucket" "corp-audit.logs" s.s3_bucket;
            Alcotest.(check string) "prefix" "hs/" s.s3_prefix;
            Alcotest.(check string) "region" "eu-west-1" s.s3_region;
            Alcotest.(check (option string))
              "endpoint" (Some "http://127.0.0.1:9000") s.s3_endpoint;
            Alcotest.(check bool)
              "lock" true
              (s.s3_object_lock
              = Some { lock_mode = Config.Compliance; retain_days = 365 });
            Alcotest.(check bool)
              "batch" true
              (s.s3_batch = { max_records = 100; max_seconds = 2 });
            Alcotest.(check bool)
              "creds" true
              (s.s3_credentials
              = Config.S3_static
                  {
                    access_key_id = "AK";
                    secret_access_key = "SK";
                    session_token = Some "ST";
                  });
            Alcotest.(check bool) "legacy projection" true (x.audit_sinks = [])
        | _ -> Alcotest.fail "expected one s3 sink");
    tc "s3 sink defaults" (fun () ->
        let x =
          ok
            "audit: {sinks: [{type: stdout}, {type: s3, bucket: b-1, region: us-east-1}]}"
        in
        match x.sinks with
        | [
         { sink = Config.Sink_stdout; on_error = Config.Fail_closed };
         { sink = Config.Sink_s3 s; on_error = Config.Fail_closed };
        ] ->
            Alcotest.(check string) "prefix" "haltsql/audit/" s.s3_prefix;
            Alcotest.(check bool)
              "batch" true
              (s.s3_batch = { max_records = 500; max_seconds = 10 });
            Alcotest.(check bool) "creds" true (s.s3_credentials = Config.S3_env);
            Alcotest.(check bool) "lock" true (s.s3_object_lock = None);
            Alcotest.(check bool) "legacy" true (x.audit_sinks = [ Config.Audit_stdout ])
        | _ -> Alcotest.fail "unexpected sinks");
    tc "s3 credential sources" (fun () ->
        let src s =
          match
            (ok
               (Printf.sprintf
                  "audit: {sinks: [{type: s3, bucket: bbb, region: r1, credentials: \
                   {source: %s}}]}"
                  s))
              .sinks
          with
          | [ { sink = Config.Sink_s3 x; _ } ] -> x.s3_credentials
          | _ -> Alcotest.fail "sink"
        in
        Alcotest.(check bool) "env" true (src "env" = Config.S3_env);
        Alcotest.(check bool) "wi" true (src "web_identity" = Config.S3_web_identity);
        Alcotest.(check bool) "instance" true (src "instance" = Config.S3_instance));
    tc "s3 static needs secret" (fun () ->
        err
          ~path:(sink_path "credentials.secret_access_key")
          ~msg:"required"
          "audit: {sinks: [{type: s3, bucket: bbb, region: r1, credentials: {source: \
           static, access_key_id: AK}}]}");
    tc "s3 static keys only with static" (fun () ->
        err
          ~path:(sink_path "credentials.access_key_id")
          ~msg:"only allowed when source is static"
          "audit: {sinks: [{type: s3, bucket: bbb, region: r1, credentials: \
           {access_key_id: AK}}]}");
    tc "s3 bucket name" (fun () ->
        err ~path:(sink_path "bucket") ~msg:"invalid bucket name \"Bad_Bucket\""
          "audit: {sinks: [{type: s3, bucket: Bad_Bucket, region: r1}]}");
    tc "s3 region required" (fun () ->
        err ~path:(sink_path "region") ~msg:"required"
          "audit: {sinks: [{type: s3, bucket: bbb}]}");
    tc "s3 object lock validation" (fun () ->
        err
          ~path:(sink_path "object_lock.mode")
          ~msg:"invalid value \"governance\""
          "audit: {sinks: [{type: s3, bucket: bbb, region: r1, object_lock: {mode: \
           governance, retain_days: 1}}]}";
        err
          ~path:(sink_path "object_lock.retain_days")
          ~msg:"between 1 and 36500"
          "audit: {sinks: [{type: s3, bucket: bbb, region: r1, object_lock: {mode: \
           GOVERNANCE, retain_days: 0}}]}");
    tc "batch range" (fun () ->
        err
          ~path:(sink_path "batch.max_records")
          ~msg:"between 1 and 100000"
          "audit: {sinks: [{type: s3, bucket: bbb, region: r1, batch: {max_records: 0}}]}");
    tc "s3 prefix must be relative" (fun () ->
        err ~path:(sink_path "prefix") ~msg:"must not start with '/'"
          "audit: {sinks: [{type: s3, bucket: bbb, region: r1, prefix: /abs/}]}");
    tc "on_error enum and file sinks" (fun () ->
        let x = ok "audit: {sinks: [{type: file, path: a.jsonl, on_error: buffer}]}" in
        Alcotest.(check bool)
          "file" true
          (x.sinks
          = [
              { sink = Config.Sink_file "/etc/haltsql/a.jsonl"; on_error = Config.Buffer };
            ]);
        Alcotest.(check bool)
          "legacy" true
          (x.audit_sinks = [ Config.Audit_file "/etc/haltsql/a.jsonl" ]);
        err ~path:(sink_path "on_error") ~msg:"invalid value \"retry\""
          "audit: {sinks: [{type: stdout, on_error: retry}]}");
    tc "gcs sink" (fun () ->
        let x =
          ok
            "audit: {sinks: [{type: gcs, bucket: my_bucket, credentials: {source: \
             service_account_file, file: sa.json}}]}"
        in
        match x.sinks with
        | [ { sink = Config.Sink_gcs g; on_error = Config.Fail_closed } ] ->
            Alcotest.(check string) "bucket" "my_bucket" g.gcs_bucket;
            Alcotest.(check string) "prefix" "haltsql/audit/" g.gcs_prefix;
            Alcotest.(check bool)
              "creds" true
              (g.gcs_credentials = Config.Gcs_service_account_file "/etc/haltsql/sa.json")
        | _ -> Alcotest.fail "expected gcs");
    tc "gcs defaults to metadata" (fun () ->
        match (ok "audit: {sinks: [{type: gcs, bucket: bkt}]}").sinks with
        | [ { sink = Config.Sink_gcs g; _ } ] ->
            Alcotest.(check bool) "metadata" true (g.gcs_credentials = Config.Gcs_metadata)
        | _ -> Alcotest.fail "expected gcs");
    tc "gcs service account needs file" (fun () ->
        err
          ~path:(sink_path "credentials.file")
          ~msg:"required"
          "audit: {sinks: [{type: gcs, bucket: bkt, credentials: {source: \
           service_account_file}}]}");
    tc "gcs metadata forbids file" (fun () ->
        err
          ~path:(sink_path "credentials.file")
          ~msg:"only allowed when source is service_account_file"
          "audit: {sinks: [{type: gcs, bucket: bkt, credentials: {source: metadata, \
           file: x}}]}");
    tc "sink keys depend on type" (fun () ->
        err ~path:(sink_path "region") ~msg:"unknown key \"region\""
          "audit: {sinks: [{type: gcs, bucket: bkt, region: r1}]}";
        err ~path:(sink_path "bucket") ~msg:"unknown key \"bucket\""
          "audit: {sinks: [{type: stdout, bucket: bkt}]}");
  ]

let secrets_doc =
  "secrets:\n\
  \  vault:\n\
  \    address: https://vault.corp:8200\n\
  \    namespace: team-a\n\
  \    auth: {method: token, token: '${env:VAULT_TOKEN}'}\n\
  \    ca_file: ca.pem\n\
  \  aws: {region: us-east-1, endpoint: 'http://127.0.0.1:4566'}\n\
  \  gcp: {project: corp-proj}\n"

let secrets_of s =
  match yaml (head ^ s) with
  | Error e -> Error e
  | Ok j ->
      Config.secrets_of_json ~base_dir:"/etc/haltsql"
        ~env:(env_of [ ("VAULT_TOKEN", "s.vault-token") ])
        j

let secrets_cases =
  [
    tc "secrets section decoded" (fun () ->
        let x = ok ~env:(env_of [ ("VAULT_TOKEN", "s.vault-token") ]) secrets_doc in
        let v = Option.get x.secrets.vault in
        Alcotest.(check string) "address" "https://vault.corp:8200" v.vault_address;
        Alcotest.(check (option string)) "ns" (Some "team-a") v.vault_namespace;
        Alcotest.(check bool)
          "auth" true
          (v.vault_auth = Config.Vault_token "s.vault-token");
        Alcotest.(check (option string)) "ca" (Some "/etc/haltsql/ca.pem") v.vault_ca_file;
        Alcotest.(check bool)
          "aws" true
          (x.secrets.aws
          = Some { aws_region = "us-east-1"; aws_endpoint = Some "http://127.0.0.1:4566" }
          );
        Alcotest.(check bool)
          "gcp" true
          (x.secrets.gcp = Some { gcp_project = Some "corp-proj"; gcp_endpoint = None }));
    tc "secrets_of_json first pass" (fun () ->
        (* other sections are not validated in the first pass *)
        let s = get_ok (secrets_of (secrets_doc ^ "server: {listen: bogus}\n")) in
        Alcotest.(check bool)
          "token" true
          ((Option.get s.vault).vault_auth = Config.Vault_token "s.vault-token"));
    tc "secrets_of_json without secrets" (fun () ->
        Alcotest.(check bool) "none" true (get_ok (secrets_of "") = Config.no_secrets));
    tc "secrets_of_json reports errors" (fun () ->
        check_err ~path:"secrets.vault.auth" ~msg:"required"
          (secrets_of "secrets: {vault: {address: 'https://v'}}"));
    tc "vault kubernetes defaults" (fun () ->
        let x =
          ok
            "secrets: {vault: {address: 'https://v:8200', auth: {method: kubernetes, \
             role: hs}}}"
        in
        Alcotest.(check bool)
          "k8s" true
          ((Option.get x.secrets.vault).vault_auth
          = Config.Vault_kubernetes
              {
                role = "hs";
                jwt_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";
                mount = "kubernetes";
              }));
    tc "vault approle" (fun () ->
        let x =
          ok
            "secrets: {vault: {address: 'https://v', auth: {method: approle, role_id: r, \
             secret_id: s, mount: corp/approle}}}"
        in
        Alcotest.(check bool)
          "approle" true
          ((Option.get x.secrets.vault).vault_auth
          = Config.Vault_approle
              { role_id = "r"; secret_id = "s"; mount = "corp/approle" });
        err ~path:"secrets.vault.auth.secret_id" ~msg:"required"
          "secrets: {vault: {address: 'https://v', auth: {method: approle, role_id: r}}}");
    tc "vault method-specific fields" (fun () ->
        err ~path:"secrets.vault.auth.role" ~msg:"not used by method token"
          "secrets: {vault: {address: 'https://v', auth: {method: token, token: t, role: \
           x}}}");
    tc "vault address must be https unless loopback" (fun () ->
        err ~path:"secrets.vault.address" ~msg:"only allowed for loopback"
          "secrets: {vault: {address: 'http://vault.corp:8200', auth: {method: token, \
           token: t}}}";
        let x =
          ok
            "secrets: {vault: {address: 'http://127.0.0.1:8200', auth: {method: token, \
             token: t}}}"
        in
        Alcotest.(check bool) "loopback ok" true (x.secrets.vault <> None);
        (* regression: a DNS name starting with "127." is not loopback *)
        err ~path:"secrets.vault.address" ~msg:"only allowed for loopback"
          "secrets: {vault: {address: 'http://127.attacker.example:8200', auth: {method: \
           token, token: t}}}");
    tc "provider placeholders not allowed in secrets" (fun () ->
        let r, _ = fake_resolver () in
        err ~resolve:r ~path:"secrets.vault.auth.token"
          ~msg:"cannot be used inside the secrets section"
          "secrets: {vault: {address: 'https://v', auth: {method: token, token: \
           '${vault:secret/x#y}'}}}");
    tc "aws region required" (fun () ->
        err ~path:"secrets.aws.region" ~msg:"required"
          "secrets: {aws: {endpoint: 'http://x'}}");
  ]

let placeholder_cases =
  [
    tc "vault placeholder resolved" (fun () ->
        let r, calls = fake_resolver () in
        let x =
          ok ~resolve:r
            "telemetry: {otlp: {endpoint: 'https://c', headers: {authorization: 'Bearer \
             ${vault:secret/data/otel#token}'}}}"
        in
        Alcotest.(check (list (pair string string)))
          "header"
          [ ("authorization", "Bearer vault-otel-token") ]
          (Option.get x.otlp).otlp_headers;
        Alcotest.(check (list (pair string string)))
          "calls"
          [ ("vault", "secret/data/otel#token") ]
          !calls);
    tc "aws-sm and gcp-sm placeholders" (fun () ->
        let r, _ = fake_resolver () in
        let x =
          ok ~resolve:r
            "audit: {sinks: [{type: s3, bucket: bbb, region: r1, credentials: {source: \
             static, access_key_id: '${aws-sm:prod/s3-key}', secret_access_key: \
             '${aws-sm:prod/s3#secret}'}}]}\n\
             telemetry: {otlp: {endpoint: 'https://c', headers: {x-g: \
             '${gcp-sm:projects/p/secrets/hdr/versions/latest}'}}}\n"
        in
        (match x.sinks with
        | [ { sink = Config.Sink_s3 { s3_credentials = Config.S3_static s; _ }; _ } ] ->
            Alcotest.(check string) "ak" "AKIAFAKE" s.access_key_id;
            Alcotest.(check string) "sk" "aws-secret-key" s.secret_access_key
        | _ -> Alcotest.fail "sink");
        Alcotest.(check (list (pair string string)))
          "gcp"
          [ ("x-g", "gcp-header") ]
          (Option.get x.otlp).otlp_headers);
    tc "missing resolver is a located error" (fun () ->
        err ~path:"telemetry.otlp.headers.a" ~msg:"secret provider not configured"
          "telemetry: {otlp: {endpoint: 'https://c', headers: {a: '${vault:kv/a#b}'}}}");
    tc "resolver error is located" (fun () ->
        let r, _ = fake_resolver () in
        err ~resolve:r ~path:"telemetry.otlp.headers.a"
          ~msg:"${aws-sm:nope}: no such secret"
          "telemetry: {otlp: {endpoint: 'https://c', headers: {a: '${aws-sm:nope}'}}}");
    tc "vault reference needs a field" (fun () ->
        let r, calls = fake_resolver () in
        err ~resolve:r ~path:"telemetry.otlp.headers.a"
          ~msg:"expected ${vault:<path>#<field>}"
          "telemetry: {otlp: {endpoint: 'https://c', headers: {a: '${vault:kv/a}'}}}";
        Alcotest.(check int) "not called" 0 (List.length !calls));
    tc "empty json key rejected" (fun () ->
        err ~path:"telemetry.otlp.headers.a" ~msg:"invalid ${gcp-sm:s#} reference"
          "telemetry: {otlp: {endpoint: 'https://c', headers: {a: '${gcp-sm:s#}'}}}");
    tc "each reference resolved once" (fun () ->
        let r, calls = fake_resolver () in
        ignore
          (ok ~resolve:r
             "telemetry: {otlp: {endpoint: 'https://c', headers: {a: \
              '${vault:secret/data/otel#token}', b: '${vault:secret/data/otel#token}'}}}");
        Alcotest.(check int) "one call" 1 (List.length !calls));
    tc "provider placeholders still rejected in inline policies" (fun () ->
        let r, calls = fake_resolver () in
        err ~resolve:r ~path:"policies[0].inline.dialect"
          ~msg:"unsupported dialect \"${vault:secret/data/otel#token}\""
          "policies:\n\
          \  - inline:\n\
          \      metadata: {name: p}\n\
          \      dialect: '${vault:secret/data/otel#token}'\n";
        Alcotest.(check int) "resolver not called" 0 (List.length !calls));
    tc "unknown scheme lists providers" (fun () ->
        err ~path:"logging.level" ~msg:"${vault:path#field}"
          "logging: {level: '${azure:x}'}");
  ]

let b64_key = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

let bundle_cases =
  [
    tc "bundle entry parsed" (fun () ->
        let x =
          ok
            (Printf.sprintf
               "policies:\n\
               \  - bundle: bundles/prod.haltsqlbundle\n\
               \    public_keys:\n\
               \      - keys/release.pub\n\
               \      - '%s'\n\
               \      - |\n\
               \        -----BEGIN PUBLIC KEY-----\n\
               \        MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n\
               \        -----END PUBLIC KEY-----\n\
               \    name_prefix: prod.\n\
               \  - inline: {metadata: {name: local}}\n"
               b64_key)
        in
        Alcotest.(check (list string)) "plain" [ "local" ] (List.map fst x.policies);
        match x.policy_bundles with
        | [ b ] -> (
            Alcotest.(check string)
              "path" "/etc/haltsql/bundles/prod.haltsqlbundle" b.bundle_path;
            Alcotest.(check (option string)) "prefix" (Some "prod.") b.name_prefix;
            match b.public_keys with
            | [ Config.Key_path p; Config.Key_base64 k; Config.Key_pem pem ] ->
                Alcotest.(check string) "key path" "/etc/haltsql/keys/release.pub" p;
                Alcotest.(check string) "b64" b64_key k;
                Alcotest.(check bool) "pem" true (contains pem "BEGIN PUBLIC KEY")
            | _ -> Alcotest.fail "unexpected keys")
        | _ -> Alcotest.fail "expected one bundle");
    tc "bundle needs public keys" (fun () ->
        err ~path:"policies[0].public_keys" ~msg:"required"
          "policies:\n  - bundle: a.haltsqlbundle\n";
        err ~path:"policies[0].public_keys" ~msg:"must not be empty"
          "policies:\n  - {bundle: a.haltsqlbundle, public_keys: []}\n");
    tc "bundle exclusive with path" (fun () ->
        err ~path:"policies[0]" ~msg:"only one of path, inline or bundle"
          "policies:\n  - {bundle: a.haltsqlbundle, path: p.yaml, public_keys: [k]}\n");
    tc "public_keys only with bundle" (fun () ->
        err ~path:"policies[0].public_keys" ~msg:"only allowed with bundle"
          "policies:\n  - {inline: {metadata: {name: p}}, public_keys: [k]}\n");
    tc "inline PEM must be a public key" (fun () ->
        err ~path:"policies[0].public_keys[0]" ~msg:"must be a public key"
          "policies:\n\
          \  - bundle: a.haltsqlbundle\n\
          \    public_keys: ['-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----']\n");
    tc "duplicate bundle" (fun () ->
        err ~path:"policies[1].bundle" ~msg:"duplicate bundle"
          "policies:\n\
          \  - {bundle: a.b, public_keys: [k]}\n\
          \  - {bundle: ./a.b, public_keys: [k]}\n");
    tc "invalid name_prefix" (fun () ->
        err ~path:"policies[0].name_prefix" ~msg:"invalid name_prefix \"-x\""
          "policies:\n  - {bundle: a.b, public_keys: [k], name_prefix: '-x'}\n");
    tc "unknown policy refs allowed with bundles" (fun () ->
        let x =
          ok
            ("server: {auth: {tokens: [{name: a, token_sha256: " ^ h1
           ^ ", policy: from-bundle}]}}\n\
              default_policy: also-from-bundle\n\
              policies:\n\
             \  - {bundle: a.b, public_keys: [k]}\n")
        in
        Alcotest.(check (option string))
          "default" (Some "also-from-bundle") x.default_policy);
    tc "bundle name_prefix restricts unknown refs" (fun () ->
        let base =
          "policies:\n  - {bundle: a.b, public_keys: [k], name_prefix: prod.}\n"
          ^ oidc_base "        policy: %s\n"
        in
        let mk p = Str_replace.replace base "%s" p in
        ignore (ok (Str_replace.replace (mk "prod.analytics") pols ""));
        err ~path:(oidc_path "policy") ~msg:"not matching any bundle name_prefix: prod."
          (Str_replace.replace (mk "dev.analytics") pols ""));
  ]

let redaction_cases =
  [
    tc "redaction of every secret" (fun () ->
        let r, _ = fake_resolver () in
        let x =
          ok ~resolve:r
            ~env:(env_of [ ("VAULT_TOKEN", "s.SUPERSECRET") ])
            ("server:\n" ^ mtls_tls
           ^ "telemetry: {otlp: {endpoint: 'https://collector', headers: {authorization: \
              '${vault:secret/data/otel#token}'}}}\n\
              audit: {sinks: [{type: s3, bucket: bbb, region: r1, credentials: {source: \
              static, access_key_id: AKIDSECRET, secret_access_key: SKSECRET, \
              session_token: STSECRET}}]}\n\
              secrets:\n\
             \  vault: {address: 'https://v', auth: {method: token, token: \
              '${env:VAULT_TOKEN}'}}\n")
        in
        let s = Yojson.Safe.to_string (Config.to_json_redacted x) in
        List.iter
          (fun secret -> Alcotest.(check bool) secret false (contains s secret))
          [
            "vault-otel-token";
            "AKIDSECRET";
            "SKSECRET";
            "STSECRET";
            "s.SUPERSECRET";
            "/k.pem";
          ];
        List.iter
          (fun shown -> Alcotest.(check bool) shown true (contains s shown))
          [
            "https://collector";
            "authorization";
            "\"bbb\"";
            "/c.pem";
            "/ca.pem";
            "required";
          ]);
    tc "approle ids redacted" (fun () ->
        let x =
          ok
            "secrets: {vault: {address: 'https://v', auth: {method: approle, role_id: \
             ROLEID1, secret_id: SECRETID1}}}"
        in
        let s = Yojson.Safe.to_string (Config.to_json_redacted x) in
        Alcotest.(check bool) "role id" false (contains s "ROLEID1");
        Alcotest.(check bool) "secret id" false (contains s "SECRETID1");
        Alcotest.(check bool) "mount" true (contains s "approle"));
    tc "redacted output shows new sections" (fun () ->
        let x = ok (oidc_base "        policy: p1\n") in
        let j = Config.to_json_redacted x in
        let open Yojson.Safe.Util in
        Alcotest.(check string)
          "issuer" "https://idp.corp.example"
          (j |> member "server" |> member "auth" |> member "oidc" |> index 0
         |> member "issuer" |> to_string));
  ]

let legacy_cases =
  [
    tc "default record keeps legacy values" (fun () ->
        let x = ok "" in
        Alcotest.(check bool) "audit_sinks" true (x.audit_sinks = [ Config.Audit_stdout ]);
        Alcotest.(check bool)
          "sinks" true
          (x.sinks = [ { sink = Config.Sink_stdout; on_error = Config.Fail_closed } ]);
        Alcotest.(check bool) "tls" true (x.tls = None);
        Alcotest.(check bool) "oidc" true (x.oidc = [] && x.mtls = []);
        Alcotest.(check bool) "secrets" true (x.secrets = Config.no_secrets);
        Alcotest.(check bool) "bundles" true (x.policy_bundles = []);
        Alcotest.(check bool)
          "same as default" true
          ({ x with policies = [] } = { Config.default with policies = [] }));
    tc "example config keeps working with otlp shorthand" (fun () ->
        let x =
          get_ok
            (Config.of_file
               ~env:
                 (env_of
                    [
                      ("HALTSQL_ANALYTICS_TOKEN_HASH", h1);
                      ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel:4317");
                    ])
               (ex "config/haltsql.yaml"))
        in
        Alcotest.(check (option string))
          "otlp" (Some "http://otel:4317")
          (Option.map (fun (o : Config.otlp) -> o.otlp_endpoint) x.otlp);
        Alcotest.(check int) "sinks" 2 (List.length x.sinks);
        Alcotest.(check int) "legacy sinks" 2 (List.length x.audit_sinks));
    tc "of_file accepts a resolver" (fun () ->
        let f = Filename.temp_file "hs" ".yaml" in
        Out_channel.with_open_bin f (fun oc ->
            output_string oc
              (head
             ^ "telemetry: {otlp: {endpoint: 'https://c', headers: {a: \
                '${vault:secret/data/otel#token}'}}}\n"));
        let r, _ = fake_resolver () in
        let x = get_ok (Config.of_file ~env:no_env ~resolve:r f) in
        Alcotest.(check (list (pair string string)))
          "h"
          [ ("a", "vault-otel-token") ]
          (Option.get x.otlp).otlp_headers;
        let e = get_err (Config.of_file ~env:no_env f) in
        Alcotest.(check bool)
          "located with line" true
          (List.exists (fun (e : Load_error.t) -> e.line = Some 3) e));
  ]

let tests =
  [
    ("config-tls", tls_cases);
    ("config-oidc", oidc_cases);
    ("config-mtls", mtls_cases);
    ("config-telemetry", telemetry_cases);
    ("config-audit", audit_cases);
    ("config-secrets", secrets_cases);
    ("config-placeholders", placeholder_cases);
    ("config-bundles", bundle_cases);
    ("config-redaction", redaction_cases);
    ("config-legacy", legacy_cases);
  ]
