(* haltsql-server.opa tests.

   Pure: input encoding, strict response parsing, verdict combination.
   Integration (real openpolicyagent/opa containers, no fake OPA):
     haltsql-identity-opa        127.0.0.1:18181  examples/opa + fixtures
                                 (host network, loopback only)
     haltsql-identity-opa-authz  127.0.0.1:18182  token authentication (headers)
     haltsql-identity-opa-tls    127.0.0.1:18184  https with a test CA
   and the reverse direction: the example verify_gate.rego in OPA calling a
   real haltsql-server (the built binary) on 127.0.0.1:18183 with http.send.
   Integration tests skip, with a message, when Docker is unavailable. *)

module Config = Haltsql.Config
module Verdict = Haltsql.Verdict
module Reason = Haltsql.Reason
module Policy = Haltsql.Policy
module Http = Haltsql_cloud.Http
module Opa = Haltsql_opa.Opa

(* The external-policy reason code (docs/reason-codes.md#e_external_policy). *)
let code = Reason.E_EXTERNAL_POLICY
let image = "openpolicyagent/opa:1.10.1"
let opa_port = 18181
let authz_port = 18182
let server_port = 18183
let tls_port = 18184
let closed_port = 18189
let authz_token = "haltsql-identity-test-token"
let run = Lwt_main.run

let cfg ?(on_error = Config.Opa_deny) ?(timeout = 3000) ?(headers = []) ?ca
    ?(url = Printf.sprintf "http://127.0.0.1:%d" opa_port) path : Config.opa =
  {
    opa_url = url;
    decision_path = path;
    opa_timeout_ms = timeout;
    opa_on_error = on_error;
    opa_headers = headers;
    opa_ca = ca;
  }

(* ---- a real verdict from a real policy ---- *)

let policy_json =
  {|{
  "apiVersion": "haltsql.dev/v1",
  "kind": "Policy",
  "metadata": {"name": "p"},
  "search_path": ["app"],
  "statements": {"allow": ["select"]},
  "tables": {
    "app.orders": {"columns": ["id", "total_cents"]},
    "app.invoices": {"columns": ["id", "amount_cents"]},
    "app.customers": {"columns": ["id", "email"]}
  }
}|}

let policy =
  lazy
    (match Haltsql.Policy_load.of_json (Yojson.Safe.from_string policy_json) with
    | Ok p -> p
    | Error _ -> Alcotest.fail "test policy does not load")

let shadow_policy = lazy { (Lazy.force policy) with Policy.mode = Policy.Shadow }
let ctx = Haltsql.Context.make [ ("tenant_id", One "acme-secret-value") ]
let verify ?(p = policy) sql = Haltsql.verify (Lazy.force p) ctx sql
let token_caller : Opa.caller = { caller_name = "analytics-agent"; caller_type = "token" }
let oidc_caller : Opa.caller = { caller_name = "oidc:corp"; caller_type = "oidc" }

let input ?(caller = token_caller) sql =
  Opa.input_of_verdict ~caller ~context:ctx (verify sql)

let outcome_t =
  Alcotest.testable
    (fun f o ->
      Format.pp_print_string f
        (match o with
        | Opa.Skipped -> "Skipped"
        | Allowed -> "Allowed"
        | Denied rs -> "Denied [" ^ String.concat "; " rs ^ "]"
        | Failed_open e -> "Failed_open " ^ e
        | Failed_closed e -> "Failed_closed " ^ e))
    ( = )

let contains s sub =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  go 0

let check_failed_closed ~sub o =
  match o with
  | Opa.Failed_closed e ->
      if not (contains e sub) then Alcotest.failf "error %S does not mention %S" e sub
  | o -> Alcotest.failf "expected Failed_closed, got %s" (Opa.outcome_label o)

(* ---- pure ---- *)

let parse status body = Opa.parse_response ~status body

let decision_t =
  Alcotest.testable
    (fun f -> function
      | Opa.Allow -> Format.pp_print_string f "Allow"
      | Deny rs -> Format.fprintf f "Deny [%s]" (String.concat "; " rs))
    ( = )

let ok_decision = Alcotest.(result decision_t string)

let test_parse_ok () =
  Alcotest.check ok_decision "true" (Ok Opa.Allow) (parse 200 {|{"result": true}|});
  Alcotest.check ok_decision "false" (Ok (Opa.Deny [])) (parse 200 {|{"result": false}|});
  Alcotest.check ok_decision "object allow" (Ok Opa.Allow)
    (parse 200 {|{"result": {"allow": true, "reasons": ["ignored"]}}|});
  Alcotest.check ok_decision "object deny"
    (Ok (Opa.Deny [ "a"; "b" ]))
    (parse 200 {|{"result": {"allow": false, "reasons": ["a", "b"]}}|});
  Alcotest.check ok_decision "object deny without reasons" (Ok (Opa.Deny []))
    (parse 200 {|{"result": {"allow": false}}|});
  Alcotest.check ok_decision "decision_id and metrics are fine" (Ok Opa.Allow)
    (parse 200 {|{"decision_id": "x", "metrics": {}, "result": true}|})

let is_error what r =
  match r with Error _ -> () | Ok _ -> Alcotest.failf "%s: expected an error" what

let test_parse_strict () =
  is_error "status" (parse 500 {|{"result": true}|});
  is_error "status 204" (parse 204 {|{"result": true}|});
  is_error "undefined" (parse 200 {|{}|});
  is_error "not json" (parse 200 "true!");
  is_error "array body" (parse 200 "[true]");
  is_error "string result" (parse 200 {|{"result": "true"}|});
  is_error "number result" (parse 200 {|{"result": 1}|});
  is_error "null result" (parse 200 {|{"result": null}|});
  is_error "extra key" (parse 200 {|{"result": {"allow": true, "why": "x"}}|});
  is_error "allow not bool" (parse 200 {|{"result": {"allow": "true"}}|});
  is_error "no allow" (parse 200 {|{"result": {"reasons": []}}|});
  is_error "reasons not strings"
    (parse 200 {|{"result": {"allow": false, "reasons": [1]}}|});
  is_error "reasons not array"
    (parse 200 {|{"result": {"allow": false, "reasons": "x"}}|});
  is_error "duplicate result" (parse 200 {|{"result": true, "result": false}|});
  is_error "duplicate allow" (parse 200 {|{"result": {"allow": false, "allow": true}}|});
  (* an error never echoes the response body *)
  match parse 200 {|{"result": "secret-ish-value"}|} with
  | Error e -> Alcotest.(check bool) "no echo" false (contains e "secret-ish")
  | Ok _ -> Alcotest.fail "expected error"

let test_reason_sanitizing () =
  let many = List.init 40 (fun i -> Printf.sprintf "\"r%d\"" i) in
  (match
     parse 200
       (Printf.sprintf {|{"result": {"allow": false, "reasons": [%s]}}|}
          (String.concat "," many))
   with
  | Ok (Opa.Deny rs) -> Alcotest.(check int) "capped" Opa.max_reasons (List.length rs)
  | _ -> Alcotest.fail "expected Deny");
  (match
     parse 200 {|{"result": {"allow": false, "reasons": ["a\nb\u0000c", "   "]}}|}
   with
  | Ok (Opa.Deny rs) -> Alcotest.(check (list string)) "control chars" [ "a b c" ] rs
  | _ -> Alcotest.fail "expected Deny");
  match
    parse 200
      (Printf.sprintf {|{"result": {"allow": false, "reasons": ["%s"]}}|}
         (String.make 500 'x'))
  with
  | Ok (Opa.Deny [ r ]) -> Alcotest.(check int) "truncated" 203 (String.length r)
  | _ -> Alcotest.fail "expected Deny"

let test_decision_url () =
  let u c = Result.map Uri.to_string (Opa.decision_url c) in
  Alcotest.(check (result string string))
    "plain" (Ok "http://127.0.0.1:18181/v1/data/haltsql/allow")
    (u (cfg "haltsql/allow"));
  Alcotest.(check (result string string))
    "trailing slash" (Ok "https://opa.example/v1/data/a/b")
    (u (cfg ~url:"https://opa.example/" "a/b"));
  is_error "http non-loopback" (u (cfg ~url:"http://opa.example" "a"));
  is_error "query" (u (cfg ~url:"https://opa.example/?x=1" "a"));
  is_error "credentials" (u (cfg ~url:"https://u:p@opa.example" "a"));
  is_error "bad path" (u (cfg "../admin"));
  is_error "leading slash" (u (cfg "/haltsql/allow"));
  is_error "empty segment" (u (cfg "haltsql//allow"))

let test_input_json () =
  let i = input "SELECT id FROM app.orders" in
  let j = Opa.input_to_json i in
  let keys = match j with `Assoc kv -> List.map fst kv | _ -> [] in
  Alcotest.(check (list string))
    "keys"
    [
      "caller";
      "policy";
      "policy_version";
      "statement_kind";
      "tables";
      "columns";
      "reasons";
      "shadow_reasons";
      "allowed";
      "sql_sha256";
      "fingerprint";
      "context_keys";
    ]
    keys;
  let s = Yojson.Safe.to_string j in
  Alcotest.(check bool) "no context value" false (contains s "acme-secret-value");
  Alcotest.(check bool) "no SQL" false (contains s "SELECT");
  Alcotest.(check (list string)) "context keys" [ "tenant_id" ] i.context_keys;
  Alcotest.(check (list string)) "tables" [ "app.orders" ] i.tables;
  Alcotest.(check bool) "allowed" true i.allowed

let test_apply () =
  let c = cfg "haltsql/decision" in
  let allowed = verify "SELECT id FROM app.orders" in
  let denied = verify "SELECT * FROM app.secrets" in
  Alcotest.(check bool) "precondition: allowed" true allowed.allowed;
  Alcotest.(check bool) "precondition: denied" false denied.allowed;
  let ap ?(mode = Policy.Enforce) v o = Opa.apply ~code ~mode c v o in
  (* OPA deny turns an allow into a deny, with one reason per OPA reason *)
  let v = ap allowed (Opa.Denied [ "r1"; "r2" ]) in
  Alcotest.(check bool) "denied" false v.allowed;
  Alcotest.(check (list string))
    "codes"
    [ Reason.code_to_string code; Reason.code_to_string code ]
    (List.map (fun (r : Reason.t) -> Reason.code_to_string r.code) v.reasons);
  Alcotest.(check bool) "message" true (contains (List.hd v.reasons).message "r1");
  Alcotest.(check string) "rule" "opa.decision" (List.hd v.reasons).rule;
  (* no OPA reasons: one generic reason *)
  Alcotest.(check int) "generic" 1 (List.length (ap allowed (Opa.Denied [])).reasons);
  (* failures *)
  let v = ap allowed (Opa.Failed_closed "boom") in
  Alcotest.(check bool) "failed closed denies" false v.allowed;
  Alcotest.(check bool)
    "failed open keeps" true
    (ap allowed (Opa.Failed_open "boom") = allowed);
  Alcotest.(check bool) "allowed keeps" true (ap allowed Opa.Allowed = allowed);
  Alcotest.(check bool) "skipped keeps" true (ap allowed Opa.Skipped = allowed);
  (* OPA can never turn a deny into an allow *)
  List.iter
    (fun o ->
      let v = ap denied o in
      Alcotest.(check bool) ("still denied: " ^ Opa.outcome_label o) false v.allowed;
      Alcotest.(check bool) "unchanged" true (v = denied))
    [
      Opa.Allowed;
      Opa.Skipped;
      Opa.Failed_open "x";
      Opa.Denied [ "x" ];
      Opa.Failed_closed "x";
    ];
  (* shadow mode: reported, not enforced *)
  let sv = verify ~p:shadow_policy "SELECT id FROM app.orders" in
  let v = ap ~mode:Policy.Shadow sv (Opa.Denied [ "r" ]) in
  Alcotest.(check bool) "shadow stays allowed" true v.allowed;
  Alcotest.(check int) "shadow reason" 1 (List.length v.shadow_reasons);
  Alcotest.(check int) "no enforce reason" 0 (List.length v.reasons)

let test_outcome_of_result () =
  let deny = cfg "a" and keep = cfg ~on_error:Config.Opa_allow_haltsql_verdict "a" in
  Alcotest.check outcome_t "deny" (Opa.Failed_closed "e")
    (Opa.outcome_of_result deny (Error "e"));
  Alcotest.check outcome_t "keep" (Opa.Failed_open "e")
    (Opa.outcome_of_result keep (Error "e"));
  Alcotest.check outcome_t "allow" Opa.Allowed (Opa.outcome_of_result keep (Ok Opa.Allow))

let test_skipped_without_request () =
  (* HaltSQL denied: OPA is not asked, even when it is unreachable *)
  let c = cfg ~url:(Printf.sprintf "http://127.0.0.1:%d" closed_port) "haltsql/allow" in
  Alcotest.check outcome_t "skipped" Opa.Skipped
    (run (Opa.check ~cfg:c ~input:(input "SELECT * FROM app.secrets")));
  let v, o =
    run
      (Opa.enforce ~code ~mode:Policy.Enforce ~cfg:c ~caller:token_caller ~context:ctx
         (verify "SELECT * FROM app.secrets"))
  in
  Alcotest.check outcome_t "enforce skipped" Opa.Skipped o;
  Alcotest.(check bool) "denied" false v.allowed

let test_connection_refused () =
  let url = Printf.sprintf "http://127.0.0.1:%d" closed_port in
  let i = input "SELECT id FROM app.orders" in
  check_failed_closed ~sub:"failed"
    (run (Opa.check ~cfg:(cfg ~url "haltsql/allow") ~input:i));
  match
    run
      (Opa.check
         ~cfg:(cfg ~url ~on_error:Config.Opa_allow_haltsql_verdict "haltsql/allow")
         ~input:i)
  with
  | Opa.Failed_open _ -> ()
  | o -> Alcotest.failf "expected Failed_open, got %s" (Opa.outcome_label o)

(* ---- docker ---- *)

let src_dir rel =
  (* dune copies source_tree deps next to the test; docker needs absolute paths *)
  let p = Filename.concat (Sys.getcwd ()) rel in
  if Sys.file_exists p then Unix.realpath p
  else
    let p2 = Filename.concat (Filename.dirname Sys.executable_name) rel in
    if Sys.file_exists p2 then Unix.realpath p2 else Alcotest.failf "missing %s" p

let wait_http ?(headers = []) ?ctx ~what url =
  let deadline = Unix.gettimeofday () +. 60. in
  let rec loop () =
    let r = run (Http.request ?ctx ~headers ~timeout:2. `GET (Uri.of_string url)) in
    match r with
    | Ok { status = 200; _ } -> Ok ()
    | _ when Unix.gettimeofday () > deadline -> Error (what ^ " did not become healthy")
    | _ ->
        Unix.sleepf 0.25;
        loop ()
  in
  loop ()

let ok_or_fail = function Ok x -> x | Error e -> Alcotest.fail e

(* ---- test PKI (ECDSA P-256, throwaway) ---- *)

let dn cn =
  [
    X509.Distinguished_name.(
      Relative_distinguished_name.singleton (CN (Common_name.v cn)));
  ]

let validity () =
  let now = Ptime_clock.now () in
  let from = Option.get (Ptime.sub_span now (Ptime.Span.of_int_s 3600)) in
  let until = Option.get (Ptime.add_span now (Ptime.Span.of_int_s (2 * 86400))) in
  (from, until)

let make_ca name =
  let key = X509.Private_key.generate `P256 in
  let csr = Result.get_ok (X509.Signing_request.create (dn name) key) in
  let ext =
    X509.Extension.(
      empty
      |> add Basic_constraints (true, (true, None))
      |> add Key_usage (true, [ `Key_cert_sign; `CRL_sign; `Digital_signature ]))
  in
  let valid_from, valid_until = validity () in
  match
    X509.Signing_request.sign csr ~valid_from ~valid_until ~extensions:ext key (dn name)
  with
  | Ok c -> (key, c)
  | Error _ -> Alcotest.fail "sign ca"

let make_server ~ca_key ~ca_cert =
  let key = X509.Private_key.generate `P256 in
  let csr = Result.get_ok (X509.Signing_request.create (dn "localhost") key) in
  let ext =
    X509.Extension.(
      empty
      |> add Basic_constraints (true, (false, None))
      |> add Key_usage (true, [ `Digital_signature; `Key_agreement ])
      |> add Ext_key_usage (false, [ `Server_auth ])
      |> add Subject_alt_name
           ( false,
             X509.General_name.(
               singleton DNS [ "localhost" ] |> add IP [ "\127\000\000\001" ]) ))
  in
  let valid_from, valid_until = validity () in
  match
    X509.Signing_request.sign csr ~valid_from ~valid_until ~extensions:ext ca_key
      (X509.Certificate.subject ca_cert)
  with
  | Ok c -> (key, c)
  | Error _ -> Alcotest.fail "sign server"

let write path s =
  Out_channel.with_open_bin path (fun oc -> Out_channel.output_string oc s)

type env = {
  ca_pem : string;  (** trusted by the TLS container's certificate *)
  ca_path : string;
  rogue_ca_pem : string;
  gate_token : string;
}

let random_hex n =
  String.concat "" (List.init n (fun _ -> Printf.sprintf "%02x" (Random.int 256)))

let setup () =
  match Docker_util.available () with
  | Error e -> Error e
  | Ok () -> (
      match Docker_util.ensure_image image with
      | Error e -> Error e
      | Ok () ->
          Random.self_init ();
          let examples = src_dir "../../examples/opa" in
          let fixtures = src_dir "fixtures/policies" in
          let authz = src_dir "fixtures/authz" in
          let gate_token = random_hex 32 in
          let is_darwin =
            try
              let ic = Unix.open_process_in "uname -s" in
              let s = try input_line ic with End_of_file -> "" in
              ignore (Unix.close_process_in ic);
              String.trim s = "Darwin"
            with _ -> false
          in
          let opa_net_args, opa_listen_addr =
            if is_darwin then
              (* On macOS Docker Desktop, --network host runs inside the Linux VM
                 and does not expose ports on the macOS host's loopback, while
                 Docker Desktop's default bridge provides host.docker.internal
                 reaching the macOS host's 127.0.0.1:18183 listener. *)
              ( [ "-p"; Printf.sprintf "127.0.0.1:%d:%d" opa_port opa_port ],
                Printf.sprintf "0.0.0.0:%d" opa_port )
            else
              (* On Linux, --network host shares the host network namespace so
                 OPA reaches 127.0.0.1:18183 via host.docker.internal -> 127.0.0.1. *)
              ( [ "--network"; "host"; "--add-host"; "host.docker.internal:127.0.0.1" ],
                Printf.sprintf "127.0.0.1:%d" opa_port )
          in
          ok_or_fail
            (Docker_util.start ~name:"haltsql-identity-opa"
               (opa_net_args
               @ [
                   "-e";
                   "HALTSQL_TOKEN=" ^ gate_token;
                   "-v";
                   examples ^ ":/policies/examples:ro";
                   "-v";
                   fixtures ^ ":/policies/fixtures:ro";
                   image;
                   "run";
                   "--server";
                   "--addr";
                   opa_listen_addr;
                   "/policies/examples";
                   "/policies/fixtures";
                 ]));
          ok_or_fail
            (Docker_util.start ~name:"haltsql-identity-opa-authz"
               [
                 "-p";
                 Printf.sprintf "127.0.0.1:%d:8181" authz_port;
                 "-v";
                 authz ^ ":/policies:ro";
                 image;
                 "run";
                 "--server";
                 "--addr";
                 "0.0.0.0:8181";
                 "--authentication=token";
                 "--authorization=basic";
                 "/policies";
               ]);
          (* TLS: a fresh CA and a server certificate for localhost / 127.0.0.1 *)
          let certs = Filename.concat (Filename.dirname Sys.executable_name) "certs" in
          (try Sys.mkdir certs 0o755 with Sys_error _ -> ());
          let ca_key, ca_cert = make_ca "haltsql identity test CA" in
          let skey, scert = make_server ~ca_key ~ca_cert in
          let _, rogue = make_ca "rogue CA" in
          let ca_pem = X509.Certificate.encode_pem ca_cert in
          let ca_path = Filename.concat certs "ca.pem" in
          write ca_path ca_pem;
          write (Filename.concat certs "server.pem") (X509.Certificate.encode_pem scert);
          (* readable by the container's non-root user; throwaway test key *)
          write (Filename.concat certs "server.key") (X509.Private_key.encode_pem skey);
          Unix.chmod (Filename.concat certs "server.key") 0o644;
          ok_or_fail
            (Docker_util.start ~name:"haltsql-identity-opa-tls"
               [
                 "-p";
                 Printf.sprintf "127.0.0.1:%d:8443" tls_port;
                 "-v";
                 certs ^ ":/certs:ro";
                 "-v";
                 authz ^ ":/policies:ro";
                 image;
                 "run";
                 "--server";
                 "--addr";
                 "0.0.0.0:8443";
                 "--tls-cert-file";
                 "/certs/server.pem";
                 "--tls-private-key-file";
                 "/certs/server.key";
                 "/policies/allow.rego";
               ]);
          let h = Printf.sprintf "http://127.0.0.1:%d/health" in
          ok_or_fail (wait_http ~what:"opa" (h opa_port));
          ok_or_fail
            (wait_http ~what:"opa (authz)"
               ~headers:[ ("authorization", "Bearer " ^ authz_token) ]
               (h authz_port));
          let ctx = run (Http.ctx_of_ca_file ca_path) |> ok_or_fail in
          ok_or_fail
            (wait_http ~ctx ~what:"opa (tls)"
               (Printf.sprintf "https://localhost:%d/health" tls_port));
          Ok
            {
              ca_pem;
              ca_path;
              rogue_ca_pem = X509.Certificate.encode_pem rogue;
              gate_token;
            })

let env = lazy (setup ())

let with_env f () =
  match Lazy.force env with
  | Ok e -> f e
  | Error msg ->
      Printf.eprintf "SKIP (OPA integration): %s\n%!" msg;
      Alcotest.skip ()

let check_cfg c i = run (Opa.check ~cfg:c ~input:i)

let test_real_allow _ =
  Alcotest.check outcome_t "bool allow" Opa.Allowed
    (check_cfg (cfg "haltsql/allow") (input "SELECT id FROM app.orders"));
  Alcotest.check outcome_t "object allow" Opa.Allowed
    (check_cfg (cfg "haltsql/decision") (input "SELECT id FROM app.orders"));
  Alcotest.check outcome_t "oidc caller may read finance" Opa.Allowed
    (check_cfg (cfg "haltsql/decision")
       (input ~caller:oidc_caller "SELECT amount_cents FROM app.invoices"))

let test_real_deny _ =
  let i = input "SELECT amount_cents FROM app.invoices" in
  Alcotest.check outcome_t "object deny with reasons"
    (Opa.Denied [ "table app.invoices needs an mTLS or SSO caller, not token" ])
    (check_cfg (cfg "haltsql/decision") i);
  Alcotest.check outcome_t "bool deny" (Opa.Denied []) (check_cfg (cfg "haltsql/allow") i);
  Alcotest.check outcome_t "blocked column"
    (Opa.Denied [ "column app.customers.email is blocked organisation-wide" ])
    (check_cfg (cfg "haltsql/decision")
       (input ~caller:oidc_caller "SELECT email FROM app.customers"));
  Alcotest.check outcome_t "fixture false" (Opa.Denied [])
    (check_cfg (cfg "haltsql_fixtures/deny_bool") i);
  Alcotest.check outcome_t "fixture {allow:false}" (Opa.Denied [])
    (check_cfg (cfg "haltsql_fixtures/deny_obj") i);
  (* end to end: verify, then OPA, then the combined verdict *)
  let v, o =
    run
      (Opa.enforce ~code ~mode:Policy.Enforce ~cfg:(cfg "haltsql/decision")
         ~caller:token_caller ~context:ctx
         (verify "SELECT amount_cents FROM app.invoices"))
  in
  Alcotest.(check string) "outcome" "denied" (Opa.outcome_label o);
  Alcotest.(check bool) "verdict denied" false v.allowed;
  Alcotest.(check bool)
    "reason" true
    (List.exists
       (fun (r : Reason.t) -> r.code = code && contains r.message "app.invoices")
       v.reasons)

(* Regression: an OPA denial (and an OPA failure with on_error deny) kept the
   bind_params of the HaltSQL verdict it overturned; a denied verdict never carries
   bind_params (docs/verdict.md). Real OPA, bound-tenancy policy. *)
let bound_policy =
  lazy
    (match
       Haltsql.Policy_load.of_json
         (Yojson.Safe.from_string
            {|{
  "apiVersion": "haltsql.dev/v1",
  "kind": "Policy",
  "metadata": {"name": "bound"},
  "search_path": ["app"],
  "statements": {"allow": ["select"]},
  "tenancy": {"mode": "bound", "keys": {"tenant": "${ctx.tenant_id}"}},
  "tables": {
    "app.invoices": {"columns": ["id", "tenant_id", "amount_cents"], "tenant_column": "tenant_id"}
  }
}|})
     with
    | Ok p -> p
    | Error _ -> Alcotest.fail "bound policy does not load")

let test_real_bind_params _ =
  let v0 =
    verify ~p:bound_policy "SELECT amount_cents FROM app.invoices WHERE tenant_id = $1"
  in
  Alcotest.(check bool) "precondition: allowed" true v0.allowed;
  Alcotest.(check bool) "precondition: bind_params" true (v0.bind_params <> []);
  let enforce c =
    run
      (Opa.enforce ~code ~mode:Policy.Enforce ~cfg:c ~caller:token_caller ~context:ctx v0)
  in
  let v, o = enforce (cfg "haltsql/decision") in
  Alcotest.(check string) "OPA denies" "denied" (Opa.outcome_label o);
  Alcotest.(check bool) "denied" false v.allowed;
  Alcotest.(check int) "OPA deny: no bind_params" 0 (List.length v.bind_params);
  let v, o =
    enforce
      (cfg ~url:(Printf.sprintf "http://127.0.0.1:%d" closed_port) "haltsql/decision")
  in
  Alcotest.(check string) "OPA down" "error_denied" (Opa.outcome_label o);
  Alcotest.(check bool) "on_error deny: denied" false v.allowed;
  Alcotest.(check int) "on_error deny: no bind_params" 0 (List.length v.bind_params)

let test_real_input _ =
  (match check_cfg (cfg "haltsql_fixtures/echo") (input "SELECT id FROM app.orders") with
  | Opa.Denied [ keys ] ->
      Alcotest.(check string)
        "input keys as OPA sees them"
        "allowed,caller,columns,context_keys,fingerprint,policy,policy_version,reasons,shadow_reasons,sql_sha256,statement_kind,tables"
        keys
  | o -> Alcotest.failf "unexpected %s" (Opa.outcome_label o));
  match
    check_cfg (cfg "haltsql_fixtures/no_leak") (input "SELECT id FROM app.orders")
  with
  | Opa.Allowed -> ()
  | o ->
      Alcotest.failf "input leaks SQL, context values or subject: %s"
        (Opa.outcome_label o)

let test_real_errors _ =
  let i = input "SELECT id FROM app.orders" in
  check_failed_closed ~sub:"undefined" (check_cfg (cfg "haltsql_fixtures/nope") i);
  List.iter
    (fun (path, sub) ->
      check_failed_closed ~sub (check_cfg (cfg ("haltsql_fixtures/" ^ path)) i))
    [
      ("string_result", "boolean or an object");
      ("extra_keys", "unexpected key");
      ("allow_not_bool", "must be a boolean");
      ("reasons_not_strings", "only strings");
      ("no_allow", "no \"allow\"");
      ("null_result", "null");
    ];
  (* on_error: allow_haltsql_verdict keeps HaltSQL's verdict *)
  let keep = cfg ~on_error:Config.Opa_allow_haltsql_verdict "haltsql_fixtures/nope" in
  let v, o =
    run
      (Opa.enforce ~code ~mode:Policy.Enforce ~cfg:keep ~caller:token_caller ~context:ctx
         (verify "SELECT id FROM app.orders"))
  in
  Alcotest.(check string) "failed open" "error_allowed" (Opa.outcome_label o);
  Alcotest.(check bool) "verdict kept" true v.allowed;
  let v, _ =
    run
      (Opa.enforce ~code ~mode:Policy.Enforce ~cfg:(cfg "haltsql_fixtures/nope")
         ~caller:token_caller ~context:ctx
         (verify "SELECT id FROM app.orders"))
  in
  Alcotest.(check bool) "failed closed denies" false v.allowed

let test_real_timeout _ =
  let t0 = Unix.gettimeofday () in
  check_failed_closed ~sub:"timed out"
    (check_cfg
       (cfg ~timeout:100 "haltsql_fixtures/slow")
       (input "SELECT id FROM app.orders"));
  let dt = Unix.gettimeofday () -. t0 in
  if dt > 1.5 then Alcotest.failf "timeout took %.2fs" dt

let test_real_headers _ =
  let url = Printf.sprintf "http://127.0.0.1:%d" authz_port in
  let i = input "SELECT id FROM app.orders" in
  Alcotest.check outcome_t "with token" Opa.Allowed
    (check_cfg
       (cfg ~url
          ~headers:[ ("Authorization", "Bearer " ^ authz_token) ]
          "haltsql_authz/allow")
       i);
  check_failed_closed ~sub:"HTTP 401" (check_cfg (cfg ~url "haltsql_authz/allow") i);
  match
    check_cfg
      (cfg ~url
         ~headers:[ ("Authorization", "Bearer wrong-value-xyz") ]
         "haltsql_authz/allow")
      i
  with
  | Opa.Failed_closed e ->
      Alcotest.(check bool) "401" true (contains e "HTTP 401");
      Alcotest.(check bool)
        "header value not in error" false
        (contains e "wrong-value-xyz")
  | o -> Alcotest.failf "expected Failed_closed, got %s" (Opa.outcome_label o)

let test_real_tls e =
  let url = Printf.sprintf "https://localhost:%d" tls_port in
  let i = input "SELECT id FROM app.orders" in
  Alcotest.check outcome_t "inline CA" Opa.Allowed
    (check_cfg (cfg ~url ~ca:(Config.Pem_inline e.ca_pem) "haltsql_authz/allow") i);
  Alcotest.check outcome_t "CA file" Opa.Allowed
    (check_cfg (cfg ~url ~ca:(Config.Pem_path e.ca_path) "haltsql_authz/allow") i);
  (* Rotating the CA file on disk invalidates the cached TLS context *)
  let rot_path = Filename.concat (Filename.dirname e.ca_path) "rotated-ca.pem" in
  write rot_path e.ca_pem;
  Unix.utimes rot_path 1_700_000_000. 1_700_000_000.;
  Alcotest.check outcome_t "CA file before rotation" Opa.Allowed
    (check_cfg (cfg ~url ~ca:(Config.Pem_path rot_path) "haltsql_authz/allow") i);
  write rot_path e.rogue_ca_pem;
  Unix.utimes rot_path 1_700_000_100. 1_700_000_100.;
  check_failed_closed ~sub:"failed"
    (check_cfg (cfg ~url ~ca:(Config.Pem_path rot_path) "haltsql_authz/allow") i);
  check_failed_closed ~sub:"failed"
    (check_cfg (cfg ~url ~ca:(Config.Pem_inline e.rogue_ca_pem) "haltsql_authz/allow") i);
  check_failed_closed ~sub:"failed" (check_cfg (cfg ~url "haltsql_authz/allow") i);
  match
    check_cfg
      (cfg ~url
         ~ca:
           (Config.Pem_inline
              "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")
         "haltsql_authz/allow")
      i
  with
  | Opa.Failed_closed _ -> ()
  | o -> Alcotest.failf "bad CA: expected Failed_closed, got %s" (Opa.outcome_label o)

(* ---- reverse direction: OPA -> haltsql-server /v1/verify ---- *)

let server_bin () =
  let b =
    Option.value
      (Sys.getenv_opt "HALTSQL_SERVER_BIN")
      ~default:"../../bin/server/main.exe"
  in
  if not (Filename.is_relative b) then b
  else
    let p1 = Filename.concat (Sys.getcwd ()) b in
    if Sys.file_exists p1 then p1
    else Filename.concat (Filename.dirname Sys.executable_name) b

let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))

let with_server e f =
  let dir = Filename.concat (Filename.dirname Sys.executable_name) "gate" in
  (try Sys.mkdir dir 0o755 with Sys_error _ -> ());
  let config = Filename.concat dir "haltsql.json" in
  let doc =
    `Assoc
      [
        ("apiVersion", `String "haltsql.dev/v1");
        ("kind", `String "Config");
        ( "server",
          `Assoc
            [
              ("listen", `String (Printf.sprintf "127.0.0.1:%d" server_port));
              ( "auth",
                `Assoc
                  [
                    ( "tokens",
                      `List
                        [
                          `Assoc
                            [
                              ("name", `String "opa-gate");
                              ("token_sha256", `String (sha256_hex e.gate_token));
                              ("policy", `String "p");
                            ];
                        ] );
                  ] );
            ] );
        ("policies", `List [ `Assoc [ ("inline", Yojson.Safe.from_string policy_json) ] ]);
        ( "audit",
          `Assoc
            [
              ( "sinks",
                `List
                  [
                    `Assoc
                      [
                        ("type", `String "file");
                        ("path", `String (Filename.concat dir "audit.jsonl"));
                      ];
                  ] );
            ] );
      ]
  in
  write config (Yojson.Safe.to_string doc);
  let out =
    Unix.openfile (Filename.concat dir "server.log") [ O_WRONLY; O_CREAT; O_TRUNC ] 0o644
  in
  let bin = server_bin () in
  let pid = Unix.create_process bin [| bin; "--config"; config |] Unix.stdin out out in
  Unix.close out;
  Fun.protect
    ~finally:(fun () ->
      (try Unix.kill pid Sys.sigterm with Unix.Unix_error _ -> ());
      let rec reap n =
        match Unix.waitpid [ Unix.WNOHANG ] pid with
        | 0, _ when n > 100 -> (
            try
              Unix.kill pid Sys.sigkill;
              ignore (Unix.waitpid [] pid)
            with _ -> ())
        | 0, _ ->
            Unix.sleepf 0.05;
            reap (n + 1)
        | _ -> ()
        | exception Unix.Unix_error (Unix.EINTR, _, _) -> reap n
        | exception Unix.Unix_error _ -> ()
      in
      reap 0)
    (fun () ->
      ok_or_fail
        (wait_http ~what:"haltsql-server"
           (Printf.sprintf "http://127.0.0.1:%d/readyz" server_port));
      f ())

let opa_query path input_json =
  let body = Yojson.Safe.to_string (`Assoc [ ("input", input_json) ]) in
  match
    run
      (Http.request ~timeout:10.
         ~headers:[ ("content-type", "application/json") ]
         ~body `POST
         (Uri.of_string (Printf.sprintf "http://127.0.0.1:%d/v1/data/%s" opa_port path)))
  with
  | Ok { status = 200; body; _ } -> (
      match Yojson.Safe.from_string body with
      | `Assoc kv -> Option.value (List.assoc_opt "result" kv) ~default:`Null
      | _ -> `Null)
  | Ok r -> Alcotest.failf "OPA answered HTTP %d: %s" r.status r.body
  | Error m -> Alcotest.fail m

let test_reverse_gate e =
  with_server e (fun () ->
      let q sql = opa_query "haltsql/gate/decision" (`Assoc [ ("sql", `String sql) ]) in
      Alcotest.(check string)
        "allowed by haltsql-server" {|{"allow":true,"reasons":[]}|}
        (Yojson.Safe.to_string (q "SELECT id FROM app.orders LIMIT 5"));
      Alcotest.(check string)
        "denied by haltsql-server" {|{"allow":false,"reasons":["E_TABLE_DENIED"]}|}
        (Yojson.Safe.to_string (q "SELECT * FROM app.secrets"));
      Alcotest.(check string)
        "write denied" {|false|}
        (Yojson.Safe.to_string
           (opa_query "haltsql/gate/allow"
              (`Assoc [ ("sql", `String "DELETE FROM app.orders") ]))));
  (* server gone: the gate fails closed *)
  Alcotest.(check string)
    "server down fails closed"
    {|{"allow":false,"reasons":["haltsql-server did not return a verdict"]}|}
    (Yojson.Safe.to_string
       (opa_query "haltsql/gate/decision"
          (`Assoc [ ("sql", `String "SELECT id FROM app.orders") ])))

let test_opa_test _ =
  (* the Rego unit tests, run by the real opa binary *)
  match
    Docker_util.run_capture
      [
        "run";
        "--rm";
        "-v";
        src_dir "../../examples/opa" ^ ":/policies:ro";
        image;
        "test";
        "-v";
        "/policies";
      ]
  with
  | Ok out -> if not (contains out "PASS: 12/12") then Alcotest.failf "opa test:\n%s" out
  | Error out -> Alcotest.failf "opa test failed:\n%s" out

let () =
  Mirage_crypto_rng_unix.use_default ();
  let tc name f = Alcotest.test_case name `Quick f in
  let it name f = Alcotest.test_case name `Slow (with_env f) in
  Alcotest.run "opa"
    [
      ( "pure",
        [
          tc "parse ok" test_parse_ok;
          tc "parse strict" test_parse_strict;
          tc "reason sanitizing" test_reason_sanitizing;
          tc "decision url" test_decision_url;
          tc "input json" test_input_json;
          tc "apply" test_apply;
          tc "outcome_of_result" test_outcome_of_result;
          tc "skipped without request" test_skipped_without_request;
          tc "connection refused" test_connection_refused;
        ] );
      ( "opa (docker)",
        [
          it "allow" test_real_allow;
          it "deny" test_real_deny;
          it "a denial carries no bind_params" test_real_bind_params;
          it "input document" test_real_input;
          it "errors" test_real_errors;
          it "timeout" test_real_timeout;
          it "headers" test_real_headers;
          it "tls" test_real_tls;
          it "reverse: OPA calls /v1/verify" test_reverse_gate;
          it "opa test examples/opa" test_opa_test;
        ] );
    ]
