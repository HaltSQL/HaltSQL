(** End-to-end tests for built-in TLS, mTLS identities and OIDC in haltsql-server.

    Everything is generated in-test: a CA, server and client certificates (x509), RSA/EC
    signing keys, and a fake OIDC issuer (discovery + JWKS over plain HTTP, allowed with
    allow_insecure_http) served in-process. Requests are written as raw HTTP/1.1 over a
    tls-lwt client so the tests control the client certificate and TLS versions. *)

open Lwt.Syntax
open Haltsql_server
module Config = Haltsql.Config
module Jwt = Haltsql_auth.Jwt
module Jwk = Haltsql_auth.Jwk

let () =
  Mirage_crypto_rng_unix.use_default ();
  Log.setup ~level:"error" ~format:"json"

let fx name = Filename.concat "fixtures" name

let tmpdir =
  let d =
    Filename.concat
      (Filename.get_temp_dir_name ())
      (Printf.sprintf "haltsql-auth-e2e-%d" (Unix.getpid ()))
  in
  (try Unix.mkdir d 0o700 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  d

let tmp name = Filename.concat tmpdir name
let write_file f s = Out_channel.with_open_bin f (fun oc -> output_string oc s)
let read_file f = In_channel.with_open_bin f In_channel.input_all

let member k = function
  | `Assoc kv -> Option.value (List.assoc_opt k kv) ~default:`Null
  | _ -> `Null

let run p = Lwt_main.run p

(* ---- PKI ---- *)

let now_p = Ptime_clock.now ()
let valid_from = Option.get (Ptime.sub_span now_p (Ptime.Span.of_int_s 3600))
let valid_until = Option.get (Ptime.add_span now_p (Ptime.Span.of_int_s (30 * 86400)))

let dn cn =
  X509.Distinguished_name.
    [ Relative_distinguished_name.singleton (CN (Common_name.v cn)) ]

let make_ca name =
  let key = X509.Private_key.generate `P256 in
  let csr = Result.get_ok (X509.Signing_request.create (dn name) key) in
  let extensions =
    X509.Extension.(
      empty
      |> add Basic_constraints (true, (true, None))
      |> add Key_usage (true, [ `Key_cert_sign; `CRL_sign; `Digital_signature ]))
  in
  let cert =
    match
      X509.Signing_request.sign csr ~valid_from ~valid_until ~extensions key (dn name)
    with
    | Ok c -> c
    | Error _ -> failwith "CA signing failed"
  in
  (key, cert)

let make_leaf ~ca:(ca_key, ca_cert) ~cn ?dns ?uri usage =
  let key = X509.Private_key.generate `P256 in
  let csr = Result.get_ok (X509.Signing_request.create (dn cn) key) in
  let san =
    X509.General_name.(
      empty
      |> (match dns with Some d -> add DNS [ d ] | None -> Fun.id)
      |> match uri with Some u -> add URI [ u ] | None -> Fun.id)
  in
  let extensions =
    X509.Extension.(
      empty
      |> add Basic_constraints (true, (false, None))
      |> add Key_usage (true, [ `Digital_signature; `Key_encipherment ])
      |> add Ext_key_usage (false, [ usage ])
      |> fun e ->
      if X509.General_name.is_empty san then e else add Subject_alt_name (false, san) e)
  in
  let cert =
    match
      X509.Signing_request.sign csr ~valid_from ~valid_until ~extensions ca_key
        (X509.Certificate.subject ca_cert)
    with
    | Ok c -> c
    | Error _ -> failwith "leaf signing failed"
  in
  (key, cert)

let ca = make_ca "HaltSQL Test CA"
let rogue_ca = make_ca "Rogue CA"
let server_leaf () = make_leaf ~ca ~cn:"localhost" ~dns:"localhost" `Server_auth
let spiffe_id = "spiffe://corp.example/ns/agents/sa/analytics"
let client_spiffe = make_leaf ~ca ~cn:"analytics" ~uri:spiffe_id `Client_auth
let client_cn = make_leaf ~ca ~cn:"support-bot" `Client_auth
let client_unmapped = make_leaf ~ca ~cn:"nobody" `Client_auth
let client_rogue = make_leaf ~ca:rogue_ca ~cn:"support-bot" `Client_auth
let client_server_eku = make_leaf ~ca ~cn:"support-bot" `Server_auth
let ca_path = tmp "ca.pem"
let cert_path = tmp "server.crt"
let key_path = tmp "server.key"

let write_server_cert (key, cert) =
  write_file cert_path (X509.Certificate.encode_pem cert);
  write_file key_path (X509.Private_key.encode_pem key)

let initial_server = server_leaf ()

let () =
  write_file ca_path (X509.Certificate.encode_pem (snd ca));
  write_server_cert initial_server

let tls_cfg ?(client_auth = Config.Client_auth_optional) ?(min_version = Config.Tls_1_2)
    () : Config.tls =
  {
    cert = Pem_path cert_path;
    key = Pem_path key_path;
    client_ca = Some (Pem_path ca_path);
    client_auth;
    min_version;
  }

(* ---- fake OIDC issuer ---- *)

let rsa_priv = Mirage_crypto_pk.Rsa.generate ~bits:2048 ()
let rsa_pub = Mirage_crypto_pk.Rsa.pub_of_priv rsa_priv
let ec_priv, ec_pub = Mirage_crypto_ec.P256.Dsa.generate ()

let jwks =
  ref
    [
      { Jwk.kid = Some "k1"; alg = Some "RS256"; use = Some "sig"; key = Jwk.Rsa rsa_pub };
    ]

let idp_hits = ref []
let idp_fd, idp_port = Server.bind_listen "127.0.0.1:0"
let issuer = Printf.sprintf "http://127.0.0.1:%d" idp_port

let () =
  let callback _conn req _body =
    let path = Uri.path (Cohttp.Request.uri req) in
    idp_hits := path :: !idp_hits;
    let json j =
      Cohttp_lwt_unix.Server.respond_string ~status:`OK
        ~headers:(Cohttp.Header.of_list [ ("content-type", "application/json") ])
        ~body:(Yojson.Safe.to_string j) ()
    in
    match path with
    | "/.well-known/openid-configuration" ->
        json
          (`Assoc [ ("issuer", `String issuer); ("jwks_uri", `String (issuer ^ "/jwks")) ])
    | "/jwks" -> json (`Assoc [ ("keys", `List (List.map Jwk.to_json !jwks)) ])
    | _ -> Cohttp_lwt_unix.Server.respond_not_found ()
  in
  Lwt.async (fun () ->
      Cohttp_lwt_unix.Server.create
        ~mode:(`TCP (`Socket idp_fd))
        (Cohttp_lwt_unix.Server.make ~callback ()))

let oidc_provider : Config.oidc_provider =
  {
    oidc_name = "fake-idp";
    issuer;
    audiences = [ "haltsql" ];
    jwks_uri = None;
    algorithms = [ Config.RS256; Config.ES256 ];
    leeway_seconds = 30;
    jwks_cache_seconds = 300;
    oidc_policy =
      Oidc_from_claim { claim = "haltsql_policy"; allowed = [ "shop"; "other" ] };
    context_claims = [ ("tenant_id", "https://corp.example/tenant") ];
    required_claims = [ ("scope", Claim_one "sql.verify") ];
    oidc_request_context_fields = [ "user_id" ];
    allow_insecure_http = true;
  }

let jwt ?(kid = "k1") ?(key = Jwt.Sign_rsa rsa_priv) ?(alg = "RS256") ?(exp_in = 600.)
    ?(aud = "haltsql") ?(tenant = `String "acme") ?(policy = "shop") ?(extra = []) () =
  let now = Unix.gettimeofday () in
  Jwt.sign ~alg ~kid key
    (`Assoc
       ([
          ("iss", `String issuer);
          ("aud", `String aud);
          ("sub", `String "user-17");
          ("exp", `Int (int_of_float (now +. exp_in)));
          ("iat", `Int (int_of_float now));
          ("scope", `String "openid sql.verify");
          ("haltsql_policy", `String policy);
          ("https://corp.example/tenant", tenant);
        ]
       @ extra))

(* ---- servers under test ---- *)

let static_token = "static-token-for-shop"
let audit_path = tmp "audit.jsonl"

let mtls_ids : Config.mtls_identity list =
  [
    {
      mtls_match = Spiffe_id spiffe_id;
      mtls_policy = "shop";
      mtls_context = [ ("tenant_id", Haltsql.Context.One "globex") ];
      mtls_request_context_fields = [];
    };
    {
      mtls_match = Subject_cn "support-bot";
      mtls_policy = "other";
      mtls_context = [];
      mtls_request_context_fields = [ "tenant_id" ];
    };
  ]

let start ?health ~tls () =
  let sources =
    {
      State.config_file = None;
      policy_files = [ fx "shop.yaml"; fx "other.json" ];
      overrides =
        (fun c ->
          {
            c with
            tls = Some tls;
            tokens =
              [
                {
                  token_name = "static";
                  token_sha256 = Auth.sha256_hex static_token;
                  token_policy = "shop";
                };
              ];
            oidc = [ oidc_provider ];
            mtls = mtls_ids;
            sinks = [ { sink = Sink_file audit_path; on_error = Fail_closed } ];
            reload_watch = false;
          });
    }
  in
  match State.load sources with
  | Error e -> Alcotest.failf "load failed: %s" (String.concat "; " e)
  | Ok cfg ->
      let st = State.create ~sources cfg in
      let fd, port = Server.bind_listen "127.0.0.1:0" in
      let health_fd, health_port =
        match health with
        | Some () ->
            let hfd, hp = Server.bind_listen "127.0.0.1:0" in
            (Some hfd, hp)
        | None -> (None, 0)
      in
      let stop, _ = Lwt.wait () in
      Lwt.async (fun () -> Server.serve ?health_fd st fd ~stop);
      (st, port, health_port)

(* X: TLS 1.2+, optional client certs, OIDC + mTLS + static token. *)
let _st_x, port_x, _ = start ~tls:(tls_cfg ()) ()

(* Y: TLS 1.3 only, client certs required, plain health port. *)
let st_y, port_y, health_y =
  start ~health:()
    ~tls:(tls_cfg ~client_auth:Config.Client_auth_required ~min_version:Config.Tls_1_3 ())
    ()

(* ---- raw HTTPS client ---- *)

type resp = { status : int; body : string; server_cert : X509.Certificate.t option }

let localhost = Domain_name.(host_exn (of_string_exn "localhost"))

let tls_request ?client ?(version = (`TLS_1_2, `TLS_1_3)) ?token ?(meth = "GET") ?body
    ?(trust = snd ca) port path =
  let authenticator =
    X509.Authenticator.chain_of_trust
      ~time:(fun () -> Some (Ptime_clock.now ()))
      [ trust ]
  in
  let certificates =
    match client with Some (k, c) -> `Single ([ c ], k) | None -> `None
  in
  let cfg =
    match Tls.Config.client ~authenticator ~version ~certificates () with
    | Ok c -> c
    | Error (`Msg m) -> failwith m
  in
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt.catch
    (fun () ->
      let* () = Lwt_unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_loopback, port)) in
      let* t = Tls_lwt.Unix.client_of_fd cfg ~host:localhost fd in
      let body = Option.value body ~default:"" in
      let req =
        String.concat "\r\n"
          ([
             Printf.sprintf "%s %s HTTP/1.1" meth path;
             "Host: localhost";
             "Connection: close";
           ]
          @ (match token with Some t -> [ "Authorization: Bearer " ^ t ] | None -> [])
          @ (if body <> "" then
               [
                 "Content-Type: application/json";
                 Printf.sprintf "Content-Length: %d" (String.length body);
               ]
             else [])
          @ [ ""; body ])
      in
      let* () = Tls_lwt.Unix.write t req in
      let buf = Buffer.create 4096 in
      let chunk = Bytes.create 4096 in
      let rec read_all () =
        let* n =
          Lwt.catch (fun () -> Tls_lwt.Unix.read t chunk) (fun _ -> Lwt.return 0)
        in
        if n = 0 then Lwt.return_unit
        else (
          Buffer.add_subbytes buf chunk 0 n;
          read_all ())
      in
      let* () = read_all () in
      let server_cert =
        match Tls_lwt.Unix.epoch t with
        | Ok e -> e.Tls.Core.peer_certificate
        | Error () -> None
      in
      let* () = Lwt.catch (fun () -> Tls_lwt.Unix.close t) (fun _ -> Lwt.return_unit) in
      let raw = Buffer.contents buf in
      let status = try Scanf.sscanf raw "HTTP/1.1 %d" Fun.id with _ -> -1 in
      let body =
        match Str.search_forward (Str.regexp_string "\r\n\r\n") raw 0 with
        | i -> String.sub raw (i + 4) (String.length raw - i - 4)
        | exception Not_found -> ""
      in
      (* With TLS 1.3 the server rejects a client certificate after the client
         considers the handshake done: that shows up as no response at all. *)
      if raw = "" then Lwt.return_error "connection closed without a response"
      else Lwt.return_ok { status; body; server_cert })
    (fun e ->
      let* () = Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit) in
      Lwt.return_error (Printexc.to_string e))

let ok_resp msg = function
  | Ok r -> r
  | Error e -> Alcotest.failf "%s: request failed: %s" msg e

let check_status msg expected r =
  let r = ok_resp msg r in
  if r.status <> expected then
    Alcotest.failf "%s: expected %d, got %d: %s" msg expected r.status r.body;
  r

let json r =
  try Yojson.Safe.from_string r.body with _ -> Alcotest.failf "not JSON: %s" r.body

let error_code r = member "code" (member "error" (json r))

let verify_body ?policy ?context sql =
  Yojson.Safe.to_string
    (`Assoc
       ([ ("sql", `String sql) ]
       @ (match context with Some c -> [ ("context", c) ] | None -> [])
       @ match policy with Some p -> [ ("policy", `String p) ] | None -> []))

let good_sql = "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 10"

let bound_tenant r =
  match member "bind_params" (json r) with `List [ p ] -> member "value" p | j -> j

let post ?client ?token ?policy ?context port =
  run
    (tls_request ?client ?token ~meth:"POST"
       ~body:(verify_body ?policy ?context good_sql)
       port "/v1/verify")

let last_audit () =
  let lines =
    String.split_on_char '\n' (read_file audit_path)
    |> List.filter (fun l -> String.trim l <> "")
  in
  Yojson.Safe.from_string (List.nth lines (List.length lines - 1))

(* ---- tests ---- *)

let tls_static_token () =
  let r =
    check_status "static token over TLS" 200
      (post ~token:static_token ~context:(`Assoc [ ("tenant_id", `String "t9") ]) port_x)
  in
  Alcotest.(check bool) "bound from body" true (bound_tenant r = `String "t9");
  let a = last_audit () in
  Alcotest.(check bool) "caller_type token" true (member "caller_type" a = `String "token");
  let _ = check_status "no auth" 401 (post port_x) in
  ()

let oidc_claims_context () =
  let token = jwt () in
  let r = check_status "oidc" 200 (post ~token port_x) in
  Alcotest.(check bool) "allowed" true (member "allowed" (json r) = `Bool true);
  Alcotest.(check bool) "tenant from claim" true (bound_tenant r = `String "acme");
  Alcotest.(check bool)
    "pinned by claim" true
    (member "name" (member "policy" (json r)) = `String "shop");
  let a = last_audit () in
  Alcotest.(check bool) "audit caller_type" true (member "caller_type" a = `String "oidc");
  Alcotest.(check bool) "audit subject" true (member "subject" a = `String "user-17");
  Alcotest.(check bool) "audit caller" true (member "caller" a = `String "oidc:fake-idp");
  let sig_part = List.nth (String.split_on_char '.' token) 2 in
  Alcotest.(check bool)
    "no raw token in audit" false
    (Str.string_match (Str.regexp (".*" ^ Str.quote sig_part)) (read_file audit_path) 0);
  (* discovery then JWKS were fetched from the fake issuer *)
  Alcotest.(check bool)
    "discovery hit" true
    (List.mem "/.well-known/openid-configuration" !idp_hits);
  Alcotest.(check bool) "jwks hit" true (List.mem "/jwks" !idp_hits);
  (* policy chosen by the claim *)
  let r =
    check_status "policy claim other" 200 (post ~token:(jwt ~policy:"other" ()) port_x)
  in
  Alcotest.(check bool)
    "other" true
    (member "name" (member "policy" (json r)) = `String "other");
  (* body asks for another policy than the pinned one *)
  let r =
    check_status "policy mismatch" 403 (post ~token:(jwt ()) ~policy:"other" port_x)
  in
  Alcotest.(check bool) "FORBIDDEN" true (error_code r = `String "FORBIDDEN")

let oidc_context_not_allowed () =
  let r =
    check_status "conflicting tenant" 403
      (post ~token:(jwt ()) ~context:(`Assoc [ ("tenant_id", `String "evil") ]) port_x)
  in
  Alcotest.(check bool) "code" true (error_code r = `String "CONTEXT_NOT_ALLOWED");
  let r =
    check_status "unlisted field" 403
      (post ~token:(jwt ()) ~context:(`Assoc [ ("role", `String "admin") ]) port_x)
  in
  Alcotest.(check bool) "code" true (error_code r = `String "CONTEXT_NOT_ALLOWED");
  let _ =
    check_status "allowed field" 200
      (post ~token:(jwt ()) ~context:(`Assoc [ ("user_id", `String "u1") ]) port_x)
  in
  let r =
    check_status "identical repeat" 200
      (post ~token:(jwt ()) ~context:(`Assoc [ ("tenant_id", `String "acme") ]) port_x)
  in
  Alcotest.(check bool) "still acme" true (bound_tenant r = `String "acme")

let oidc_rejections () =
  let rejected msg tok =
    let r = check_status msg 401 (post ~token:tok port_x) in
    Alcotest.(check bool) (msg ^ " code") true (error_code r = `String "UNAUTHORIZED")
  in
  rejected "expired" (jwt ~exp_in:(-120.) ());
  rejected "wrong aud" (jwt ~aud:"someone-else" ());
  rejected "policy not allowed" (jwt ~policy:"admin" ());
  rejected "bad tenant claim type" (jwt ~tenant:(`Assoc []) ());
  rejected "missing scope" (jwt ~extra:[ ("scope", `String "openid") ] ());
  rejected "alg none"
    (Jwt.sign ~alg:"none" ~kid:"k1" (Jwt.Sign_rsa rsa_priv)
       (`Assoc [ ("iss", `String issuer) ]));
  (* a JWT-shaped token from an unknown issuer is checked as a static token: 401 *)
  rejected "unknown issuer"
    (Jwt.sign ~alg:"RS256" ~kid:"k1" (Jwt.Sign_rsa rsa_priv)
       (`Assoc [ ("iss", `String "https://x") ]))

let oidc_key_rotation () =
  (* the IdP rotates to an EC key: the unknown kid triggers one JWKS refresh *)
  jwks :=
    !jwks @ [ { Jwk.kid = Some "k2"; alg = None; use = None; key = Jwk.P256 ec_pub } ];
  let before = List.length (List.filter (( = ) "/jwks") !idp_hits) in
  let _ =
    check_status "rotated EC key" 200
      (post ~token:(jwt ~kid:"k2" ~alg:"ES256" ~key:(Jwt.Sign_p256 ec_priv) ()) port_x)
  in
  let after = List.length (List.filter (( = ) "/jwks") !idp_hits) in
  Alcotest.(check int) "one refresh" (before + 1) after

let mtls_spiffe () =
  let r = check_status "spiffe identity" 200 (post ~client:client_spiffe port_x) in
  Alcotest.(check bool) "static context" true (bound_tenant r = `String "globex");
  Alcotest.(check bool)
    "shop" true
    (member "name" (member "policy" (json r)) = `String "shop");
  let a = last_audit () in
  Alcotest.(check bool) "caller_type mtls" true (member "caller_type" a = `String "mtls");
  Alcotest.(check bool) "subject spiffe" true (member "subject" a = `String spiffe_id);
  let r =
    check_status "mtls body tenant" 403
      (post ~client:client_spiffe
         ~context:(`Assoc [ ("tenant_id", `String "acme") ])
         port_x)
  in
  Alcotest.(check bool)
    "CONTEXT_NOT_ALLOWED" true
    (error_code r = `String "CONTEXT_NOT_ALLOWED");
  (* mTLS identity wins over a bearer token on the same request *)
  let r =
    check_status "mtls + token" 200
      (post ~client:client_spiffe ~token:static_token port_x)
  in
  Alcotest.(check bool) "mtls context kept" true (bound_tenant r = `String "globex")

let mtls_cn () =
  let r =
    check_status "cn identity" 200
      (post ~client:client_cn ~context:(`Assoc [ ("tenant_id", `String "t2") ]) port_x)
  in
  Alcotest.(check bool)
    "policy other" true
    (member "name" (member "policy" (json r)) = `String "other");
  let a = last_audit () in
  Alcotest.(check bool) "subject cn" true (member "subject" a = `String "support-bot");
  (* valid cert, no identity: falls back to bearer auth *)
  let _ = check_status "unmapped, no token" 401 (post ~client:client_unmapped port_x) in
  let _ =
    check_status "unmapped + token" 200
      (post ~client:client_unmapped ~token:static_token port_x)
  in
  (* certificate from another CA: the handshake fails *)
  (match post ~client:client_rogue port_x with
  | Error _ -> ()
  | Ok r -> Alcotest.failf "rogue CA client accepted (%d)" r.status);
  (* right CA, but the certificate is only valid for server authentication *)
  match post ~client:client_server_eku port_x with
  | Error _ -> ()
  | Ok r -> Alcotest.failf "serverAuth-only client cert accepted (%d)" r.status

let required_client_certs () =
  (match run (tls_request port_y "/healthz") with
  | Error _ -> ()
  | Ok r -> Alcotest.failf "no client cert accepted (%d)" r.status);
  let _ =
    check_status "with client cert" 200
      (run (tls_request ~client:client_cn port_y "/healthz"))
  in
  (* TLS 1.3 only *)
  (match
     run (tls_request ~client:client_cn ~version:(`TLS_1_2, `TLS_1_2) port_y "/healthz")
   with
  | Error _ -> ()
  | Ok r -> Alcotest.failf "TLS 1.2 accepted by a 1.3-only server (%d)" r.status);
  (* untrusted server cert from the client's point of view *)
  match run (tls_request ~client:client_cn ~trust:(snd rogue_ca) port_y "/healthz") with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "client accepted a server cert from the wrong CA"

let plain_health_port () =
  let req path =
    run
      (let* r, b =
         Cohttp_lwt_unix.Client.get
           (Uri.of_string (Printf.sprintf "http://127.0.0.1:%d%s" health_y path))
       in
       let* body = Cohttp_lwt.Body.to_string b in
       Lwt.return (Cohttp.Code.code_of_status (Cohttp.Response.status r), body))
  in
  Alcotest.(check int) "healthz" 200 (fst (req "/healthz"));
  Alcotest.(check int) "readyz" 200 (fst (req "/readyz"));
  Alcotest.(check int) "verify not served" 404 (fst (req "/v1/verify"));
  Alcotest.(check int) "metrics not served" 404 (fst (req "/metrics"))

let tls_reload () =
  let fingerprint c = X509.Certificate.fingerprint `SHA256 c in
  let served () =
    match
      (ok_resp "reload probe" (run (tls_request ~client:client_cn port_y "/healthz")))
        .server_cert
    with
    | Some c -> fingerprint c
    | None -> Alcotest.fail "no server certificate"
  in
  Alcotest.(check string) "initial cert" (fingerprint (snd initial_server)) (served ());
  let rotated = server_leaf () in
  write_server_cert rotated;
  (match State.reload ~reason:"test" st_y with
  | Ok () -> ()
  | Error e -> Alcotest.failf "reload: %s" (String.concat "; " e));
  Alcotest.(check string) "rotated cert served" (fingerprint (snd rotated)) (served ());
  (* a broken key keeps the last good TLS material *)
  write_file key_path "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n";
  (match State.reload ~reason:"test" st_y with
  | Ok () -> Alcotest.fail "reload with a broken key succeeded"
  | Error _ -> ());
  Alcotest.(check string) "last good kept" (fingerprint (snd rotated)) (served ());
  (* mismatched key and cert *)
  let other = server_leaf () in
  write_file cert_path (X509.Certificate.encode_pem (snd rotated));
  write_file key_path (X509.Private_key.encode_pem (fst other));
  (match State.reload ~reason:"test" st_y with
  | Ok () -> Alcotest.fail "reload with a mismatched key succeeded"
  | Error e ->
      Alcotest.(check bool)
        "mismatch message" true
        (List.exists (fun m -> Str.string_match (Str.regexp ".*does not match") m 0) e));
  write_server_cert rotated

let tls_load_errors () =
  let bad = tmp "bad.pem" in
  write_file bad "not pem";
  let t = { (tls_cfg ()) with cert = Pem_path bad } in
  (match Tls_setup.load t with
  | Error m ->
      Alcotest.(check bool)
        "names setting" true
        (Str.string_match (Str.regexp "server.tls.cert") m 0)
  | Ok _ -> Alcotest.fail "bad cert accepted");
  let t = { (tls_cfg ()) with client_ca = None } in
  match Tls_setup.load t with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "optional client auth without CA accepted"

(* ---- the real binary with a TLS config ---- *)

let server_bin =
  let b =
    Option.value
      (Sys.getenv_opt "HALTSQL_SERVER_BIN")
      ~default:"../../bin/server/main.exe"
  in
  if Filename.is_relative b then Filename.concat (Sys.getcwd ()) b else b

let subprocess_tls () =
  let config = tmp "tls-config.yaml" in
  let policy = Filename.concat (Sys.getcwd ()) (fx "shop.yaml") in
  write_file config
    (Printf.sprintf
       {|apiVersion: haltsql.dev/v1
kind: Config
server:
  tls:
    cert: %s
    key: %s
    client_ca: %s
    client_auth: required
    min_version: "1.3"
  auth:
    mtls:
      identities:
        - subject_cn: support-bot
          policy: shop
          context: { tenant_id: acme }
policies:
  - path: %s
|}
       cert_path key_path ca_path policy);
  let err = tmp "proc.stderr" in
  let fd_err = Unix.openfile err [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC ] 0o600 in
  let devnull = Unix.openfile "/dev/null" [ Unix.O_WRONLY ] 0 in
  let pid =
    Unix.create_process server_bin
      [|
        server_bin;
        "--config";
        config;
        "--listen";
        "127.0.0.1:0";
        "--health-listen";
        "127.0.0.1:0";
        "--audit";
        "none";
      |]
      Unix.stdin devnull fd_err
  in
  Unix.close fd_err;
  Unix.close devnull;
  let rec find n =
    let s = try read_file err with _ -> "" in
    let line =
      String.split_on_char '\n' s
      |> List.find_map (fun l ->
          match Yojson.Safe.from_string l with
          | j when member "msg" j = `String "haltsql-server listening" -> Some j
          | _ -> None
          | exception _ -> None)
    in
    match line with
    | Some j -> j
    | None when n > 200 ->
        Unix.kill pid Sys.sigkill;
        Alcotest.failf "server did not start:\n%s" s
    | None ->
        Unix.sleepf 0.05;
        find (n + 1)
  in
  let j = find 0 in
  let port = match member "port" j with `Int p -> p | _ -> Alcotest.fail "port" in
  let hport =
    match member "health_port" j with `Int p -> p | _ -> Alcotest.fail "health_port"
  in
  Alcotest.(check bool) "tls logged" true (member "tls" j = `Bool true);
  Alcotest.(check bool)
    "client_auth logged" true
    (member "client_auth" j = `String "required");
  let r = check_status "mtls verify" 200 (post ~client:client_cn port) in
  Alcotest.(check bool) "tenant from identity" true (bound_tenant r = `String "acme");
  (match run (tls_request port "/healthz") with
  | Error _ -> ()
  | Ok r -> Alcotest.failf "no client cert accepted (%d)" r.status);
  let code =
    run
      (let* r, b =
         Cohttp_lwt_unix.Client.get
           (Uri.of_string (Printf.sprintf "http://127.0.0.1:%d/healthz" hport))
       in
       let* _ = Cohttp_lwt.Body.to_string b in
       Lwt.return (Cohttp.Code.code_of_status (Cohttp.Response.status r)))
  in
  Alcotest.(check int) "plain health port" 200 code;
  (* SIGHUP reloads the rotated certificate *)
  let rotated = server_leaf () in
  write_server_cert rotated;
  Unix.kill pid Sys.sighup;
  Unix.sleepf 0.5;
  let served =
    match
      (ok_resp "after SIGHUP" (run (tls_request ~client:client_cn port "/healthz")))
        .server_cert
    with
    | Some c -> X509.Certificate.fingerprint `SHA256 c
    | None -> ""
  in
  Alcotest.(check bool)
    "rotated cert after SIGHUP" true
    (served = X509.Certificate.fingerprint `SHA256 (snd rotated));
  Unix.kill pid Sys.sigterm;
  let rec wait n =
    match Unix.waitpid [ Unix.WNOHANG ] pid with
    | 0, _ when n > 100 ->
        Unix.kill pid Sys.sigkill;
        Alcotest.fail "server did not exit"
    | 0, _ ->
        Unix.sleepf 0.05;
        wait (n + 1)
    | _, Unix.WEXITED c -> c
    | _ -> -1
  in
  Alcotest.(check int) "graceful exit" 0 (wait 0);
  let log = read_file err in
  List.iter
    (fun secret ->
      if Str.string_match (Str.regexp (".*" ^ Str.quote secret)) log 0 then
        Alcotest.fail "private key material in logs")
    [ "PRIVATE KEY" ]

let () =
  let tc n f = Alcotest.test_case n `Quick f in
  Alcotest.run ~and_exit:true "haltsql-server auth e2e"
    [
      ( "tls",
        [ tc "static token over TLS" tls_static_token; tc "load errors" tls_load_errors ]
      );
      ( "oidc",
        [
          tc "claims-derived tenant context" oidc_claims_context;
          tc "CONTEXT_NOT_ALLOWED" oidc_context_not_allowed;
          tc "rejections" oidc_rejections;
          tc "key rotation refresh" oidc_key_rotation;
        ] );
      ( "mtls",
        [ tc "SPIFFE mapping" mtls_spiffe; tc "subject CN, unmapped, rogue CA" mtls_cn ]
      );
      ( "required",
        [
          tc "client certs required, TLS 1.3 only" required_client_certs;
          tc "plain health port" plain_health_port;
          tc "certificate reload" tls_reload;
        ] );
      ( "process",
        [ tc "binary: TLS + mTLS, health port, SIGHUP cert reload" subprocess_tls ] );
    ]
