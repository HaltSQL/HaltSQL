(** Unit tests for haltsql.pgwire: codecs, SCRAM, config, enforcement, statement state. *)

open Haltsql_pgwire
open Lwt.Syntax

let check_str = Alcotest.(check string)
let check_bool = Alcotest.(check bool)
let check_int = Alcotest.(check int)
let hex = Sec.hex

module Astring_like = struct
  let contains s sub =
    let n = String.length s and m = String.length sub in
    let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
    go 0
end

let raises_malformed name f =
  match f () with
  | _ -> Alcotest.failf "%s: expected Wire.Malformed" name
  | exception Wire.Malformed _ -> ()

(* ------------------------------------------------------------------ Wire *)

let test_frame () =
  check_str "Sync" "\x53\x00\x00\x00\x04" (Wire.frame 'S' "");
  check_str "Query" "Q\x00\x00\x00\x0dSELECT 1\x00" (Wire.frame 'Q' "SELECT 1\x00");
  check_str "SSLRequest" "\x00\x00\x00\x08\x04\xd2\x16\x2f" Wire.encode_ssl_request;
  check_str "ReadyForQuery idle" "Z\x00\x00\x00\x05I" (Wire.ready_for_query 'I');
  check_str "AuthenticationOk" "R\x00\x00\x00\x08\x00\x00\x00\x00" Wire.auth_ok;
  check_str "BackendKeyData" "K\x00\x00\x00\x0c\x00\x00\x00\x07\xff\xff\xff\xfe"
    (Wire.backend_key_data ~pid:7 ~key:(-2));
  check_str "CancelRequest"
    "\x00\x00\x00\x10\x04\xd2\x16\x2e\x00\x00\x00\x01\x00\x00\x00\x02"
    (Wire.encode_cancel ~pid:1 ~key:2)

let body_of packet = String.sub packet 4 (String.length packet - 4)

let test_startup () =
  let p = Wire.encode_startup [ ("user", "agent"); ("database", "app") ] in
  check_str "bytes"
    "\x00\x00\x00\x21\x00\x03\x00\x00user\x00agent\x00database\x00app\x00\x00" p;
  (match Wire.decode_startup (body_of p) with
  | Wire.Startup { major = 3; minor = 0; params } ->
      Alcotest.(check (list (pair string string)))
        "params"
        [ ("user", "agent"); ("database", "app") ]
        params
  | _ -> Alcotest.fail "expected Startup 3.0");
  (match Wire.decode_startup (body_of Wire.encode_ssl_request) with
  | Wire.Ssl_request -> ()
  | _ -> Alcotest.fail "expected SSLRequest");
  (match Wire.decode_startup "\x04\xd2\x16\x30" with
  | Wire.Gssenc_request -> ()
  | _ -> Alcotest.fail "expected GSSENCRequest");
  (match Wire.decode_startup (body_of (Wire.encode_cancel ~pid:42 ~key:(-5))) with
  | Wire.Cancel_request { pid = 42; key = -5 } -> ()
  | _ -> Alcotest.fail "expected CancelRequest");
  (match Wire.decode_startup "\x00\x03\x00\x02user\x00a\x00\x00" with
  | Wire.Startup { minor = 2; _ } -> ()
  | _ -> Alcotest.fail "expected 3.2");
  raises_malformed "protocol 2.0" (fun () ->
      Wire.decode_startup "\x00\x02\x00\x00user\x00a\x00\x00");
  raises_malformed "duplicate param" (fun () ->
      Wire.decode_startup "\x00\x03\x00\x00user\x00a\x00user\x00b\x00\x00");
  raises_malformed "missing terminator" (fun () ->
      Wire.decode_startup "\x00\x03\x00\x00user\x00a\x00");
  raises_malformed "ssl trailing" (fun () -> Wire.decode_startup "\x04\xd2\x16\x2fX")

let test_query_parse () =
  check_str "query" "SELECT 1" (Wire.decode_query "SELECT 1\x00");
  raises_malformed "embedded NUL" (fun () -> Wire.decode_query "SELECT 1\x00; DROP\x00");
  raises_malformed "no NUL" (fun () -> Wire.decode_query "SELECT 1");
  let p = { Wire.stmt = "s1"; query = "SELECT $1"; param_types = [ 25; 23 ] } in
  let framed = Wire.encode_parse p in
  check_str "parse bytes"
    "P\x00\x00\x00\x1bs1\x00SELECT $1\x00\x00\x02\x00\x00\x00\x19\x00\x00\x00\x17" framed;
  let p' = Wire.decode_parse (String.sub framed 5 (String.length framed - 5)) in
  check_str "stmt" "s1" p'.stmt;
  check_str "query" "SELECT $1" p'.query;
  Alcotest.(check (list int)) "types" [ 25; 23 ] p'.param_types;
  raises_malformed "negative count" (fun () -> Wire.decode_parse "s\x00q\x00\xff\xff");
  raises_malformed "truncated types" (fun () ->
      Wire.decode_parse "s\x00q\x00\x00\x01\x00\x00")

let test_bind () =
  let b =
    {
      Wire.portal = "";
      bstmt = "s1";
      param_formats = [ 0; 1 ];
      params = [ Some "acme"; None ];
      result_formats = [ 1 ];
    }
  in
  let framed = Wire.encode_bind b in
  check_str "bind bytes"
    "B\x00\x00\x00\x20\x00s1\x00\x00\x02\x00\x00\x00\x01\x00\x02\x00\x00\x00\x04acme\xff\xff\xff\xff\x00\x01\x00\x01"
    framed;
  let b' = Wire.decode_bind (String.sub framed 5 (String.length framed - 5)) in
  check_bool "roundtrip" true (b = b');
  check_int "format 0" 0 (Wire.param_format b' 0);
  check_int "format 1" 1 (Wire.param_format b' 1);
  check_int "no formats -> text" 0 (Wire.param_format { b' with param_formats = [] } 1);
  check_int "single format applies to all" 1
    (Wire.param_format { b' with param_formats = [ 1 ] } 0);
  raises_malformed "format count mismatch" (fun () ->
      Wire.decode_bind
        "\x00s\x00\x00\x02\x00\x00\x00\x00\x00\x03\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00");
  raises_malformed "bad format code" (fun () ->
      Wire.decode_bind "\x00s\x00\x00\x01\x00\x02\x00\x00\x00\x00");
  raises_malformed "negative length" (fun () ->
      Wire.decode_bind "\x00s\x00\x00\x00\x00\x01\xff\xff\xff\xfe\x00\x00");
  raises_malformed "trailing" (fun () ->
      Wire.decode_bind "\x00s\x00\x00\x00\x00\x00\x00\x00X")

let test_misc_messages () =
  (match Wire.decode_describe_or_close "Sname\x00" with
  | 'S', "name" -> ()
  | _ -> Alcotest.fail "describe");
  raises_malformed "bad target" (fun () -> Wire.decode_describe_or_close "Xname\x00");
  (match Wire.decode_execute "p\x00\x00\x00\x00\x0a" with
  | "p", 10 -> ()
  | _ -> Alcotest.fail "execute");
  let e = Wire.error_response [ ('S', "ERROR"); ('C', "42501"); ('M', "a\x00b") ] in
  let fields = Wire.decode_fields (String.sub e 5 (String.length e - 5)) in
  Alcotest.(check (list (pair char string)))
    "fields (NUL sanitized)"
    [ ('S', "ERROR"); ('C', "42501"); ('M', "a?b") ]
    fields;
  (match Wire.decode_auth "\x00\x00\x00\x05\x01\x02\x03\x04" with
  | Wire.Auth_md5 "\x01\x02\x03\x04" -> ()
  | _ -> Alcotest.fail "md5");
  (match
     Wire.decode_auth "\x00\x00\x00\x0aSCRAM-SHA-256\x00SCRAM-SHA-256-PLUS\x00\x00"
   with
  | Wire.Auth_sasl [ "SCRAM-SHA-256"; "SCRAM-SHA-256-PLUS" ] -> ()
  | _ -> Alcotest.fail "sasl");
  (match Wire.decode_auth "\x00\x00\x00\x07" with
  | Wire.Auth_other 7 -> ()
  | _ -> Alcotest.fail "gss");
  (match Wire.decode_sasl_initial "SCRAM-SHA-256\x00\x00\x00\x00\x03abc" with
  | "SCRAM-SHA-256", Some "abc" -> ()
  | _ -> Alcotest.fail "sasl initial");
  check_str "negotiate" "v\x00\x00\x00\x13\x00\x03\x00\x00\x00\x00\x00\x01_pq_.x\x00"
    (Wire.negotiate_protocol_version ~minor:0 [ "_pq_.x" ])

(* ------------------------------------------------------------------- Sec *)

let test_sec () =
  List.iter
    (fun (raw, enc) ->
      check_str ("b64 " ^ raw) enc (Sec.b64_encode raw);
      Alcotest.(check (option string)) ("unb64 " ^ enc) (Some raw) (Sec.b64_decode enc))
    [ ("", ""); ("f", "Zg=="); ("fo", "Zm8="); ("foo", "Zm9v"); ("foobar", "Zm9vYmFy") ];
  List.iter
    (fun bad ->
      Alcotest.(check (option string)) ("reject " ^ bad) None (Sec.b64_decode bad))
    [ "Zg="; "Z==="; "Zg==Zg=="; "Zm9v\n"; "Zm9*"; "=Zg="; "Zh=="; "Zm9=" ];
  check_bool "ct equal" true (Sec.ct_equal "abc" "abc");
  check_bool "ct differ" false (Sec.ct_equal "abc" "abd");
  check_bool "ct length" false (Sec.ct_equal "abc" "ab");
  check_str "md5 password" "md5bb41a296aab6baccb36ff243a562abff"
    (Upstream.md5_password ~user:"postgres" ~password:"secret" ~salt:"\001\002\003\004")

(* ----------------------------------------------------------------- SCRAM *)

(* RFC 7677 section 3 test vector. *)
let rfc_cnonce = "rOprNGfwEbeRWgbNEkqO"
let rfc_snonce = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
let rfc_salt = "W22ZaJ0SNY7soEsUEjb6gQ=="
let rfc_server_first = "r=" ^ rfc_cnonce ^ rfc_snonce ^ ",s=" ^ rfc_salt ^ ",i=4096"

let rfc_client_final =
  "c=biws,r=" ^ rfc_cnonce ^ rfc_snonce
  ^ ",p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="

let rfc_server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="

let rfc_verifier () =
  Scram.make_verifier ~iterations:4096
    ~salt:(Option.get (Sec.b64_decode rfc_salt))
    "pencil"

let test_pbkdf2 () =
  (* RFC 7914 section 11, PBKDF2-HMAC-SHA256 P="passwd" S="salt" c=1 (first block) *)
  check_str "pbkdf2 c=1"
    "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
    (hex (Scram.pbkdf2_sha256 ~password:"passwd" ~salt:"salt" ~iterations:1))

let test_scram_client_rfc () =
  let st, first = Scram.Client.first ~user:"user" ~nonce:rfc_cnonce () in
  check_str "client-first" ("n,,n=user,r=" ^ rfc_cnonce) first;
  match Scram.Client.final st ~password:"pencil" rfc_server_first with
  | Error e -> Alcotest.fail e
  | Ok (st, final) ->
      check_str "client-final" rfc_client_final final;
      check_bool "server signature ok" true
        (Scram.Client.verify_server st rfc_server_final = Ok ());
      check_bool "bad server signature rejected" true
        (Result.is_error
           (Scram.Client.verify_server st "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
      check_bool "server error surfaced" true
        (Scram.Client.verify_server st "e=invalid-proof"
        = Error "upstream SCRAM error: invalid-proof")

let test_scram_server_rfc () =
  let start () =
    Scram.Server.start
      ~verifier:(Some (rfc_verifier ()))
      ~mock_secret:"m" ~user:"user" ~server_nonce:rfc_snonce ("n,,n=user,r=" ^ rfc_cnonce)
  in
  match start () with
  | Error e -> Alcotest.fail e
  | Ok (st, server_first) -> (
      check_str "server-first" rfc_server_first server_first;
      Alcotest.(check (result string string))
        "server-final" (Ok rfc_server_final)
        (Scram.Server.finish st rfc_client_final);
      let bad_proof =
        "c=biws,r=" ^ rfc_cnonce ^ rfc_snonce
        ^ ",p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVR="
      in
      check_bool "non-canonical base64 proof" true
        (Result.is_error (Scram.Server.finish st bad_proof));
      let wrong_proof =
        "c=biws,r=" ^ rfc_cnonce ^ rfc_snonce
        ^ ",p=eHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
      in
      check_bool "wrong proof" true (Result.is_error (Scram.Server.finish st wrong_proof));
      let bad_nonce =
        "c=biws,r=" ^ rfc_cnonce ^ "X,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
      in
      check_bool "wrong nonce" true (Result.is_error (Scram.Server.finish st bad_nonce));
      let bad_cb =
        "c=eSws,r=" ^ rfc_cnonce ^ rfc_snonce
        ^ ",p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
      in
      check_bool "cb header mismatch" true
        (Result.is_error (Scram.Server.finish st bad_cb));
      (* unknown user: same flow, always fails, deterministic fake salt *)
      match
        Scram.Server.start ~verifier:None ~mock_secret:"m" ~user:"ghost"
          ~server_nonce:rfc_snonce ("n,,n=,r=" ^ rfc_cnonce)
      with
      | Error e -> Alcotest.fail e
      | Ok (st', sf) ->
          check_bool "mock salt is stable" true
            (match
               Scram.Server.start ~verifier:None ~mock_secret:"m" ~user:"ghost"
                 ~server_nonce:rfc_snonce ("n,,n=,r=" ^ rfc_cnonce)
             with
            | Ok (_, sf2) -> sf = sf2
            | Error _ -> false);
          check_bool "mock never succeeds" true
            (Result.is_error (Scram.Server.finish st' rfc_client_final)))

let test_scram_server_rejects () =
  let start first =
    Scram.Server.start
      ~verifier:(Some (rfc_verifier ()))
      ~mock_secret:"m" ~user:"u" ~server_nonce:"abc" first
  in
  List.iter
    (fun (name, first) -> check_bool name true (Result.is_error (start first)))
    [
      ("channel binding requested", "p=tls-server-end-point,,n=,r=x");
      ("authzid", "n,a=admin,n=,r=x");
      ("mandatory extension", "n,,m=ext,n=,r=x");
      ("no nonce", "n,,n=");
      ("garbage", "hello");
      ("comma in nonce", "n,,n=,r=");
    ];
  check_bool "y flag accepted" true (Result.is_ok (start "y,,n=,r=abc"))

let test_scram_roundtrip () =
  let v = Scram.make_verifier ~iterations:4096 "s3cret!" in
  let s = Scram.verifier_to_string v in
  check_bool "prefix" true
    (String.length s > 20 && String.sub s 0 19 = "SCRAM-SHA-256$4096:");
  check_bool "parse(to_string)" true (Scram.parse_verifier s = Ok v);
  (* full client <-> server exchange with our own implementations *)
  let cst, cfirst = Scram.Client.first ~nonce:"clientnonce" () in
  match
    Scram.Server.start ~verifier:(Some v) ~mock_secret:"m" ~user:"agent"
      ~server_nonce:"servernonce" cfirst
  with
  | Error e -> Alcotest.fail e
  | Ok (sst, sfirst) -> (
      match Scram.Client.final cst ~password:"s3cret!" sfirst with
      | Error e -> Alcotest.fail e
      | Ok (cst, cfinal) -> (
          match Scram.Server.finish sst cfinal with
          | Error e -> Alcotest.fail e
          | Ok sfinal ->
              check_bool "mutual auth" true (Scram.Client.verify_server cst sfinal = Ok ());
              let _, cfinal_wrong =
                Result.get_ok (Scram.Client.final cst ~password:"wrong" sfirst)
              in
              check_bool "wrong password" true
                (Result.is_error (Scram.Server.finish sst cfinal_wrong))))

let test_parse_verifier_errors () =
  List.iter
    (fun s -> check_bool s true (Result.is_error (Scram.parse_verifier s)))
    [
      "";
      "md5abcdef";
      "SCRAM-SHA-256$4096:c2FsdA==$AAAA:BBBB";
      "SCRAM-SHA-256$0:c2FsdA==$" ^ String.make 44 'A' ^ ":" ^ String.make 44 'A';
      "SCRAM-SHA-256$x:c2FsdA==$" ^ String.make 43 'A' ^ "=:" ^ String.make 43 'A' ^ "=";
      "SCRAM-SHA-1$4096:c2FsdA==$" ^ String.make 43 'A' ^ "=:" ^ String.make 43 'A' ^ "=";
    ];
  (* a verifier exactly as stored by PostgreSQL 17 for password "haltlab" *)
  check_bool "postgres format" true
    (Result.is_ok
       (Scram.parse_verifier
          ("SCRAM-SHA-256$4096:"
          ^ Sec.b64_encode "0123456789abcdef"
          ^ "$"
          ^ Sec.b64_encode (String.make 32 'k')
          ^ ":"
          ^ Sec.b64_encode (String.make 32 's'))))

(* ---------------------------------------------------------------- Config *)

let verifier =
  Scram.verifier_to_string (Scram.make_verifier ~salt:"0123456789abcdef" "pw")

let base_config ?(extra = []) ?(auth = None) ?(upstream = None) () : Yojson.Safe.t =
  `Assoc
    ([
       ("apiVersion", `String "haltsql.dev/v1");
       ("kind", `String "ProxyConfig");
       ("listen", `String "127.0.0.1:0");
       ( "upstream",
         Option.value upstream
           ~default:
             (`Assoc
                [
                  ("host", `String "127.0.0.1");
                  ("port", `Int 5417);
                  ("database", `String "app");
                  ("user", `String "svc");
                  ("password", `String "${env:UP_PW}");
                ]) );
       ("policies", `List [ `Assoc [ ("path", `String "fixtures/policy.yaml") ] ]);
       ( "auth",
         Option.value auth
           ~default:
             (`Assoc
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
                ]) );
     ]
    @ extra)

let env = function "UP_PW" -> Some "s3cret" | _ -> None
let load j = Proxy_config.of_json ~base_dir:(Sys.getcwd ()) ~env j

let errors_of j =
  match load j with
  | Ok _ -> Alcotest.fail "expected errors"
  | Error es -> List.map Haltsql.Load_error.to_string es

let has_error_in name substr es =
  if not (List.exists (fun e -> Astring_like.contains e substr) es) then
    Alcotest.failf "%s: no error containing %S in [%s]" name substr
      (String.concat "; " es)

let has_error name substr j = has_error_in name substr (errors_of j)

let test_config_ok () =
  match load (base_config ()) with
  | Error es ->
      Alcotest.failf "unexpected: %s"
        (String.concat "; " (List.map Haltsql.Load_error.to_string es))
  | Ok c -> (
      check_str "password resolved" "s3cret" (Option.get c.upstream.password);
      check_int "default max_connections" 100 c.limits.max_connections;
      check_int "default max_message_bytes" 1048576 c.limits.max_message_bytes;
      check_str "default deny sqlstate" "42501" c.deny_sqlstate;
      check_bool "tx control default" true c.allow_transaction_control;
      check_bool "audit default stdout" true (c.audit = Proxy_config.Audit_stdout);
      check_int "listen port" 0 c.listen_port;
      match c.auth with
      | Proxy_config.Scram_users [ u ] ->
          check_str "user" "agent" u.user_name;
          check_str "policy" "proxy-test" u.user_binding.policy_name
      | _ -> Alcotest.fail "auth")

let test_config_yaml_example () =
  match
    Proxy_config.of_file
      ~env:(function "UPSTREAM_PASSWORD" -> Some "pw" | _ -> None)
      "fixtures/proxy.example.yaml"
  with
  | Ok c ->
      check_int "listen port" 6432 c.listen_port;
      check_int "idle" 300 (int_of_float c.limits.idle_timeout);
      check_str "user" "haltsql_service" c.upstream.user;
      let red = Yojson.Safe.to_string (Proxy_config.to_json_redacted c) in
      check_bool "password redacted" false (Astring_like.contains red "\"pw\"");
      check_bool "verifier redacted" false (Astring_like.contains red "SCRAM-SHA-256$")
  | Error es ->
      Alcotest.failf "example config: %s"
        (String.concat "; " (List.map Haltsql.Load_error.to_string es))

let test_config_errors () =
  has_error "unknown top key" "bogus: unknown key"
    (base_config ~extra:[ ("bogus", `Int 1) ] ());
  (match
     Proxy_config.of_json ~base_dir:(Sys.getcwd ()) ~env:(fun _ -> None) (base_config ())
   with
  | Ok _ -> Alcotest.fail "unset env var must fail"
  | Error es ->
      has_error_in "env unset" "upstream.password: environment variable UP_PW is not set"
        (List.map Haltsql.Load_error.to_string es));
  has_error "bad sqlstate" "invalid SQLSTATE"
    (base_config ~extra:[ ("deny_sqlstate", `String "4250") ] ());
  has_error "upstream unknown key" "upstream.passwd: unknown key"
    (base_config
       ~upstream:
         (Some
            (`Assoc
               [
                 ("host", `String "h");
                 ("database", `String "d");
                 ("user", `String "u");
                 ("passwd", `String "x");
               ]))
       ());
  has_error "upstream missing database" "upstream.database: required"
    (base_config
       ~upstream:(Some (`Assoc [ ("host", `String "h"); ("user", `String "u") ]))
       ());
  has_error "verify-full needs ca" "upstream.tls.ca: required when mode is verify-full"
    (base_config
       ~upstream:
         (Some
            (`Assoc
               [
                 ("host", `String "h");
                 ("database", `String "d");
                 ("user", `String "u");
                 ("tls", `Assoc [ ("mode", `String "verify-full") ]);
               ]))
       ());
  let user ?(policy = "proxy-test") ?(context = `Assoc [ ("tenant_id", `String "acme") ])
      ?(v = verifier) () =
    Some
      (`Assoc
         [
           ("method", `String "scram");
           ( "users",
             `List
               [
                 `Assoc
                   [
                     ("name", `String "agent");
                     ("scram_verifier", `String v);
                     ("policy", `String policy);
                     ("context", context);
                   ];
               ] );
         ])
  in
  has_error "unknown policy" "unknown policy \"nope\""
    (base_config ~auth:(user ~policy:"nope" ()) ());
  has_error "context missing tenant" "needs context value \"tenant_id\""
    (base_config ~auth:(user ~context:(`Assoc [ ("org", `String "x") ]) ()) ());
  has_error "bad verifier" "invalid SCRAM verifier"
    (base_config ~auth:(user ~v:"md5abc" ()) ());
  has_error "cert without tls" "tls: required when auth.method is cert"
    (base_config
       ~auth:
         (Some
            (`Assoc
               [
                 ("method", `String "cert");
                 ( "identities",
                   `List
                     [
                       `Assoc
                         [
                           ("subject_cn", `String "agent");
                           ("policy", `String "proxy-test");
                           ("context", `Assoc [ ("tenant_id", `String "acme") ]);
                         ];
                     ] );
               ]))
       ());
  has_error "spiffe prefix" "must start with spiffe://"
    (base_config
       ~auth:
         (Some
            (`Assoc
               [
                 ("method", `String "cert");
                 ( "identities",
                   `List
                     [
                       `Assoc
                         [
                           ("spiffe_id", `String "https://x");
                           ("policy", `String "proxy-test");
                           ("context", `Assoc [ ("tenant_id", `String "acme") ]);
                         ];
                     ] );
               ]))
       ());
  has_error "bad limits" "limits.max_connections: 0 is out of range"
    (base_config ~extra:[ ("limits", `Assoc [ ("max_connections", `Int 0) ]) ] ());
  has_error "unknown placeholder" "unknown placeholder ${ctx.tenant_id}"
    (base_config ~extra:[ ("deny_sqlstate", `String "${ctx.tenant_id}") ] ());
  has_error "tls cert unreadable" "tls.cert"
    (base_config
       ~extra:
         [
           ( "tls",
             `Assoc
               [
                 ("cert", `String "/nonexistent.pem"); ("key", `String "/nonexistent.key");
               ] );
         ]
       ())

(* Regression: tls.key given as a ${file:...} placeholder expands to the PEM contents.
   It used to be treated as a path, and the "cannot open <path>" error then printed the
   whole private key. Inline PEM is now accepted, and no TLS error ever echoes the
   value. *)
let test_config_tls_key_material () =
  let tmp contents =
    let f = Filename.temp_file "haltsql_tls" ".pem" in
    Out_channel.with_open_bin f (fun oc -> output_string oc contents);
    f
  in
  let tls_errors ~cert ~key =
    errors_of
      (base_config
         ~extra:[ ("tls", `Assoc [ ("cert", `String cert); ("key", `String key) ]) ]
         ())
    |> List.filter (fun e -> Astring_like.contains e "tls.")
  in
  let secret = "SECRETKEYBYTES0123456789abcdef" in
  let garbled =
    "-----BEGIN PRIVATE KEY-----\n" ^ secret ^ "\n-----END PRIVATE KEY-----\n"
  in
  let no_secret name es =
    List.iter
      (fun e ->
        if Astring_like.contains e secret || Astring_like.contains e "BEGIN PRIVATE" then
          Alcotest.failf "%s: error leaks key material: %s" name e)
      es
  in
  (* inline garbage through ${file:...} *)
  let f = tmp garbled in
  let es = tls_errors ~cert:"/nonexistent.pem" ~key:("${file:" ^ f ^ "}") in
  no_secret "file placeholder" es;
  has_error_in "file placeholder" "invalid PEM private key" es;
  (* inline garbage directly *)
  let es = tls_errors ~cert:"/nonexistent.pem" ~key:garbled in
  no_secret "inline" es;
  (* key text without a PEM header, taken as a path *)
  let es = tls_errors ~cert:"/nonexistent.pem" ~key:secret in
  no_secret "as path" es;
  has_error_in "as path" "cannot read private key file" es;
  (* a valid key through ${file:...} loads (only the bogus cert is reported) *)
  let good = X509.Private_key.encode_pem (X509.Private_key.generate `ED25519) in
  let g = tmp good in
  let es = tls_errors ~cert:"/nonexistent.pem" ~key:("${file:" ^ g ^ "}") in
  check_bool
    (Printf.sprintf "valid inline key accepted: [%s]" (String.concat "; " es))
    false
    (List.exists (fun e -> Astring_like.contains e "tls.key") es);
  Sys.remove f;
  Sys.remove g

(* --------------------------------------------------------------- Enforce *)

let binding ?(ctx = Haltsql.Context.make [ ("tenant_id", Haltsql.Context.One "acme") ]) ()
    =
  let policy = Result.get_ok (Haltsql.Policy_load.of_file "fixtures/policy.yaml") in
  { Proxy_config.policy_name = "proxy-test"; policy; context = ctx }

let q_orders = "SELECT id FROM app.orders WHERE tenant_id = $1 ORDER BY id LIMIT 10"

let test_enforce_simple () =
  let b = binding () in
  (match Enforce.simple ~sqlstate:"42501" b "SELECT code FROM app.currencies LIMIT 5" with
  | _, Ok () -> ()
  | _, Error _ -> Alcotest.fail "currencies should be allowed");
  (match Enforce.simple ~sqlstate:"42501" b q_orders with
  | v, Error d ->
      check_bool "verdict itself allowed" true v.allowed;
      Alcotest.(check (list string)) "codes" [ "E_PARAM_UNBOUND" ] d.codes;
      check_str "sqlstate" "42501" d.sqlstate
  | _, Ok () -> Alcotest.fail "bound params in simple protocol must be denied");
  (match
     Enforce.simple ~sqlstate:"HV000" b
       "SELECT email FROM app.users WHERE tenant_id = $1 LIMIT 1"
   with
  | _, Error d ->
      Alcotest.(check (list string)) "codes" [ "E_COLUMN_DENIED" ] d.codes;
      let f = Enforce.deny_fields d in
      Alcotest.(check (option string)) "S" (Some "ERROR") (List.assoc_opt 'S' f);
      Alcotest.(check (option string)) "V" (Some "ERROR") (List.assoc_opt 'V' f);
      Alcotest.(check (option string)) "C" (Some "HV000") (List.assoc_opt 'C' f);
      Alcotest.(check (option string))
        "D" (Some "HaltSQL reasons: E_COLUMN_DENIED") (List.assoc_opt 'D' f);
      check_bool "M prefix" true
        (Astring_like.contains (List.assoc 'M' f)
           "haltsql: query denied by policy \"proxy-test\"");
      check_bool "H present" true (List.mem_assoc 'H' f)
  | _, Ok () -> Alcotest.fail "email must be denied");
  (match Enforce.simple ~sqlstate:"42501" ~allow_tx:true b "begin" with
  | v, Ok () ->
      Alcotest.(check (option string)) "kind" (Some "transaction") v.statement_kind
  | _ -> Alcotest.fail "BEGIN allowed with allow_tx");
  match Enforce.simple ~sqlstate:"42501" b "BEGIN" with
  | _, Error d ->
      Alcotest.(check (list string))
        "BEGIN without allow_tx" [ "E_STATEMENT_KIND" ] d.codes
  | _ -> Alcotest.fail "BEGIN must go through the policy when allow_tx is false"

let test_transaction_control () =
  List.iter
    (fun s -> check_bool s true (Enforce.transaction_control s))
    [
      "BEGIN";
      "begin;";
      "  Begin Work  ";
      "START TRANSACTION";
      "BEGIN ISOLATION LEVEL SERIALIZABLE";
      "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY";
      "START TRANSACTION READ WRITE NOT DEFERRABLE";
      "COMMIT";
      "commit work";
      "END";
      "ROLLBACK";
      "ROLLBACK TRANSACTION";
      "ABORT";
    ];
  List.iter
    (fun s -> check_bool s false (Enforce.transaction_control s))
    [
      "";
      "BEGIN; SELECT 1";
      "COMMIT AND CHAIN";
      "ROLLBACK TO SAVEPOINT a";
      "SAVEPOINT a";
      "PREPARE TRANSACTION 'x'";
      "BEGIN -- c";
      "BEGIN /* x */";
      "COMMIT PREPARED 'x'";
      "SET TRANSACTION READ WRITE";
      "BEGIN ISOLATION LEVEL";
      "END IF";
      "BEGIN;;";
    ]

let bind_msg ?(formats = []) params =
  { Wire.portal = ""; bstmt = "s"; param_formats = formats; params; result_formats = [] }

let test_enforce_bind () =
  let b = binding () in
  let v, _ = Enforce.parse ~sqlstate:"42501" b q_orders in
  check_bool "parse allowed" true v.allowed;
  (match Enforce.bind ~sqlstate:"42501" v (bind_msg [ Some "globex" ]) with
  | Ok b' ->
      Alcotest.(check (list (option string))) "overwritten" [ Some "acme" ] b'.params
  | Error d -> Alcotest.fail d.message);
  (match Enforce.bind ~sqlstate:"42501" v (bind_msg [ None ]) with
  | Ok b' ->
      Alcotest.(check (list (option string))) "NULL overwritten" [ Some "acme" ] b'.params
  | Error d -> Alcotest.fail d.message);
  (match
     Enforce.bind ~sqlstate:"42501" v (bind_msg ~formats:[ 1 ] [ Some "\x00\x01" ])
   with
  | Error d ->
      Alcotest.(check (list string)) "binary rejected" [ "E_PARAM_UNBOUND" ] d.codes
  | Ok _ -> Alcotest.fail "binary tenancy param must be rejected");
  (match Enforce.bind ~sqlstate:"42501" v (bind_msg []) with
  | Error d ->
      check_bool "missing param" true
        (Astring_like.contains d.message "supplies 0 parameter")
  | Ok _ -> Alcotest.fail "missing tenancy param must be rejected");
  (* a statement without tenancy params passes unchanged *)
  let v2, _ =
    Enforce.parse ~sqlstate:"42501" b "SELECT code FROM app.currencies LIMIT 5"
  in
  let m = bind_msg ~formats:[ 1 ] [] in
  check_bool "unchanged" true (Enforce.bind ~sqlstate:"42501" v2 m = Ok m);
  check_str "array literal" {|{"a","b\"c","d\\e"}|}
    (Enforce.context_text (Haltsql.Context.Many [ "a"; "b\"c"; "d\\e" ]));
  check_str "scalar" "acme" (Enforce.context_text (Haltsql.Context.One "acme"))

(* ------------------------------------------------------------ Stmt_state *)

let verdict_with params : Haltsql.Verdict.t =
  {
    allowed = true;
    reasons = [];
    shadow_reasons = [];
    policy_name = "p";
    policy_version = "v";
    statement_kind = Some "select";
    tables = [];
    columns = [];
    bind_params = List.map (fun n -> (n, Haltsql.Context.One "t")) params;
    fingerprint = None;
    sql_sha256 = "";
    elapsed_us = 0;
  }

(* Regression: a client-declared Parse type for a tenancy parameter (float8 =
   701 rounds 64-bit IDs, name = 19 / "char" = 18 truncate) must not reach
   PostgreSQL; other parameters keep their declared types. *)
let test_reset_tenancy_param_types () =
  let b = binding () in
  let v, r = Enforce.parse ~sqlstate:"42501" b q_orders in
  check_bool "parse allowed" true (Result.is_ok r);
  Alcotest.(check (list int)) "tenancy param" [ 1 ] (List.map fst v.bind_params);
  let mk types = { Wire.stmt = "s"; query = q_orders; param_types = types } in
  let reset types = (Enforce.reset_tenancy_param_types v (mk types)).param_types in
  Alcotest.(check (list int)) "float8 cleared" [ 0 ] (reset [ 701 ]);
  Alcotest.(check (list int)) "name cleared" [ 0 ] (reset [ 19 ]);
  Alcotest.(check (list int)) "char cleared" [ 0 ] (reset [ 18 ]);
  Alcotest.(check (list int)) "text cleared too" [ 0 ] (reset [ 25 ]);
  Alcotest.(check (list int)) "no types" [] (reset []);
  let p0 = mk [ 0 ] in
  check_bool "unchanged is physically equal" true
    (Enforce.reset_tenancy_param_types v p0 == p0);
  (* only tenancy params are touched *)
  let v3 = verdict_with [ 2 ] in
  let p3 = { Wire.stmt = "s"; query = "q"; param_types = [ 23; 701; 19 ] } in
  Alcotest.(check (list int))
    "only $2" [ 23; 0; 19 ] (Enforce.reset_tenancy_param_types v3 p3).param_types;
  (* the rewritten message round-trips through the wire codec *)
  let enc = Wire.encode_parse (Enforce.reset_tenancy_param_types v (mk [ 701 ])) in
  let back = Wire.decode_parse (String.sub enc 5 (String.length enc - 5)) in
  Alcotest.(check (list int)) "encoded" [ 0 ] back.param_types;
  check_str "query kept" q_orders back.query

let lookup_str st name =
  match Stmt_state.lookup st name with
  | Stmt_state.Found v -> Printf.sprintf "found%d" (List.length v.bind_params)
  | Stmt_state.Missing -> "missing"
  | Stmt_state.Wait -> "wait"

let test_stmt_state () =
  let st = Stmt_state.create () in
  check_str "empty" "missing" (lookup_str st "s1");
  Stmt_state.note_parse st "s1" (verdict_with [ 1 ]);
  check_str "same segment uses pending" "found1" (lookup_str st "s1");
  Stmt_state.end_segment st;
  check_str "later segment must wait" "wait" (lookup_str st "s1");
  check_bool "parse complete" true (Stmt_state.on_parse_complete st = Ok ());
  check_str "committed" "found1" (lookup_str st "s1");
  Stmt_state.on_ready st;
  check_int "no segments" 0 (Stmt_state.in_flight st);
  (* unnamed replaced; a Parse ignored after an upstream error is never committed *)
  Stmt_state.note_parse st "" (verdict_with [ 1 ]);
  Stmt_state.end_segment st;
  ignore (Stmt_state.on_parse_complete st);
  Stmt_state.on_ready st;
  check_str "unnamed committed" "found1" (lookup_str st "");
  Stmt_state.touch st;
  Stmt_state.note_parse st "" (verdict_with [ 2; 3 ]);
  Stmt_state.end_segment st;
  check_bool "error, no injected deny" true (Stmt_state.on_error st = None);
  Stmt_state.on_ready st;
  check_str "ignored unnamed parse not committed, old one dropped" "missing"
    (lookup_str st "");
  (* close *)
  Stmt_state.note_close_statement st "s1";
  check_str "closed in segment" "missing" (lookup_str st "s1");
  Stmt_state.end_segment st;
  check_bool "close complete" true (Stmt_state.on_close_complete st = Ok ());
  Stmt_state.on_ready st;
  check_str "closed" "missing" (lookup_str st "s1");
  (* injected deny is returned once, for the head segment *)
  Stmt_state.set_deny st ~token:"tok" [ ('C', "42501") ];
  Stmt_state.end_segment st;
  (match Stmt_state.on_error st with
  | Some ("tok", [ ('C', "42501") ]) -> ()
  | _ -> Alcotest.fail "expected injected deny");
  check_bool "deny consumed" true (Stmt_state.on_error st = None);
  Stmt_state.on_ready st;
  (* desync is detected *)
  check_bool "unexpected ParseComplete" true
    (Result.is_error (Stmt_state.on_parse_complete st));
  check_bool "unexpected CloseComplete" true
    (Result.is_error (Stmt_state.on_close_complete st));
  let small = Stmt_state.create ~max_pending:2 () in
  Stmt_state.note_parse small "a" (verdict_with []);
  Stmt_state.note_parse small "b" (verdict_with []);
  match Stmt_state.note_parse small "c" (verdict_with []) with
  | () -> Alcotest.fail "expected Overflow"
  | exception Stmt_state.Overflow -> ()

(* --------------------------------------------------------- Io / Upstream *)

(* Frame lengths are validated before anything is allocated. *)
let test_io_length_bounds () =
  let attempt bytes =
    Lwt_main.run
      (let a, b = Lwt_unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
       let io = Io.of_fd b in
       Lwt.finalize
         (fun () ->
           let* _ = Lwt_unix.write_string a bytes 0 (String.length bytes) in
           let* () = Lwt_unix.close a in
           Lwt.catch
             (fun () ->
               let* _ = Io.read_message io ~max:1024 in
               Lwt.return "ok")
             (function
               | Wire.Malformed _ -> Lwt.return "malformed"
               | Io.Too_large _ -> Lwt.return "too_large"
               | Io.Closed -> Lwt.return "closed"
               | e -> Lwt.return (Printexc.to_string e)))
         (fun () -> Io.close io))
  in
  check_str "negative length" "malformed" (attempt "Q\xff\xff\xff\xff");
  check_str "length below header" "malformed" (attempt "Q\x00\x00\x00\x03");
  check_str "oversized length" "too_large" (attempt "Q\x7f\xff\xff\xff");
  check_str "truncated body" "closed" (attempt "Q\x00\x00\x00\x10abc");
  check_str "valid" "ok" (attempt "Q\x00\x00\x00\x05x")

(* Regression: an upstream that accepts TCP and then never answers the SSLRequest used
   to hang [Upstream.connect] (and [send_cancel]) forever; both are now bounded by
   [connect_timeout]. *)
let test_stalled_upstream () =
  let listener = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.setsockopt listener Unix.SO_REUSEADDR true;
  Unix.bind listener (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  Unix.listen listener 16;
  let port = match Unix.getsockname listener with Unix.ADDR_INET (_, p) -> p | _ -> 0 in
  let u =
    {
      Proxy_config.host = "127.0.0.1";
      port;
      database = "db";
      user = "u";
      password = None;
      tls_mode = Proxy_config.Tls_require;
      tls_ca = [];
      connect_timeout = 0.3;
    }
  in
  let t0 = Unix.gettimeofday () in
  let r =
    Lwt_main.run
      (Lwt.catch
         (fun () ->
           let* io = Upstream.connect u ~application_name:None in
           let* () = Io.close io in
           Lwt.return "connected")
         (function
           | Upstream.Upstream_error m -> Lwt.return m
           | e -> Lwt.return (Printexc.to_string e)))
  in
  let dt = Unix.gettimeofday () -. t0 in
  check_str "connect fails with a timeout" "upstream timed out" r;
  check_bool (Printf.sprintf "bounded (%.2fs)" dt) true (dt < 2.);
  let t0 = Unix.gettimeofday () in
  Lwt_main.run (Upstream.send_cancel u ~pid:1 ~key:2);
  let dt = Unix.gettimeofday () -. t0 in
  check_bool (Printf.sprintf "cancel bounded (%.2fs)" dt) true (dt < 2.);
  Unix.close listener

let () =
  Sec.init_rng ();
  Alcotest.run "pgwire"
    [
      ( "wire",
        [
          Alcotest.test_case "framing" `Quick test_frame;
          Alcotest.test_case "startup packets" `Quick test_startup;
          Alcotest.test_case "query and parse" `Quick test_query_parse;
          Alcotest.test_case "bind" `Quick test_bind;
          Alcotest.test_case "other messages" `Quick test_misc_messages;
        ] );
      ("sec", [ Alcotest.test_case "base64, ct_equal, md5" `Quick test_sec ]);
      ( "io",
        [
          Alcotest.test_case "frame length bounds" `Quick test_io_length_bounds;
          Alcotest.test_case "stalled upstream is bounded" `Quick test_stalled_upstream;
        ] );
      ( "scram",
        [
          Alcotest.test_case "pbkdf2 vector" `Quick test_pbkdf2;
          Alcotest.test_case "RFC 7677 client" `Quick test_scram_client_rfc;
          Alcotest.test_case "RFC 7677 server" `Quick test_scram_server_rfc;
          Alcotest.test_case "server rejects" `Quick test_scram_server_rejects;
          Alcotest.test_case "verifier + roundtrip" `Quick test_scram_roundtrip;
          Alcotest.test_case "verifier parse errors" `Quick test_parse_verifier_errors;
        ] );
      ( "config",
        [
          Alcotest.test_case "valid" `Quick test_config_ok;
          Alcotest.test_case "YAML example" `Quick test_config_yaml_example;
          Alcotest.test_case "errors" `Quick test_config_errors;
          Alcotest.test_case "tls key material never echoed" `Quick
            test_config_tls_key_material;
        ] );
      ( "enforce",
        [
          Alcotest.test_case "simple" `Quick test_enforce_simple;
          Alcotest.test_case "transaction control" `Quick test_transaction_control;
          Alcotest.test_case "bind" `Quick test_enforce_bind;
          Alcotest.test_case "tenancy param types reset" `Quick
            test_reset_tenancy_param_types;
        ] );
      ("stmt_state", [ Alcotest.test_case "bookkeeping" `Quick test_stmt_state ]);
    ]
