(* Console authentication and auth-related config: dev-mode rules, trusted proxies and
   the proxy shared secret, role union, session_hours enforcement for OIDC, and lazy
   secret placeholders. Calls Console_auth.authenticate directly (no server). *)

module C = Haltsql_console
module Cfg = C.Console_config
module A = C.Console_auth

let ( let* ) = Lwt.bind

let cfg_of auth ?(listen = "127.0.0.1:0") () =
  Cfg.of_json (`Assoc [ ("listen", `String listen); ("auth", `Assoc auth) ])

let expect_invalid name f =
  match f () with
  | _ -> Alcotest.failf "%s: expected Invalid" name
  | exception Cfg.Invalid _ -> ()

let request ?(headers = []) () =
  Cohttp.Request.make
    ~headers:(Cohttp.Header.of_list headers)
    (Uri.of_string "http://console.test/api/v1/me")

let auth_of ?fetch ?now (c : Cfg.t) ?peer headers =
  Lwt_main.run (A.authenticate (A.create ?fetch ?now c.auth) ?peer (request ~headers ()))

let roles_s rs = List.map C.Rbac.role_to_string rs

let check_ok msg ?role ?roles outcome =
  match outcome with
  | A.Unauthenticated m -> Alcotest.failf "%s: unauthenticated (%s)" msg m
  | A.Authenticated (p : C.Ctx.principal) ->
      Option.iter
        (fun r ->
          Alcotest.(check string)
            (msg ^ ": role") (C.Rbac.role_to_string r)
            (C.Rbac.role_to_string p.role))
        role;
      Option.iter
        (fun rs ->
          Alcotest.(check (list string)) (msg ^ ": roles") (roles_s rs) (roles_s p.roles))
        roles

let check_rejected msg ?reason outcome =
  match outcome with
  | A.Authenticated p -> Alcotest.failf "%s: authenticated as %s" msg p.id
  | A.Unauthenticated m ->
      Option.iter (fun r -> Alcotest.(check string) (msg ^ ": reason") r m) reason

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let token_entry =
  `Assoc
    [
      ("name", `String "ci");
      ("sha256", `String (Haltsql.sha256_hex "tok"));
      ("role", `String "audit");
    ]

(* ---- dev ---- *)

let dev_tests =
  let dev = ("dev", `Bool true) in
  [
    ( "rejected alongside oidc, proxy or tokens",
      `Quick,
      fun () ->
        expect_invalid "tokens" (fun () ->
            cfg_of [ dev; ("tokens", `List [ token_entry ]) ] ());
        expect_invalid "proxy" (fun () ->
            cfg_of
              [
                dev;
                ( "proxy",
                  `Assoc
                    [
                      ("user_header", `String "x-user");
                      ("trusted_proxies", `List [ `String "10.0.0.0/8" ]);
                    ] );
              ]
              ());
        expect_invalid "oidc" (fun () ->
            cfg_of
              [
                dev;
                ( "oidc",
                  `List
                    [
                      `Assoc
                        [
                          ("name", `String "idp");
                          ("issuer", `String "https://idp.test");
                          ("audience", `String "console");
                        ];
                    ] );
              ]
              ()) );
    ( "rejected on non-loopback listen",
      `Quick,
      fun () ->
        List.iter
          (fun listen -> expect_invalid listen (fun () -> cfg_of [ dev ] ~listen ()))
          [ "0.0.0.0:8090"; ":8090"; "*:8090"; "10.1.2.3:8090"; "[::]:8090"; "nope" ] );
    ( "accepted on loopback listen",
      `Quick,
      fun () ->
        List.iter
          (fun listen -> ignore (cfg_of [ dev ] ~listen ()))
          [ "127.0.0.1:0"; "127.0.0.2:8090"; "[::1]:8090"; "localhost:8090" ] );
    ( "validate_dev after a listen override",
      `Quick,
      fun () ->
        let c = cfg_of [ dev ] () in
        Alcotest.(check bool) "ok" true (Cfg.validate_dev c = Ok ());
        Alcotest.(check bool)
          "0.0.0.0" true
          (Result.is_error (Cfg.validate_dev { c with listen = "0.0.0.0:8090" })) );
    ( "defaults to the dev role",
      `Quick,
      fun () ->
        let role c =
          match (c : Cfg.t).auth.dev with
          | Some d -> C.Rbac.role_to_string d.dev_role
          | None -> "none"
        in
        Alcotest.(check string) "dev: true" "dev" (role (cfg_of [ dev ] ()));
        Alcotest.(check string)
          "dev: {user}" "dev"
          (role (cfg_of [ ("dev", `Assoc [ ("user", `String "me@x") ]) ] ()));
        check_ok "anonymous request is the dev user" ~role:C.Rbac.Dev
          ~roles:[ C.Rbac.Dev ]
          (auth_of (cfg_of [ dev ] ()) []) );
    ( "no dev fallback without dev",
      `Quick,
      fun () ->
        let c = cfg_of [ ("tokens", `List [ token_entry ]) ] () in
        check_rejected "anonymous" ~reason:"authentication required" (auth_of c []);
        check_ok "token" ~role:C.Rbac.Audit
          (auth_of c [ ("authorization", "Bearer tok") ]) );
  ]

(* ---- proxy ---- *)

let proxy_cfg ?(roles = [ ("owner", [ "owners" ]); ("admin", [ "admins" ]) ]) fields =
  cfg_of
    [
      ( "proxy",
        `Assoc
          ([
             ("user_header", `String "X-Auth-Request-Email");
             ("groups_header", `String "X-Auth-Request-Groups");
           ]
          @ fields) );
      ( "roles",
        `Assoc
          (List.map (fun (r, gs) -> (r, `List (List.map (fun g -> `String g) gs))) roles)
      );
    ]
    ()

let user ?(groups = "owners") extra =
  [ ("x-auth-request-email", "lee@acme.test"); ("x-auth-request-groups", groups) ] @ extra

let untrusted = "proxy identity headers from an untrusted source"

let proxy_tests =
  [
    ( "requires trusted_proxies or a shared secret",
      `Quick,
      fun () ->
        expect_invalid "neither" (fun () -> proxy_cfg []);
        expect_invalid "bad cidr" (fun () ->
            proxy_cfg [ ("trusted_proxies", `List [ `String "10.0.0.0/99" ]) ]);
        expect_invalid "header without digest" (fun () ->
            proxy_cfg [ ("secret_header", `String "x-proxy-secret") ]);
        expect_invalid "bad digest" (fun () ->
            proxy_cfg
              [
                ("secret_header", `String "x-proxy-secret");
                ("secret_sha256", `String "ab");
              ]) );
    ( "trusted peers (IPv4 and IPv6 CIDR)",
      `Quick,
      fun () ->
        let c =
          proxy_cfg
            [
              ( "trusted_proxies",
                `List [ `String "10.0.0.0/8"; `String "fd00::/8"; `String "192.168.1.7" ]
              );
            ]
        in
        check_ok "10.0.0.5" ~role:C.Rbac.Owner (auth_of c ~peer:"10.0.0.5" (user []));
        check_ok "fd00::1" (auth_of c ~peer:"fd00::1" (user []));
        check_ok "[fd12::5]" (auth_of c ~peer:"[fd12::5]" (user []));
        check_ok "single ip" (auth_of c ~peer:"192.168.1.7" (user []));
        check_ok "ipv4-mapped" (auth_of c ~peer:"::ffff:10.1.1.1" (user []));
        check_rejected "outside v4" ~reason:untrusted
          (auth_of c ~peer:"11.0.0.5" (user []));
        check_rejected "outside v6" ~reason:untrusted (auth_of c ~peer:"::1" (user []));
        check_rejected "neighbour of single ip" ~reason:untrusted
          (auth_of c ~peer:"192.168.1.8" (user []));
        check_rejected "unknown peer" ~reason:untrusted (auth_of c (user []));
        check_rejected "no headers, untrusted peer" ~reason:"authentication required"
          (auth_of c ~peer:"11.0.0.5" []) );
    ( "shared-secret header",
      `Quick,
      fun () ->
        let c =
          proxy_cfg
            [
              ("secret_header", `String "X-Proxy-Secret");
              ("secret_sha256", `String (Haltsql.sha256_hex "s3cret"));
            ]
        in
        check_ok "right secret" (auth_of c (user [ ("x-proxy-secret", "s3cret") ]));
        check_rejected "wrong secret" ~reason:untrusted
          (auth_of c (user [ ("x-proxy-secret", "guess") ]));
        check_rejected "missing secret" ~reason:untrusted (auth_of c (user []));
        (* both checks configured: both must pass *)
        let c =
          proxy_cfg
            [
              ("trusted_proxies", `List [ `String "10.0.0.0/8" ]);
              ("secret_header", `String "X-Proxy-Secret");
              ("secret_sha256", `String (Haltsql.sha256_hex "s3cret"));
            ]
        in
        check_ok "both"
          (auth_of c ~peer:"10.2.3.4" (user [ ("x-proxy-secret", "s3cret") ]));
        check_rejected "secret but bad peer" ~reason:untrusted
          (auth_of c ~peer:"8.8.8.8" (user [ ("x-proxy-secret", "s3cret") ])) );
    ( "group_prefix",
      `Quick,
      fun () ->
        let c =
          proxy_cfg
            ~roles:[ ("admin", [ "admins" ]); ("analyst", [ "proxy:admins" ]) ]
            [
              ("trusted_proxies", `List [ `String "::1" ]);
              ("group_prefix", `String "proxy:");
            ]
        in
        check_ok "prefixed group" ~role:C.Rbac.Analyst ~roles:[ C.Rbac.Analyst ]
          (auth_of c ~peer:"::1" (user ~groups:"admins" [])) );
    ( "union of roles",
      `Quick,
      fun () ->
        let c =
          proxy_cfg
            ~roles:
              [ ("owner", [ "owners" ]); ("admin", [ "admins" ]); ("dev", [ "eng" ]) ]
            [ ("trusted_proxies", `List [ `String "127.0.0.1" ]) ]
        in
        check_ok "owner+admin" ~role:C.Rbac.Admin
          ~roles:[ C.Rbac.Admin; C.Rbac.Owner ]
          (auth_of c ~peer:"127.0.0.1" (user ~groups:"owners, admins" []));
        check_ok "all three"
          ~roles:[ C.Rbac.Admin; C.Rbac.Owner; C.Rbac.Dev ]
          (auth_of c ~peer:"127.0.0.1" (user ~groups:"eng,owners,admins,other" []));
        check_rejected "no mapped group"
          (auth_of c ~peer:"127.0.0.1" (user ~groups:"other" [])) );
  ]

(* ---- OIDC session_hours ---- *)

let now = 1_800_000_000.
let issuer = "https://idp.test"
let jwks_uri = "https://idp.test/jwks"

let ed_priv =
  match Mirage_crypto_ec.Ed25519.priv_of_octets (String.make 32 '\007') with
  | Ok k -> k
  | Error _ -> assert false

let jwks =
  let key =
    {
      Haltsql_auth.Jwk.kid = Some "k1";
      alg = None;
      use = Some "sig";
      key = Haltsql_auth.Jwk.Ed25519 (Mirage_crypto_ec.Ed25519.pub_of_priv ed_priv);
    }
  in
  Yojson.Safe.to_string (`Assoc [ ("keys", `List [ Haltsql_auth.Jwk.to_json key ]) ])

let fetch uri =
  if Uri.to_string uri = jwks_uri then Lwt.return (Ok jwks)
  else Lwt.return (Error "not found")

let oidc_cfg ?(session_hours = 8) ?(extra = []) () =
  cfg_of
    (extra
    @ [
        ( "oidc",
          `List
            [
              `Assoc
                [
                  ("name", `String "idp");
                  ("issuer", `String issuer);
                  ("audience", `String "console");
                  ("jwks_uri", `String jwks_uri);
                ];
            ] );
        ( "roles",
          `Assoc
            [
              ("owner", `List [ `String "idp:owners" ]);
              ("admin", `List [ `String "idp:admins" ]);
            ] );
        ("session_hours", `Int session_hours);
      ])
    ()

let jwt claims =
  Haltsql_auth.Jwt.sign ~alg:"EdDSA" ~kid:"k1" (Haltsql_auth.Jwt.Sign_ed25519 ed_priv)
    (`Assoc
       ([
          ("iss", `String issuer);
          ("aud", `String "console");
          ("sub", `String "u1");
          ("email", `String "kim@acme.test");
          ("exp", `Float (now +. 600.));
          ("groups", `List [ `String "owners"; `String "admins" ]);
        ]
       @ claims))

let oidc_auth c claims =
  auth_of ~fetch ~now:(fun () -> now) c [ ("authorization", "Bearer " ^ jwt claims) ]

let expired = "session expired; sign in again"

let session_tests =
  [
    ( "session_hours range",
      `Quick,
      fun () ->
        expect_invalid "0" (fun () -> oidc_cfg ~session_hours:0 ());
        expect_invalid "721" (fun () -> oidc_cfg ~session_hours:721 ());
        ignore (oidc_cfg ~session_hours:720 ()) );
    ( "OIDC sign-in age",
      `Quick,
      fun () ->
        let c = oidc_cfg () in
        check_ok "fresh iat" ~role:C.Rbac.Admin
          ~roles:[ C.Rbac.Admin; C.Rbac.Owner ]
          (oidc_auth c [ ("iat", `Float (now -. 60.)) ]);
        check_ok "no iat or auth_time" (oidc_auth c []);
        check_ok "auth_time within"
          (oidc_auth c
             [
               ("iat", `Float (now -. 60.)); ("auth_time", `Float (now -. (7. *. 3600.)));
             ]);
        check_rejected "old auth_time, fresh iat" ~reason:expired
          (oidc_auth c
             [
               ("iat", `Float (now -. 60.)); ("auth_time", `Float (now -. (9. *. 3600.)));
             ]);
        check_rejected "old iat" ~reason:expired
          (oidc_auth c [ ("iat", `Float (now -. (8. *. 3600.) -. 1.)) ]) );
    ( "require_auth_time",
      `Quick,
      fun () ->
        Alcotest.(check bool) "default off" false (oidc_cfg ()).auth.require_auth_time;
        let c = oidc_cfg ~extra:[ ("require_auth_time", `Bool true) ] () in
        check_rejected "no claims" ~reason:expired (oidc_auth c []);
        check_rejected "iat only" ~reason:expired
          (oidc_auth c [ ("iat", `Float (now -. 60.)) ]);
        check_ok "fresh auth_time" (oidc_auth c [ ("auth_time", `Float (now -. 60.)) ]);
        check_rejected "old auth_time" ~reason:expired
          (oidc_auth c [ ("auth_time", `Float (now -. (9. *. 3600.))) ]);
        Alcotest.(check bool)
          "session_fresh" false
          (A.session_fresh ~require_auth_time:true ~now ~session_hours:1
             [ ("iat", `Float now) ]);
        expect_invalid "not a bool" (fun () ->
            oidc_cfg ~extra:[ ("require_auth_time", `String "yes") ] ()) );
    ( "sessions safeguard is verified only for OIDC-only with require_auth_time",
      `Quick,
      fun () ->
        let v c = C.Access.sessions_verified (c : Cfg.t).auth in
        let strict = [ ("require_auth_time", `Bool true) ] in
        Alcotest.(check bool) "oidc only, strict" true (v (oidc_cfg ~extra:strict ()));
        Alcotest.(check bool) "oidc only, lenient" false (v (oidc_cfg ()));
        Alcotest.(check bool)
          "oidc + tokens" false
          (v (oidc_cfg ~extra:(("tokens", `List [ token_entry ]) :: strict) ()));
        Alcotest.(check bool)
          "oidc + proxy" false
          (v
             (oidc_cfg
                ~extra:
                  (( "proxy",
                     `Assoc
                       [
                         ("user_header", `String "x-user");
                         ("trusted_proxies", `List [ `String "10.0.0.0/8" ]);
                       ] )
                  :: strict)
                ()));
        Alcotest.(check bool)
          "tokens only" false
          (v (cfg_of (("tokens", `List [ token_entry ]) :: strict) ()));
        Alcotest.(check bool) "dev" false (v (cfg_of [ ("dev", `Bool true) ] ())) );
    ( "sessions safeguard detail",
      `Quick,
      fun () ->
        let cfg = Helpers.config ~extra:[ ("auth", `Assoc [ ("dev", `Bool true) ]) ] () in
        Helpers.with_console ~background:false cfg (fun r ->
            let* code, j = Helpers.get r "/api/v1/access/roles" in
            Alcotest.(check int) "status" 200 code;
            let sessions =
              match Helpers.member "safeguards" j with
              | `List l ->
                  List.find (fun x -> Helpers.member "id" x = `String "sessions") l
              | _ -> Alcotest.fail "no safeguards"
            in
            Alcotest.(check bool)
              "not verified" true
              (Helpers.member "verified" sessions = `Bool false);
            let detail =
              match Helpers.member "detail" sessions with `String s -> s | _ -> ""
            in
            Alcotest.(check bool)
              "auth_time, else iat" true
              (contains detail "by auth_time, else iat");
            Alcotest.(check bool)
              "proxy and tokens" true
              (contains detail
                 "proxy and service-token sessions are not limited by the console");
            Lwt.return_unit) );
    ( "session_fresh",
      `Quick,
      fun () ->
        let f claims = A.session_fresh ~now ~session_hours:1 claims in
        Alcotest.(check bool) "none" true (f []);
        Alcotest.(check bool) "iat ok" true (f [ ("iat", `Float (now -. 3600.)) ]);
        Alcotest.(check bool)
          "iat old" false
          (f [ ("iat", `Int (int_of_float now - 3601)) ]);
        Alcotest.(check bool)
          "auth_time wins" false
          (f [ ("iat", `Float now); ("auth_time", `Float (now -. 7200.)) ]) );
  ]

(* ---- lazy secrets ---- *)

let write_config text =
  let f = Filename.temp_file "console" ".json" in
  let oc = open_out f in
  output_string oc text;
  close_out oc;
  f

let doc ~integrations =
  Yojson.Safe.to_string
    (`Assoc
       [
         ("listen", `String "127.0.0.1:0");
         ("auth", `Assoc [ ("dev", `Bool true) ]);
         ( "verifiers",
           `List
             [
               `Assoc
                 [
                   ("name", `String "v");
                   ("url", `String "http://v");
                   ("token", `String "${env:ADMIN_TOKEN}");
                 ];
             ] );
         ("integrations", integrations);
       ])

let env = function
  | "ADMIN_TOKEN" -> Some "admin-secret"
  | "SLACK" -> Some "https://hooks.slack.test/abc"
  | _ -> None

let webhook (j : Yojson.Safe.t) =
  match j with
  | `Assoc l -> (
      match List.assoc_opt "slack" l with
      | Some (`Assoc s) -> (
          match List.assoc_opt "webhook" s with Some (`String w) -> w | _ -> "?")
      | _ -> "?")
  | _ -> "?"

let secrets_tests =
  [
    ( "integrations stay unresolved; resolve expands",
      `Quick,
      fun () ->
        let file =
          write_config
            (doc
               ~integrations:
                 (`Assoc [ ("slack", `Assoc [ ("webhook", `String "${env:SLACK}") ]) ]))
        in
        match Lwt_main.run (Cfg.load ~env file) with
        | Error m -> Alcotest.failf "load: %s" m
        | Ok c ->
            Alcotest.(check (option string))
              "typed field resolved" (Some "admin-secret") (List.hd c.verifiers).v_token;
            Alcotest.(check string) "unresolved" "${env:SLACK}" (webhook c.integrations);
            let raw = Yojson.Safe.to_string c.raw in
            Alcotest.(check bool) "raw unresolved" true (contains raw "${env:SLACK}");
            Alcotest.(check bool)
              "raw keeps typed placeholder" true
              (contains raw "${env:ADMIN_TOKEN}");
            Alcotest.(check bool) "raw has no secret" false (contains raw "admin-secret");
            Alcotest.(check (result string string))
              "resolve" (Ok "https://hooks.slack.test/abc")
              (Lwt_main.run (Cfg.resolve c "${env:SLACK}"));
            Alcotest.(check (result string string))
              "resolve with text" (Ok "url=https://hooks.slack.test/abc; ${x}")
              (Lwt_main.run (Cfg.resolve c "url=${env:SLACK}; $${x}"));
            Alcotest.(check bool)
              "unset env" true
              (Result.is_error (Lwt_main.run (Cfg.resolve c "${env:NOPE}"))) );
    ( "lazy placeholders are validated at load",
      `Quick,
      fun () ->
        let bad integrations =
          let file = write_config (doc ~integrations) in
          Result.is_error (Lwt_main.run (Cfg.load ~env file))
        in
        Alcotest.(check bool)
          "unset env" true
          (bad (`Assoc [ ("x", `String "${env:NOPE}") ]));
        Alcotest.(check bool)
          "unconfigured vault" true
          (bad (`Assoc [ ("x", `String "${vault:secret/x#y}") ]));
        Alcotest.(check bool) "no scheme" true (bad (`Assoc [ ("x", `String "${oops}") ]));
        Alcotest.(check bool)
          "unknown scheme" true
          (bad (`Assoc [ ("x", `String "${file:/etc/passwd}") ])) );
  ]

let () =
  Alcotest.run "console-auth"
    [
      ("dev", dev_tests);
      ("proxy", proxy_tests);
      ("session", session_tests);
      ("secrets", secrets_tests);
    ]
