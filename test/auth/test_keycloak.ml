(* policy_from_groups against a REAL identity provider: Keycloak
   (quay.io/keycloak/keycloak, dev mode) on 127.0.0.1:18190.

   Setup, through Keycloak's admin REST API: a realm, a confidential client
   with a group-membership mapper and an audience mapper, groups, a realm role,
   users in various groups, and the client's service account in a group.
   Real tokens come from the password and client-credentials grants. HaltSQL
   loads the server configuration with Config.of_json, discovers the issuer
   and fetches its JWKS over HTTP with Oidc_client, verifies the tokens and
   maps their groups to policies.

   Skips, with a message, when Docker is unavailable. *)

open Haltsql_auth
module Config = Haltsql.Config
module Http = Haltsql_cloud.Http

let image = "quay.io/keycloak/keycloak:26.4.2"
let container = "haltsql-identity-keycloak"
let port = 18190
let base = Printf.sprintf "http://127.0.0.1:%d" port
let realm = "haltsql"
let issuer = Printf.sprintf "%s/realms/%s" base realm
let client_id = "haltsql-agent"
let run = Lwt_main.run

let random_hex n =
  String.concat "" (List.init n (fun _ -> Printf.sprintf "%02x" (Random.int 256)))

let fail_resp what (r : Http.response) =
  Alcotest.failf "%s: HTTP %d %s" what r.status
    (if String.length r.body > 300 then String.sub r.body 0 300 else r.body)

let request ?token ?(headers = []) ?body ?(form = false) meth path =
  let headers =
    headers
    @ (match token with Some t -> [ ("authorization", "Bearer " ^ t) ] | None -> [])
    @
    match body with
    | Some _ when form -> [ ("content-type", "application/x-www-form-urlencoded") ]
    | Some _ -> [ ("content-type", "application/json") ]
    | None -> []
  in
  match
    run (Http.request ~timeout:30. ~headers ?body meth (Uri.of_string (base ^ path)))
  with
  | Ok r -> r
  | Error e -> Alcotest.failf "%s %s: %s" (Cohttp.Code.string_of_method meth) path e

let json_body (r : Http.response) = Yojson.Safe.from_string r.body

let member k = function
  | `Assoc kv -> Option.value (List.assoc_opt k kv) ~default:`Null
  | _ -> `Null

let str = function
  | `String s -> s
  | j -> Alcotest.failf "not a string: %s" (Yojson.Safe.to_string j)

(* ---- Keycloak admin API ---- *)

let token_request path fields =
  let r = request ~form:true ~body:(Http.form_encode fields) `POST path in
  if r.status <> 200 then fail_resp ("token " ^ path) r;
  str (member "access_token" (json_body r))

let admin_token admin_password =
  token_request "/realms/master/protocol/openid-connect/token"
    [
      ("grant_type", "password");
      ("client_id", "admin-cli");
      ("username", "admin");
      ("password", admin_password);
    ]

let post_created ~token path doc =
  let r = request ~token ~body:(Yojson.Safe.to_string doc) `POST path in
  if r.status <> 201 then fail_resp ("POST " ^ path) r;
  match Http.header r "location" with
  | Some loc -> List.hd (List.rev (String.split_on_char '/' loc))
  | None -> Alcotest.failf "POST %s: no Location" path

let put_no_content ~token path =
  let r = request ~token `PUT path in
  if r.status <> 204 then fail_resp ("PUT " ^ path) r

let admin = Printf.sprintf "/admin/realms/%s" realm

type env = { client_secret : string; passwords : (string * string) list }

let setup_realm admin_password =
  let token = admin_token admin_password in
  ignore
    (post_created ~token "/admin/realms"
       (`Assoc [ ("realm", `String realm); ("enabled", `Bool true) ]));
  let group name =
    (name, post_created ~token (admin ^ "/groups") (`Assoc [ ("name", `String name) ]))
  in
  let groups = List.map group [ "admins"; "support"; "analysts"; "marketing" ] in
  ignore
    ( post_created ~token (admin ^ "/roles") (`Assoc [ ("name", `String "sql-reader") ])
    |> fun _ -> () );
  let client_secret = random_hex 24 in
  let client_uuid =
    post_created ~token (admin ^ "/clients")
      (`Assoc
         [
           ("clientId", `String client_id);
           ("enabled", `Bool true);
           ("publicClient", `Bool false);
           ("secret", `String client_secret);
           ("standardFlowEnabled", `Bool false);
           ("directAccessGrantsEnabled", `Bool true);
           ("serviceAccountsEnabled", `Bool true);
           ( "protocolMappers",
             `List
               [
                 `Assoc
                   [
                     ("name", `String "groups");
                     ("protocol", `String "openid-connect");
                     ("protocolMapper", `String "oidc-group-membership-mapper");
                     ( "config",
                       `Assoc
                         [
                           ("claim.name", `String "groups");
                           ("full.path", `String "false");
                           ("access.token.claim", `String "true");
                           ("id.token.claim", `String "false");
                           ("userinfo.token.claim", `String "false");
                         ] );
                   ];
                 `Assoc
                   [
                     ("name", `String "haltsql-audience");
                     ("protocol", `String "openid-connect");
                     ("protocolMapper", `String "oidc-audience-mapper");
                     ( "config",
                       `Assoc
                         [
                           ("included.custom.audience", `String "haltsql");
                           ("access.token.claim", `String "true");
                           ("id.token.claim", `String "false");
                         ] );
                   ];
               ] );
         ])
  in
  let role =
    let r = request ~token `GET (admin ^ "/roles/sql-reader") in
    if r.status <> 200 then fail_resp "GET role" r;
    json_body r
  in
  let user name member_of =
    let password = random_hex 12 in
    let id =
      post_created ~token (admin ^ "/users")
        (`Assoc
           [
             ("username", `String name);
             ("enabled", `Bool true);
             ("email", `String (name ^ "@example.test"));
             ("emailVerified", `Bool true);
             ("firstName", `String name);
             ("lastName", `String "Test");
             ( "credentials",
               `List
                 [
                   `Assoc
                     [
                       ("type", `String "password");
                       ("value", `String password);
                       ("temporary", `Bool false);
                     ];
                 ] );
           ])
    in
    List.iter
      (fun g ->
        put_no_content ~token
          (Printf.sprintf "%s/users/%s/groups/%s" admin id (List.assoc g groups)))
      member_of;
    (name, id, password)
  in
  let users =
    [
      user "alice" [ "analysts" ];
      user "bob" [ "analysts"; "support" ];
      user "carol" [ "marketing" ];
      user "dave" [];
      user "erin" [ "admins"; "marketing" ];
    ]
  in
  (* alice also gets the realm role, for the realm_access.roles mapping *)
  let _, alice_id, _ = List.hd users in
  let r =
    request ~token
      ~body:(Yojson.Safe.to_string (`List [ role ]))
      `POST
      (Printf.sprintf "%s/users/%s/role-mappings/realm" admin alice_id)
  in
  if r.status <> 204 then fail_resp "role mapping" r;
  (* the client's service account (client-credentials grant) is in "support" *)
  let r =
    request ~token `GET
      (Printf.sprintf "%s/clients/%s/service-account-user" admin client_uuid)
  in
  if r.status <> 200 then fail_resp "service-account-user" r;
  let sa_id = str (member "id" (json_body r)) in
  put_no_content ~token
    (Printf.sprintf "%s/users/%s/groups/%s" admin sa_id (List.assoc "support" groups));
  { client_secret; passwords = List.map (fun (n, _, p) -> (n, p)) users }

let wait_ready () =
  let deadline = Unix.gettimeofday () +. 180. in
  let rec loop () =
    match
      run
        (Http.request ~timeout:3. `GET
           (Uri.of_string (issuer |> fun _ -> base ^ "/realms/master")))
    with
    | Ok { status = 200; _ } -> Ok ()
    | _ when Unix.gettimeofday () > deadline ->
        Error ("keycloak did not start:\n" ^ Docker_util.logs container)
    | _ ->
        Unix.sleepf 1.;
        loop ()
  in
  loop ()

let setup () =
  match Docker_util.available () with
  | Error e -> Error e
  | Ok () -> (
      match Docker_util.ensure_image image with
      | Error e -> Error e
      | Ok () -> (
          Random.self_init ();
          let admin_password = random_hex 16 in
          match
            Docker_util.start ~name:container
              [
                "-p";
                Printf.sprintf "127.0.0.1:%d:8080" port;
                "-e";
                "KC_BOOTSTRAP_ADMIN_USERNAME=admin";
                "-e";
                "KC_BOOTSTRAP_ADMIN_PASSWORD=" ^ admin_password;
                image;
                "start-dev";
                "--http-port=8080";
              ]
          with
          | Error e -> Error e
          | Ok () -> (
              match wait_ready () with
              | Error e -> Alcotest.fail e
              | Ok () -> Ok (setup_realm admin_password))))

let env = lazy (setup ())

let with_env f () =
  match Lazy.force env with
  | Ok e -> f e
  | Error msg ->
      Printf.eprintf "SKIP (Keycloak integration): %s\n%!" msg;
      Alcotest.skip ()

(* ---- tokens ---- *)

let token_endpoint = Printf.sprintf "/realms/%s/protocol/openid-connect/token" realm

let password_token e user =
  token_request token_endpoint
    [
      ("grant_type", "password");
      ("client_id", client_id);
      ("client_secret", e.client_secret);
      ("username", user);
      ("password", List.assoc user e.passwords);
      ("scope", "openid");
    ]

let client_token e =
  token_request token_endpoint
    [
      ("grant_type", "client_credentials");
      ("client_id", client_id);
      ("client_secret", e.client_secret);
    ]

(* ---- HaltSQL configuration (through the real config loader) ---- *)

let config_doc ?(claim = "groups") ?default () =
  let inline name =
    `Assoc
      [
        ( "inline",
          `Assoc
            [
              ("metadata", `Assoc [ ("name", `String name) ]);
              ("search_path", `List [ `String "app" ]);
              ( "tables",
                `Assoc [ ("app.orders", `Assoc [ ("columns", `List [ `String "id" ]) ]) ]
              );
            ] );
      ]
  in
  `Assoc
    [
      ("apiVersion", `String "haltsql.dev/v1");
      ("kind", `String "Config");
      ( "server",
        `Assoc
          [
            ( "auth",
              `Assoc
                [
                  ( "oidc",
                    `List
                      [
                        `Assoc
                          [
                            ("name", `String "keycloak");
                            ("issuer", `String issuer);
                            ("audiences", `List [ `String "haltsql" ]);
                            ("allow_insecure_http", `Bool true);
                            ( "policy_from_groups",
                              `Assoc
                                ([
                                   ("claim", `String claim);
                                   ( "map",
                                     `List
                                       (List.map
                                          (fun (g, p) ->
                                            `Assoc
                                              [
                                                ("group", `String g); ("policy", `String p);
                                              ])
                                          [
                                            ("admins", "p-admin");
                                            ("support", "p-support");
                                            ("analysts", "p-analytics");
                                            ("sql-reader", "p-reader");
                                          ]) );
                                 ]
                                @
                                match default with
                                | Some d -> [ ("default", `String d) ]
                                | None -> []) );
                          ];
                      ] );
                ] );
          ] );
      ( "policies",
        `List
          (List.map inline
             [ "p-admin"; "p-support"; "p-analytics"; "p-reader"; "p-default" ]) );
    ]

let load ?claim ?default () =
  match Config.of_json (config_doc ?claim ?default ()) with
  | Ok c -> c
  | Error errs ->
      Alcotest.failf "config: %s"
        (String.concat "; " (List.map Haltsql.Load_error.to_string errs))

let registry ?(with_groups = true) (c : Config.t) =
  if with_groups then Oidc_client.registry ~group_policies:c.oidc_group_policies c.oidc
  else Oidc_client.registry c.oidc

let authenticate reg tok = run (Oidc_client.authenticate reg tok)

let expect_policy what ?group reg tok policy =
  match authenticate reg tok with
  | `Verified (id : Oidc.identity) ->
      Alcotest.(check string) (what ^ ": policy") policy id.policy;
      Alcotest.(check string) (what ^ ": provider") "keycloak" id.provider;
      Option.iter
        (fun g ->
          Alcotest.(check (option string))
            (what ^ ": matched group") (Some g) id.matched_group)
        group
  | `Rejected e -> Alcotest.failf "%s: rejected: %s" what (Jwt.error_to_string e)
  | `Not_applicable -> Alcotest.failf "%s: not applicable" what

let expect_rejected what reg tok ok =
  match authenticate reg tok with
  | `Rejected e when ok e -> ()
  | `Rejected e ->
      Alcotest.failf "%s: unexpected rejection %s" what (Jwt.error_to_string e)
  | `Verified (id : Oidc.identity) ->
      Alcotest.failf "%s: accepted with policy %s" what id.policy
  | `Not_applicable -> Alcotest.failf "%s: not applicable" what

(* ---- tests ---- *)

let groups_to_policies e =
  let c = load () in
  Alcotest.(check int) "one group mapping" 1 (List.length c.oidc_group_policies);
  let reg = registry c in
  expect_policy "alice (analysts)" ~group:"analysts" reg (password_token e "alice")
    "p-analytics";
  expect_policy "bob (analysts + support): first rule wins" ~group:"support" reg
    (password_token e "bob") "p-support";
  expect_policy "erin (admins + marketing)" ~group:"admins" reg (password_token e "erin")
    "p-admin";
  expect_policy "service account (client credentials)" ~group:"support" reg
    (client_token e) "p-support"

let unmapped_denied e =
  let reg = registry (load ()) in
  expect_rejected "carol (marketing only)" reg (password_token e "carol") (function
    | Jwt.No_group_policy "groups" -> true
    | _ -> false);
  (* Keycloak omits the claim for a user in no group *)
  expect_rejected "dave (no group)" reg (password_token e "dave") (function
    | Jwt.Missing_claim "groups" | Jwt.No_group_policy "groups" -> true
    | _ -> false)

let default_policy e =
  let reg = registry (load ~default:"p-default" ()) in
  (match authenticate reg (password_token e "carol") with
  | `Verified id ->
      Alcotest.(check string) "carol gets the default" "p-default" id.policy;
      Alcotest.(check (option string)) "no matched group" None id.matched_group
  | `Rejected err -> Alcotest.failf "carol rejected: %s" (Jwt.error_to_string err)
  | `Not_applicable -> Alcotest.fail "not applicable");
  expect_policy "alice still mapped" reg (password_token e "alice") "p-analytics"

let realm_roles e =
  (* a dot-path claim: Keycloak's realm_access.roles *)
  let reg = registry (load ~claim:"realm_access.roles" ()) in
  expect_policy "alice via realm role" ~group:"sql-reader" reg (password_token e "alice")
    "p-reader";
  expect_rejected "bob has no mapped role" reg (password_token e "bob") (function
    | Jwt.No_group_policy "realm_access.roles" -> true
    | _ -> false)

let fail_closed_without_hook e =
  (* a server that ignores oidc_group_policies rejects every token *)
  let reg = registry ~with_groups:false (load ()) in
  expect_rejected "placeholder policy" reg (password_token e "alice") (function
    | Jwt.Policy_not_allowed _ | Jwt.Missing_claim _ -> true
    | _ -> false);
  (* hot reload: update with the mappings restores group selection, keeping keys *)
  let c = load () in
  let reg = Oidc_client.update ~group_policies:c.oidc_group_policies reg c.oidc in
  expect_policy "after update" reg (password_token e "alice") "p-analytics"

let tampered e =
  let reg = registry (load ()) in
  let tok = password_token e "carol" in
  (* swap carol's payload for one claiming "admins", keeping Keycloak's signature *)
  match String.split_on_char '.' tok with
  | [ h; p; s ] ->
      let payload =
        Yojson.Safe.from_string (Option.get (B64url.decode p |> Result.to_option))
      in
      let payload =
        match payload with
        | `Assoc kv ->
            `Assoc
              (("groups", `List [ `String "admins" ]) :: List.remove_assoc "groups" kv)
        | j -> j
      in
      let forged =
        String.concat "." [ h; B64url.encode (Yojson.Safe.to_string payload); s ]
      in
      expect_rejected "forged groups" reg forged (function
        | Jwt.Bad_signature -> true
        | _ -> false)
  | _ -> Alcotest.fail "not a JWT"

(* The real haltsql-server binary with the same provider: caller resolution
   selects the policy from the token's groups (HALTSQL_SERVER_BIN, set by dune). *)
let server_port = 18191

let real_server e =
  match Sys.getenv_opt "HALTSQL_SERVER_BIN" with
  | None -> Alcotest.fail "HALTSQL_SERVER_BIN is not set"
  | Some bin ->
      let dir = Filename.temp_dir "haltsql-kc-server" "" in
      let cfg = Filename.concat dir "config.json" in
      let doc =
        match config_doc () with
        | `Assoc kv ->
            let server =
              match List.assoc "server" kv with
              | `Assoc s ->
                  `Assoc
                    (("listen", `String (Printf.sprintf "127.0.0.1:%d" server_port)) :: s)
              | j -> j
            in
            `Assoc
              (("server", server)
              :: ("audit", `Assoc [ ("sinks", `List [ `Assoc [ ("type", `String "file"); ("path", `String (Filename.concat dir "audit.jsonl")) ] ]) ])
              :: List.remove_assoc "server" kv)
        | j -> j
      in
      Out_channel.with_open_bin cfg (fun oc -> output_string oc (Yojson.Safe.to_string doc));
      let log = Unix.openfile (Filename.concat dir "server.log") [ O_WRONLY; O_CREAT; O_TRUNC ] 0o600 in
      let pid =
        Unix.create_process bin [| bin; "--config"; cfg |] Unix.stdin log log
      in
      Unix.close log;
      let finally () =
        (try Unix.kill pid Sys.sigterm with _ -> ());
        let rec reap () =
          match Unix.waitpid [] pid with
          | _ -> ()
          | exception Unix.Unix_error (Unix.EINTR, _, _) -> reap ()
        in
        reap ()
      in
      Fun.protect ~finally (fun () ->
          let base = Printf.sprintf "http://127.0.0.1:%d" server_port in
          let deadline = Unix.gettimeofday () +. 30. in
          let rec wait () =
            match run (Http.request ~timeout:2. `GET (Uri.of_string (base ^ "/healthz"))) with
            | Ok { status = 200; _ } -> ()
            | _ when Unix.gettimeofday () > deadline ->
                Alcotest.failf "server did not start: %s"
                  (In_channel.with_open_bin (Filename.concat dir "server.log") In_channel.input_all)
            | _ ->
                Unix.sleepf 0.2;
                wait ()
          in
          wait ();
          let verify tok =
            match
              run
                (Http.request ~timeout:30.
                   ~headers:
                     [ ("authorization", "Bearer " ^ tok); ("content-type", "application/json") ]
                   ~body:{|{"sql":"SELECT id FROM orders LIMIT 1"}|} `POST
                   (Uri.of_string (base ^ "/v1/verify")))
            with
            | Ok r -> r
            | Error err -> Alcotest.failf "verify: %s" err
          in
          let r = verify (password_token e "alice") in
          Alcotest.(check int) "alice: 200" 200 r.status;
          Alcotest.(check string) "alice: policy from group analysts" "p-analytics"
            (str (member "name" (member "policy" (json_body r))));
          let r = verify (password_token e "bob") in
          Alcotest.(check string) "bob: first rule (support)" "p-support"
            (str (member "name" (member "policy" (json_body r))));
          let r = verify (password_token e "carol") in
          Alcotest.(check int) "carol (no mapped group): 401" 401 r.status)

let () =
  Mirage_crypto_rng_unix.use_default ();
  let it n f = Alcotest.test_case n `Slow (with_env f) in
  Alcotest.run "haltsql.auth keycloak"
    [
      ( "keycloak (docker)",
        [
          it "groups map to policies" groups_to_policies;
          it "user in no mapped group is denied" unmapped_denied;
          it "default policy" default_policy;
          it "realm roles by dot path" realm_roles;
          it "fail closed without the hook; update" fail_closed_without_hook;
          it "forged groups claim" tampered;
          it "real haltsql-server selects the policy from groups" real_server;
        ] );
    ]
