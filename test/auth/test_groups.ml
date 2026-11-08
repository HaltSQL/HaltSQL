(* policy_from_groups: pure claim handling (Okta, Keycloak, Auth0, Azure AD /
   Entra ID token shapes), first-match semantics, defaults, overage, and the
   Oidc.verify hook with tokens signed in-test. No network. *)

open Haltsql_auth
module Config = Haltsql.Config

let () = Mirage_crypto_rng_unix.use_default ()

let gp ?(claim = "groups") ?default rules : Config.groups_policy =
  {
    groups_claim = claim;
    group_rules =
      List.map (fun (group, group_policy) -> { Config.group; group_policy }) rules;
    group_default = default;
  }

let rules =
  [ ("admins", "p-admin"); ("support", "p-support"); ("analysts", "p-analytics") ]

let claims j = match Yojson.Safe.from_string j with `Assoc kv -> kv | _ -> assert false

let err_t =
  Alcotest.testable (fun f e -> Format.pp_print_string f (Jwt.error_to_string e)) ( = )

let res = Alcotest.(result string err_t)
let resolve ?claim ?default j = Group_policy.resolve (gp ?claim ?default rules) (claims j)

(* ---- IdP token shapes ---- *)

let okta () =
  (* Okta: a "groups" claim added by a groups claim filter, array of names *)
  Alcotest.check res "okta" (Ok "p-analytics")
    (resolve {|{"sub": "00u1", "groups": ["Everyone", "analysts"]}|});
  Alcotest.check res "okta custom claim name" (Ok "p-support")
    (resolve ~claim:"okta_groups" {|{"okta_groups": ["support"]}|})

let keycloak () =
  (* Keycloak group membership mapper with full.path=false, and realm roles *)
  Alcotest.check res "keycloak groups" (Ok "p-support")
    (resolve {|{"groups": ["support"], "realm_access": {"roles": ["offline_access"]}}|});
  Alcotest.check res "keycloak full path does not match a bare name"
    (Error (Jwt.No_group_policy "groups"))
    (resolve {|{"groups": ["/support"]}|});
  Alcotest.check res "keycloak realm roles by dot path" (Ok "p-admin")
    (resolve ~claim:"realm_access.roles"
       {|{"realm_access": {"roles": ["default-roles-corp", "admins"]}}|});
  Alcotest.check res "keycloak client roles by dot path" (Ok "p-analytics")
    (resolve ~claim:"resource_access.haltsql.roles"
       {|{"resource_access": {"haltsql": {"roles": ["analysts"]}}}|})

let auth0 () =
  (* Auth0: namespaced custom claim set by an Action; the name contains dots and
     slashes and is matched as one claim name first *)
  Alcotest.check res "auth0 namespaced" (Ok "p-admin")
    (resolve ~claim:"https://corp.example.com/groups"
       {|{"https://corp.example.com/groups": ["admins"], "permissions": []}|})

let azure_overage () =
  let overage = Error (Jwt.Groups_overage "groups") in
  Alcotest.check res "_claim_names/_claim_sources" overage
    (resolve
       {|{"oid": "x", "_claim_names": {"groups": "src1"},
          "_claim_sources": {"src1": {"endpoint": "https://graph.windows.net/t/users/x/getMemberObjects"}}}|});
  Alcotest.check res "overage even when a (partial) groups claim is present" overage
    (resolve
       {|{"groups": ["admins"], "_claim_names": {"groups": "src1"}, "_claim_sources": {}}|});
  Alcotest.check res "hasgroups (implicit flow)" overage (resolve {|{"hasgroups": true}|});
  Alcotest.check res "malformed _claim_names fails closed" overage
    (resolve {|{"groups": ["admins"], "_claim_names": "groups"}|});
  Alcotest.check res "_claim_names for another claim is not overage" (Ok "p-admin")
    (resolve {|{"groups": ["admins"], "_claim_names": {"roles": "src1"}}|});
  Alcotest.check res "overage for the first segment of a dot path"
    (Error (Jwt.Groups_overage "groups.ids"))
    (resolve ~claim:"groups.ids" {|{"_claim_names": {"groups": "src1"}}|});
  Alcotest.check res "hasgroups ignored for a roles claim" (Ok "p-support")
    (resolve ~claim:"roles" {|{"roles": ["support"], "hasgroups": true}|});
  (* Entra ID group object ids work when emitted in the token *)
  let g = gp [ ("8b0e5a9c-1c1f-4c55-9d2a-5f1f3c0f2a11", "p-admin") ] in
  Alcotest.check res "entra object id" (Ok "p-admin")
    (Group_policy.resolve g
       (claims {|{"groups": ["8b0e5a9c-1c1f-4c55-9d2a-5f1f3c0f2a11"]}|}));
  let msg = Jwt.error_to_string (Jwt.Groups_overage "groups") in
  Alcotest.(check bool)
    "message names overage" true
    (String.length msg > 0
    &&
    let sub = "overage" in
    let n = String.length sub in
    let rec go i =
      i + n <= String.length msg && (String.sub msg i n = sub || go (i + 1))
    in
    go 0);
  Alcotest.(check string)
    "code" "groups_overage"
    (Jwt.error_code (Jwt.Groups_overage "groups"))

(* ---- shapes ---- *)

let shapes () =
  Alcotest.check res "string is one group" (Ok "p-support")
    (resolve {|{"groups": "support"}|});
  Alcotest.check res "string is never split on spaces"
    (Error (Jwt.No_group_policy "groups"))
    (resolve {|{"groups": "support analysts"}|});
  Alcotest.check res "missing" (Error (Jwt.Missing_claim "groups"))
    (resolve {|{"sub": "x"}|});
  List.iter
    (fun j -> Alcotest.check res j (Error (Jwt.Bad_claim "groups")) (resolve j))
    [
      {|{"groups": 7}|};
      {|{"groups": {"admins": true}}|};
      {|{"groups": ["admins", 1]}|};
      {|{"groups": null}|};
      {|{"groups": true}|};
      {|{"groups": [["admins"]]}|};
    ];
  Alcotest.check res "empty array: no match" (Error (Jwt.No_group_policy "groups"))
    (resolve {|{"groups": []}|});
  Alcotest.check res "empty array with default" (Ok "p-default")
    (resolve ~default:"p-default" {|{"groups": []}|});
  Alcotest.check res "case-sensitive" (Error (Jwt.No_group_policy "groups"))
    (resolve {|{"groups": ["Admins"]}|})

(* ---- selection ---- *)

let first_match () =
  (* config order wins, not token order *)
  Alcotest.check res "support before analysts" (Ok "p-support")
    (resolve {|{"groups": ["analysts", "support"]}|});
  Alcotest.check res "admins first" (Ok "p-admin")
    (resolve {|{"groups": ["analysts", "support", "admins"]}|});
  (match
     Group_policy.select (gp rules) (claims {|{"groups": ["x", "analysts", "support"]}|})
   with
  | Ok s ->
      Alcotest.(check string) "policy" "p-support" s.policy;
      Alcotest.(check (option string)) "matched" (Some "support") s.matched_group;
      Alcotest.(check (list string)) "groups" [ "x"; "analysts"; "support" ] s.groups
  | Error e -> Alcotest.fail (Jwt.error_to_string e));
  (* the same answer as the config contract's selector *)
  List.iter
    (fun gs ->
      let g = gp ~default:"d" rules in
      let j = `Assoc [ ("groups", `List (List.map (fun s -> `String s) gs)) ] in
      let kv = match j with `Assoc kv -> kv | _ -> [] in
      Alcotest.(check (option string))
        (String.concat "," gs)
        (Config.select_group_policy g gs)
        (Result.to_option (Group_policy.resolve g kv)))
    [
      []; [ "analysts" ]; [ "support"; "admins" ]; [ "nobody" ]; [ "analysts"; "nobody" ];
    ]

let default_and_unknown () =
  (match
     Group_policy.select
       (gp ~default:"p-default" rules)
       (claims {|{"groups": ["marketing"]}|})
   with
  | Ok s ->
      Alcotest.(check string) "default" "p-default" s.policy;
      Alcotest.(check (option string)) "no matched group" None s.matched_group
  | Error e -> Alcotest.fail (Jwt.error_to_string e));
  let e = Jwt.No_group_policy "groups" in
  Alcotest.check res "unknown group, no default" (Error e)
    (resolve {|{"groups": ["marketing"]}|});
  Alcotest.(check string) "code" "no_group_policy" (Jwt.error_code e);
  Alcotest.(check bool)
    "message does not echo groups" false
    (let m = Jwt.error_to_string e in
     let sub = "marketing" in
     let n = String.length sub in
     let rec go i = i + n <= String.length m && (String.sub m i n = sub || go (i + 1)) in
     go 0)

(* ---- the Oidc.verify hook ---- *)

let rsa_priv = Mirage_crypto_pk.Rsa.generate ~bits:2048 ()

let keys =
  [
    {
      Jwk.kid = Some "k1";
      alg = None;
      use = Some "sig";
      key = Jwk.Rsa (Mirage_crypto_pk.Rsa.pub_of_priv rsa_priv);
    };
  ]

let issuer = "https://idp.example.com"
let now = 1_800_000_000.

let provider : Config.oidc_provider =
  {
    oidc_name = "corp";
    issuer;
    audiences = [ "haltsql" ];
    jwks_uri = Some "https://idp.example.com/jwks";
    algorithms = [ Config.RS256 ];
    leeway_seconds = 60;
    jwks_cache_seconds = 300;
    (* the placeholder Config puts on a policy_from_groups provider *)
    oidc_policy = Config.Oidc_from_claim { claim = "groups"; allowed = [] };
    context_claims = [ ("tenant_id", "tenant") ];
    required_claims = [];
    oidc_request_context_fields = [];
    allow_insecure_http = false;
  }

let token extra =
  Jwt.sign ~alg:"RS256" ~kid:"k1" (Jwt.Sign_rsa rsa_priv)
    (`Assoc
       ([
          ("iss", `String issuer);
          ("aud", `String "haltsql");
          ("sub", `String "user-1");
          ("exp", `Int (int_of_float now + 600));
          ("tenant", `String "acme");
        ]
       @ extra))

let verify_hook () =
  let g = gp rules in
  let tok = token [ ("groups", `List [ `String "analysts"; `String "support" ]) ] in
  (match Oidc.verify ~groups:g provider ~keys ~now tok with
  | Ok id ->
      Alcotest.(check string) "policy" "p-support" id.policy;
      Alcotest.(check (option string)) "matched" (Some "support") id.matched_group;
      Alcotest.(check bool)
        "context still derived" true
        (id.context = [ ("tenant_id", Haltsql.Context.One "acme") ])
  | Error e -> Alcotest.fail (Jwt.error_to_string e));
  (* without the hook the placeholder rejects every token (fail closed) *)
  (match Oidc.verify provider ~keys ~now tok with
  | Error (Jwt.Policy_not_allowed _) -> ()
  | Ok _ -> Alcotest.fail "placeholder must not accept tokens"
  | Error e -> Alcotest.failf "unexpected %s" (Jwt.error_to_string e));
  let rej what extra want =
    match Oidc.verify ~groups:g provider ~keys ~now (token extra) with
    | Error e when e = want -> ()
    | Error e -> Alcotest.failf "%s: got %s" what (Jwt.error_to_string e)
    | Ok _ -> Alcotest.failf "%s: accepted" what
  in
  rej "unknown group"
    [ ("groups", `List [ `String "marketing" ]) ]
    (Jwt.No_group_policy "groups");
  rej "missing" [] (Jwt.Missing_claim "groups");
  rej "overage"
    [
      ("_claim_names", `Assoc [ ("groups", `String "src1") ]);
      ("_claim_sources", `Assoc []);
    ]
    (Jwt.Groups_overage "groups");
  (* signature checks still come first *)
  let forged =
    Jwt.sign ~alg:"RS256" ~kid:"k1"
      (Jwt.Sign_rsa (Mirage_crypto_pk.Rsa.generate ~bits:2048 ()))
      (`Assoc [ ("iss", `String issuer); ("groups", `List [ `String "admins" ]) ])
  in
  match Oidc.verify ~groups:g provider ~keys ~now forged with
  | Error Jwt.Bad_signature -> ()
  | _ -> Alcotest.fail "forged token must fail on the signature"

let () =
  let tc n f = Alcotest.test_case n `Quick f in
  Alcotest.run "haltsql.auth groups"
    [
      ( "idp shapes",
        [
          tc "okta" okta;
          tc "keycloak" keycloak;
          tc "auth0" auth0;
          tc "azure ad / entra overage" azure_overage;
        ] );
      ("claims", [ tc "shapes" shapes ]);
      ( "selection",
        [ tc "first match" first_match; tc "default and unknown" default_and_unknown ] );
      ("oidc", [ tc "verify hook" verify_hook ]);
    ]
