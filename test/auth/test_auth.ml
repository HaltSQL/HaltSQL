(* Tests for haltsql.auth: pure JWT/OIDC verification tables (keys generated
   in-test), the JWKS cache logic with a fake fetcher and clock, mTLS identity
   mapping and request-context merging. No network. *)

open Haltsql_auth
module Config = Haltsql.Config
module Context = Haltsql.Context

let () = Mirage_crypto_rng_unix.use_default ()

(* ---- keys ---- *)

let rsa_priv = Mirage_crypto_pk.Rsa.generate ~bits:2048 ()
let rsa_pub = Mirage_crypto_pk.Rsa.pub_of_priv rsa_priv
let rsa2_priv = Mirage_crypto_pk.Rsa.generate ~bits:2048 ()
let rsa2_pub = Mirage_crypto_pk.Rsa.pub_of_priv rsa2_priv
let p256_priv, p256_pub = Mirage_crypto_ec.P256.Dsa.generate ()
let p384_priv, p384_pub = Mirage_crypto_ec.P384.Dsa.generate ()
let ed_priv, ed_pub = Mirage_crypto_ec.Ed25519.generate ()
let jwk ?alg ?(use = Some "sig") kid key = { Jwk.kid = Some kid; alg; use; key }

let keys =
  [
    jwk "rsa1" (Jwk.Rsa rsa_pub);
    jwk "ec1" (Jwk.P256 p256_pub);
    jwk "ec384" (Jwk.P384 p384_pub);
    jwk "ed1" (Jwk.Ed25519 ed_pub);
  ]

let issuer = "https://idp.example.com"
let now = 1_800_000_000.

let provider ?(algorithms = Config.[ RS256; RS384; PS256; ES256; ES384; EdDSA ])
    ?(policy = Config.Oidc_pinned "shop") ?(required = []) ?(context_claims = [])
    ?(leeway = 60) () : Config.oidc_provider =
  {
    oidc_name = "corp";
    issuer;
    audiences = [ "haltsql"; "haltsql-alt" ];
    jwks_uri = Some "https://idp.example.com/jwks";
    algorithms;
    leeway_seconds = leeway;
    jwks_cache_seconds = 300;
    oidc_policy = policy;
    context_claims;
    required_claims = required;
    oidc_request_context_fields = [ "user_id" ];
    allow_insecure_http = false;
  }

let base_claims ?(exp = now +. 600.) () =
  [
    ("iss", `String issuer);
    ("aud", `String "haltsql");
    ("sub", `String "user-17");
    ("exp", `Int (int_of_float exp));
    ("iat", `Int (int_of_float now - 10));
  ]

let claims ?exp ?(drop = []) extra =
  `Assoc
    (List.filter
       (fun (k, _) -> not (List.mem k drop || List.mem_assoc k extra))
       (base_claims ?exp ())
    @ extra)

let sign ?(alg = "RS256") ?(kid = Some "rsa1") ?extra_header key c =
  Jwt.sign ~alg ?kid ?extra_header key c

let rs ?alg ?kid ?extra_header c = sign ?alg ?kid ?extra_header (Jwt.Sign_rsa rsa_priv) c
let verify ?(p = provider ()) ?(at = now) tok = Oidc.verify p ~keys ~now:at tok

let err =
  Alcotest.testable
    (fun ppf e -> Format.pp_print_string ppf (Jwt.error_to_string e))
    ( = )

let check_err msg expected r =
  match r with
  | Ok _ -> Alcotest.failf "%s: expected %s, got Ok" msg (Jwt.error_to_string expected)
  | Error e -> Alcotest.check err msg expected e

let check_ok msg r =
  match r with
  | Ok (id : Oidc.identity) -> id
  | Error e -> Alcotest.failf "%s: expected Ok, got %s" msg (Jwt.error_to_string e)

(* ---- b64url ---- *)

let b64url () =
  for n = 0 to 40 do
    let s = String.init n (fun i -> Char.chr (((i * 37) + n) land 255)) in
    match B64url.decode (B64url.encode s) with
    | Ok s' -> Alcotest.(check string) (Printf.sprintf "roundtrip %d" n) s s'
    | Error e -> Alcotest.failf "roundtrip %d: %s" n e
  done;
  Alcotest.(check string) "known" "aGVsbG8_" (B64url.encode "hello?");
  Alcotest.(check bool) "padding rejected" true (Result.is_error (B64url.decode "QQ=="));
  Alcotest.(check bool)
    "std alphabet rejected" true
    (Result.is_error (B64url.decode "a+b/"));
  Alcotest.(check bool) "length 1 mod 4" true (Result.is_error (B64url.decode "QUFBQ"));
  Alcotest.(check bool) "non-canonical" true (Result.is_error (B64url.decode "QR"));
  Alcotest.(check (result string string)) "canonical" (Ok "A") (B64url.decode "QQ")

(* ---- JWK ---- *)

let jwk_parsing () =
  let set = `Assoc [ ("keys", `List (List.map Jwk.to_json keys)) ] in
  (match Jwk.set_of_json set with
  | Ok (ks, []) ->
      Alcotest.(check int) "all keys" 4 (List.length ks);
      Alcotest.(check (list (option string)))
        "kids"
        [ Some "rsa1"; Some "ec1"; Some "ec384"; Some "ed1" ]
        (List.map (fun (k : Jwk.t) -> k.kid) ks)
  | Ok (_, bad) -> Alcotest.failf "unexpected skips: %s" (String.concat "; " bad)
  | Error e -> Alcotest.fail e);
  let small = Mirage_crypto_pk.Rsa.(pub_of_priv (generate ~bits:1024 ())) in
  let bad =
    [
      ("oct", `Assoc [ ("kty", `String "oct"); ("k", `String "c2VjcmV0") ]);
      ("rsa1024", Jwk.to_json (jwk "small" (Jwk.Rsa small)));
      ( "private",
        match Jwk.to_json (jwk "x" (Jwk.Rsa rsa_pub)) with
        | `Assoc kv -> `Assoc (kv @ [ ("d", `String "AQAB") ])
        | j -> j );
      ( "bad point",
        `Assoc
          [
            ("kty", `String "EC");
            ("crv", `String "P-256");
            ("x", `String (B64url.encode (String.make 32 '\001')));
            ("y", `String (B64url.encode (String.make 32 '\002')));
          ] );
      ("unknown kty", `Assoc [ ("kty", `String "XYZ") ]);
    ]
  in
  List.iter
    (fun (name, j) ->
      Alcotest.(check bool) ("rejected: " ^ name) true (Result.is_error (Jwk.of_json j)))
    bad;
  match
    Jwk.set_of_json
      (`Assoc [ ("keys", `List (Jwk.to_json (List.hd keys) :: List.map snd bad)) ])
  with
  | Ok (ks, skipped) ->
      Alcotest.(check int) "good kept" 1 (List.length ks);
      Alcotest.(check int) "bad skipped" 5 (List.length skipped)
  | Error e -> Alcotest.fail e

let jwk_compat () =
  let r = jwk "r" (Jwk.Rsa rsa_pub) in
  Alcotest.(check bool) "rsa RS256" true (Jwk.compatible Config.RS256 r);
  Alcotest.(check bool) "rsa PS256" true (Jwk.compatible Config.PS256 r);
  Alcotest.(check bool) "rsa ES256" false (Jwk.compatible Config.ES256 r);
  Alcotest.(check bool)
    "ec ES384" false
    (Jwk.compatible Config.ES384 (jwk "e" (Jwk.P256 p256_pub)));
  Alcotest.(check bool)
    "use enc" false
    (Jwk.compatible Config.RS256 (jwk ~use:(Some "enc") "r" (Jwk.Rsa rsa_pub)));
  Alcotest.(check bool)
    "alg pinned other" false
    (Jwk.compatible Config.RS256 (jwk ~alg:"PS256" "r" (Jwk.Rsa rsa_pub)));
  Alcotest.(check bool)
    "alg pinned same" true
    (Jwk.compatible Config.PS256 (jwk ~alg:"PS256" "r" (Jwk.Rsa rsa_pub)))

(* ---- JWT verification table ---- *)

let valid_algorithms () =
  let c = claims [] in
  let cases =
    [
      ("RS256", rs c);
      ("RS384", rs ~alg:"RS384" c);
      ("PS256", rs ~alg:"PS256" c);
      ("ES256", sign ~alg:"ES256" ~kid:(Some "ec1") (Jwt.Sign_p256 p256_priv) c);
      ("ES384", sign ~alg:"ES384" ~kid:(Some "ec384") (Jwt.Sign_p384 p384_priv) c);
      ("EdDSA", sign ~alg:"EdDSA" ~kid:(Some "ed1") (Jwt.Sign_ed25519 ed_priv) c);
    ]
  in
  List.iter
    (fun (name, tok) ->
      let id = check_ok name (verify tok) in
      Alcotest.(check string) (name ^ " policy") "shop" id.policy;
      Alcotest.(check (option string)) (name ^ " sub") (Some "user-17") id.subject;
      Alcotest.(check string) (name ^ " provider") "corp" id.provider)
    cases

let alg_attacks () =
  let c = claims [] in
  (* algorithm outside the provider's allowlist *)
  check_err "RS256 not allowed" (Jwt.Alg_not_allowed "RS256")
    (verify ~p:(provider ~algorithms:[ Config.ES256 ] ()) (rs c));
  (* alg: none, with and without a signature segment *)
  check_err "alg none" (Jwt.Alg_not_allowed "none") (verify (rs ~alg:"none" c));
  let unsigned =
    match String.split_on_char '.' (rs ~alg:"none" c) with
    | [ h; p; _ ] -> h ^ "." ^ p ^ "."
    | _ -> assert false
  in
  (match verify unsigned with
  | Error (Jwt.Malformed _) -> ()
  | _ -> Alcotest.fail "unsigned token must be malformed");
  (* HS256 key confusion: HMAC over the input keyed with the RSA public modulus *)
  let header = B64url.encode {|{"alg":"HS256","kid":"rsa1"}|} in
  let payload = B64url.encode (Yojson.Safe.to_string c) in
  let input = header ^ "." ^ payload in
  let secret = Mirage_crypto_pk.Z_extra.to_octets_be rsa_pub.n in
  let mac = Digestif.SHA256.(to_raw_string (hmac_string ~key:secret input)) in
  check_err "HS256 confusion" (Jwt.Alg_not_allowed "HS256")
    (verify (input ^ "." ^ B64url.encode mac));
  (* ES256 token whose kid names the RSA key: key type must match the alg *)
  check_err "kid of wrong key type" (Jwt.Unknown_kid "rsa1")
    (verify (sign ~alg:"ES256" ~kid:(Some "rsa1") (Jwt.Sign_p256 p256_priv) c));
  (* RS256 claimed, signed with a different RSA key *)
  check_err "wrong key" Jwt.Bad_signature (verify (sign (Jwt.Sign_rsa rsa2_priv) c));
  (* crit header *)
  match verify (rs ~extra_header:[ ("crit", `List [ `String "exp" ]) ] c) with
  | Error (Jwt.Malformed _) -> ()
  | _ -> Alcotest.fail "crit must be rejected"

let kid_cases () =
  let c = claims [] in
  check_err "missing kid" Jwt.Missing_kid (verify (rs ~kid:None c));
  check_err "unknown kid" (Jwt.Unknown_kid "nope") (verify (rs ~kid:(Some "nope") c))

let tampering () =
  let tok = rs (claims []) in
  let forged_payload =
    B64url.encode (Yojson.Safe.to_string (claims [ ("sub", `String "admin") ]))
  in
  let tampered =
    match String.split_on_char '.' tok with
    | [ h; _; s ] -> String.concat "." [ h; forged_payload; s ]
    | _ -> assert false
  in
  check_err "tampered payload" Jwt.Bad_signature (verify tampered);
  let bad_sig =
    match String.split_on_char '.' tok with
    | [ h; p; _ ] -> String.concat "." [ h; p; B64url.encode (String.make 256 'x') ]
    | _ -> assert false
  in
  check_err "garbage signature" Jwt.Bad_signature (verify bad_sig);
  (match verify "not.a.jwt!" with
  | Error (Jwt.Malformed _) -> ()
  | _ -> Alcotest.fail "malformed");
  (match verify (String.make 20000 'a' ^ ".b.c") with
  | Error (Jwt.Malformed _) -> ()
  | _ -> Alcotest.fail "oversize");
  (* duplicate claim names are ambiguous: rejected *)
  let dup = B64url.encode {|{"iss":"https://evil","iss":"https://idp.example.com"}|} in
  match String.split_on_char '.' tok with
  | [ h; _; s ] -> (
      match verify (String.concat "." [ h; dup; s ]) with
      | Error (Jwt.Malformed _) -> ()
      | _ -> Alcotest.fail "duplicate claims")
  | _ -> assert false

let time_claims () =
  check_err "expired" Jwt.Expired (verify (rs (claims ~exp:(now -. 61.) [])));
  ignore (check_ok "within leeway" (verify (rs (claims ~exp:(now -. 30.) []))));
  check_err "expired, no leeway" Jwt.Expired
    (verify ~p:(provider ~leeway:0 ()) (rs (claims ~exp:(now -. 1.) [])));
  check_err "nbf future" Jwt.Not_yet_valid
    (verify (rs (claims [ ("nbf", `Int (int_of_float now + 120)) ])));
  ignore
    (check_ok "nbf within leeway"
       (verify (rs (claims [ ("nbf", `Int (int_of_float now + 30)) ]))));
  check_err "iat future" Jwt.Issued_in_future
    (verify (rs (claims [ ("iat", `Int (int_of_float now + 3600)) ])));
  check_err "missing exp" (Jwt.Missing_claim "exp")
    (verify (rs (claims ~drop:[ "exp" ] [])));
  check_err "exp string" (Jwt.Bad_claim "exp")
    (verify (rs (claims [ ("exp", `String "soon") ])));
  ignore (check_ok "float exp" (verify (rs (claims [ ("exp", `Float (now +. 100.5)) ]))))

let iss_aud () =
  check_err "wrong iss" Jwt.Wrong_issuer
    (verify (rs (claims [ ("iss", `String "https://evil.example") ])));
  check_err "iss trailing slash" Jwt.Wrong_issuer
    (verify (rs (claims [ ("iss", `String (issuer ^ "/")) ])));
  check_err "missing iss" Jwt.Wrong_issuer (verify (rs (claims ~drop:[ "iss" ] [])));
  check_err "wrong aud" Jwt.Wrong_audience
    (verify (rs (claims [ ("aud", `String "other") ])));
  check_err "missing aud" Jwt.Wrong_audience (verify (rs (claims ~drop:[ "aud" ] [])));
  ignore
    (check_ok "aud array"
       (verify (rs (claims [ ("aud", `List [ `String "x"; `String "haltsql-alt" ]) ]))));
  check_err "aud array none" Jwt.Wrong_audience
    (verify (rs (claims [ ("aud", `List [ `String "x"; `Int 3 ]) ])))

let required_claims () =
  let p =
    provider
      ~required:
        [
          ("scope", Config.Claim_one "sql.verify");
          ("groups", Config.Claim_all [ "a"; "b" ]);
        ]
      ()
  in
  let ok =
    [
      ("scope", `String "openid sql.verify profile");
      ("groups", `List [ `String "b"; `String "a"; `String "c" ]);
    ]
  in
  ignore (check_ok "all required" (verify ~p (rs (claims ok))));
  check_err "missing scope" (Jwt.Missing_claim "scope")
    (verify ~p (rs (claims [ List.nth ok 1 ])));
  check_err "scope substring is not a match" (Jwt.Claim_mismatch "scope")
    (verify ~p (rs (claims [ ("scope", `String "sql.verifyx"); List.nth ok 1 ])));
  check_err "groups partial" (Jwt.Claim_mismatch "groups")
    (verify ~p (rs (claims [ List.hd ok; ("groups", `List [ `String "a" ]) ])));
  (* nested required claim via dot path *)
  let p = provider ~required:[ ("realm_access.roles", Config.Claim_one "sql") ] () in
  ignore
    (check_ok "dot path"
       (verify ~p
          (rs
             (claims [ ("realm_access", `Assoc [ ("roles", `List [ `String "sql" ]) ]) ]))));
  (* scp splits on spaces like scope, but arbitrary string claims do not *)
  let p_scp = provider ~required:[ ("scp", Config.Claim_one "sql.verify") ] () in
  ignore
    (check_ok "scp space-separated"
       (verify ~p:p_scp (rs (claims [ ("scp", `String "openid sql.verify") ]))));
  let p_role = provider ~required:[ ("role", Config.Claim_one "admin") ] () in
  check_err "non-scope string claim does not space-split" (Jwt.Claim_mismatch "role")
    (verify ~p:p_role (rs (claims [ ("role", `String "user admin") ])));
  ignore
    (check_ok "non-scope string claim exact match"
       (verify ~p:p_role (rs (claims [ ("role", `String "admin") ]))))

let policy_selection () =
  let p =
    provider
      ~policy:
        (Config.Oidc_from_claim
           { claim = "haltsql_policy"; allowed = [ "shop"; "other" ] })
      ()
  in
  let id =
    check_ok "allowed policy"
      (verify ~p (rs (claims [ ("haltsql_policy", `String "other") ])))
  in
  Alcotest.(check string) "selected" "other" id.policy;
  check_err "not allowed" (Jwt.Policy_not_allowed "haltsql_policy")
    (verify ~p (rs (claims [ ("haltsql_policy", `String "admin") ])));
  check_err "non-string" (Jwt.Policy_not_allowed "haltsql_policy")
    (verify ~p (rs (claims [ ("haltsql_policy", `List [ `String "shop" ]) ])));
  check_err "missing" (Jwt.Missing_claim "haltsql_policy") (verify ~p (rs (claims [])))

let context_claims () =
  let p =
    provider
      ~context_claims:
        [
          ("tenant_id", "https://corp.example/tenant");
          ("org", "org.id");
          ("regions", "regions");
          ("uid", "uid");
        ]
      ()
  in
  let good =
    [
      ("https://corp.example/tenant", `String "acme");
      ("org", `Assoc [ ("id", `Int 42) ]);
      ("regions", `List [ `String "eu-1"; `Int 2 ]);
      ("uid", `Float 7.0);
    ]
  in
  let id = check_ok "context" (verify ~p (rs (claims good))) in
  Alcotest.(check bool)
    "derived context" true
    (id.context
    = Context.
        [
          ("tenant_id", One "acme");
          ("org", One "42");
          ("regions", Many [ "eu-1"; "2" ]);
          ("uid", One "7");
        ]);
  Alcotest.(check (list string)) "request fields" [ "user_id" ] id.request_context_fields;
  let with_ k v = List.map (fun (k', v') -> if k' = k then (k, v) else (k', v')) good in
  check_err "object" (Jwt.Bad_claim "https://corp.example/tenant")
    (verify ~p (rs (claims (with_ "https://corp.example/tenant" (`Assoc [])))));
  check_err "bool" (Jwt.Bad_claim "uid")
    (verify ~p (rs (claims (with_ "uid" (`Bool true)))));
  check_err "fraction" (Jwt.Bad_claim "uid")
    (verify ~p (rs (claims (with_ "uid" (`Float 1.5)))));
  check_err "empty array" (Jwt.Bad_claim "regions")
    (verify ~p (rs (claims (with_ "regions" (`List [])))));
  check_err "nested array" (Jwt.Bad_claim "regions")
    (verify ~p (rs (claims (with_ "regions" (`List [ `List [] ])))));
  check_err "null" (Jwt.Bad_claim "uid") (verify ~p (rs (claims (with_ "uid" `Null))));
  check_err "missing" (Jwt.Missing_claim "org.id")
    (verify ~p (rs (claims (List.filter (fun (k, _) -> k <> "org") good))))

let shape_helpers () =
  let tok = rs (claims []) in
  Alcotest.(check bool) "looks like jwt" true (Jwt.looks_like_jwt tok);
  Alcotest.(check bool) "opaque token" false (Jwt.looks_like_jwt "token-for-shop-agent");
  Alcotest.(check bool) "dots but not jwt" false (Jwt.looks_like_jwt "a.b.c");
  Alcotest.(check (option string))
    "unverified iss" (Some issuer) (Jwt.unverified_issuer tok)

(* ---- Oidc_client: cache, refresh, discovery (fake fetch + clock) ---- *)

let jwks_json ks =
  Yojson.Safe.to_string (`Assoc [ ("keys", `List (List.map Jwk.to_json ks)) ])

type fake = {
  mutable routes : (string * (string, string) result) list;
  mutable calls : string list;
  mutable clock : float;
}

let fake () = { routes = []; calls = []; clock = now }

let fetch_of f : Oidc_client.fetch =
 fun uri ->
  let u = Uri.to_string uri in
  f.calls <- u :: f.calls;
  Lwt.return (Option.value (List.assoc_opt u f.routes) ~default:(Error "HTTP 404"))

let count f u = List.length (List.filter (( = ) u) f.calls)
let run = Lwt_main.run
let jwks_url = "https://idp.example.com/jwks"

let cache_and_unknown_kid () =
  let f = fake () in
  f.routes <- [ (jwks_url, Ok (jwks_json [ jwk "rsa1" (Jwk.Rsa rsa_pub) ])) ];
  let p =
    Oidc_client.provider ~fetch:(fetch_of f) ~now:(fun () -> f.clock) (provider ())
  in
  let v tok = run (Oidc_client.verify p tok) in
  let t1 = rs (claims []) in
  ignore (check_ok "first" (v t1));
  ignore (check_ok "cached" (v t1));
  Alcotest.(check int) "one fetch while fresh" 1 (count f jwks_url);
  (* a token from a rotated key: one forced refresh finds it *)
  let t2 = sign ~kid:(Some "rsa2") (Jwt.Sign_rsa rsa2_priv) (claims []) in
  f.routes <-
    [
      ( jwks_url,
        Ok (jwks_json [ jwk "rsa1" (Jwk.Rsa rsa_pub); jwk "rsa2" (Jwk.Rsa rsa2_pub) ]) );
    ];
  ignore (check_ok "rotated key after refresh" (v t2));
  Alcotest.(check int) "refetched once" 2 (count f jwks_url);
  (* another unknown kid within 30 s: no new fetch *)
  f.clock <- f.clock +. 10.;
  check_err "unknown kid rate limited" (Jwt.Unknown_kid "zzz")
    (v (rs ~kid:(Some "zzz") (claims [])));
  Alcotest.(check int) "no fetch within 30s" 2 (count f jwks_url);
  f.clock <- f.clock +. 25.;
  check_err "unknown kid after 30s" (Jwt.Unknown_kid "zzz")
    (v (rs ~kid:(Some "zzz") (claims [])));
  Alcotest.(check int) "fetch after 30s" 3 (count f jwks_url)

let stale_while_error () =
  let f = fake () in
  f.routes <- [ (jwks_url, Ok (jwks_json keys)) ];
  let p =
    Oidc_client.provider ~fetch:(fetch_of f) ~now:(fun () -> f.clock) (provider ())
  in
  let v at = run (Oidc_client.verify p (rs (claims ~exp:(at +. 600.) []))) in
  ignore (check_ok "warm" (v f.clock));
  f.routes <- [];
  (* expired cache (ttl 300), IdP down: stale keys still accepted *)
  f.clock <- now +. 301.;
  ignore (check_ok "stale accepted" (v f.clock));
  Alcotest.(check int) "refresh attempted" 2 (count f jwks_url);
  (* failed attempts are not retried within 5 s *)
  f.clock <- now +. 303.;
  ignore (check_ok "stale, no retry" (v f.clock));
  Alcotest.(check int) "no hammering" 2 (count f jwks_url);
  (* beyond ttl + min(ttl, 3600) = 600 s: fail closed *)
  f.clock <- now +. 601.;
  (match v f.clock with
  | Error (Jwt.Keys_unavailable _) -> ()
  | Ok _ -> Alcotest.fail "stale keys used past the bound"
  | Error e -> Alcotest.failf "unexpected %s" (Jwt.error_to_string e));
  (* IdP back: recovers *)
  f.routes <- [ (jwks_url, Ok (jwks_json keys)) ];
  f.clock <- now +. 700.;
  ignore (check_ok "recovered" (v f.clock))

let discovery () =
  let f = fake () in
  let disc = "https://idp.example.com/.well-known/openid-configuration" in
  let jw = "https://keys.idp.example.com/k" in
  f.routes <-
    [
      (disc, Ok (Printf.sprintf {|{"issuer":%S,"jwks_uri":%S}|} issuer jw));
      (jw, Ok (jwks_json keys));
    ];
  let cfg = { (provider ()) with jwks_uri = None } in
  let p = Oidc_client.provider ~fetch:(fetch_of f) ~now:(fun () -> f.clock) cfg in
  ignore (check_ok "via discovery" (run (Oidc_client.verify p (rs (claims [])))));
  Alcotest.(check (list string)) "fetch order" [ disc; jw ] (List.rev f.calls);
  (* issuer mismatch in the discovery document *)
  let f2 = fake () in
  f2.routes <-
    [
      (disc, Ok (Printf.sprintf {|{"issuer":"https://evil","jwks_uri":%S}|} jw));
      (jw, Ok (jwks_json keys));
    ];
  let p2 = Oidc_client.provider ~fetch:(fetch_of f2) cfg in
  (match
     run (Oidc_client.verify p2 (rs (claims ~exp:(Unix.gettimeofday () +. 600.) [])))
   with
  | Error (Jwt.Keys_unavailable m) ->
      Alcotest.(check bool) "mentions issuer" true (String.length m > 0);
      Alcotest.(check int) "jwks never fetched" 0 (count f2 jw)
  | _ -> Alcotest.fail "discovery issuer mismatch must fail");
  (* http jwks_uri without allow_insecure_http *)
  let f3 = fake () in
  let p3 =
    Oidc_client.provider ~fetch:(fetch_of f3)
      { cfg with jwks_uri = Some "http://idp.example.com/jwks" }
  in
  (match run (Oidc_client.refresh p3) with
  | Error _ -> Alcotest.(check int) "no plain-http fetch" 0 (List.length f3.calls)
  | Ok _ -> Alcotest.fail "http jwks_uri accepted");
  (* loopback jwks_uri rejected when issuer is not on loopback *)
  let f4 = fake () in
  let p4 =
    Oidc_client.provider ~fetch:(fetch_of f4)
      { cfg with jwks_uri = Some "https://127.0.0.1/jwks" }
  in
  (match run (Oidc_client.refresh p4) with
  | Error _ -> Alcotest.(check int) "no loopback jwks fetch" 0 (List.length f4.calls)
  | Ok _ -> Alcotest.fail "loopback jwks_uri for non-loopback issuer accepted");
  (* discovered loopback jwks_uri also rejected when issuer is not on loopback *)
  let f5 = fake () in
  f5.routes <-
    [
      ( disc,
        Ok (Printf.sprintf {|{"issuer":%S,"jwks_uri":"https://localhost/jwks"}|} issuer)
      );
    ];
  let p5 = Oidc_client.provider ~fetch:(fetch_of f5) cfg in
  match run (Oidc_client.refresh p5) with
  | Error _ -> Alcotest.(check int) "only discovery fetched" 1 (List.length f5.calls)
  | Ok _ -> Alcotest.fail "discovered loopback jwks_uri accepted"

let registry () =
  let f = fake () in
  f.routes <- [ (jwks_url, Ok (jwks_json keys)) ];
  let r =
    Oidc_client.registry ~fetch:(fetch_of f) ~now:(fun () -> f.clock) [ provider () ]
  in
  let auth t = run (Oidc_client.authenticate r t) in
  (match auth "opaque-static-token" with
  | `Not_applicable -> ()
  | _ -> Alcotest.fail "opaque");
  (match auth (rs (claims [ ("iss", `String "https://other-idp") ])) with
  | `Not_applicable -> ()
  | _ -> Alcotest.fail "unknown issuer falls back");
  (match auth (rs (claims [])) with
  | `Verified id -> Alcotest.(check string) "verified" "corp" id.provider
  | _ -> Alcotest.fail "verified");
  (match auth (rs (claims [ ("aud", `String "nope") ])) with
  | `Rejected Jwt.Wrong_audience -> ()
  | _ -> Alcotest.fail "rejected");
  Alcotest.(check bool) "empty" true (Oidc_client.is_empty (Oidc_client.registry []));
  (* update keeps the cache of an unchanged provider *)
  let r2 = Oidc_client.update r [ provider () ] in
  ignore (run (Oidc_client.authenticate r2 (rs (claims []))));
  Alcotest.(check int) "cache reused across update" 1 (count f jwks_url)

(* ---- mTLS and request context ---- *)

let mtls_mapping () =
  let ids : Config.mtls_identity list =
    [
      {
        mtls_match = Config.Spiffe_id "spiffe://corp.example/ns/a/sa/analytics";
        mtls_policy = "shop";
        mtls_context = [ ("tenant_id", Context.One "acme") ];
        mtls_request_context_fields = [];
      };
      {
        mtls_match = Config.Subject_cn "support-bot";
        mtls_policy = "other";
        mtls_context = [];
        mtls_request_context_fields = [ "tenant_id" ];
      };
    ]
  in
  let peer ?spiffe ?cn () =
    {
      Mtls.spiffe_id = spiffe;
      uri_sans = Option.to_list spiffe;
      subject_cn = cn;
      fingerprint = "ab";
    }
  in
  let pol p =
    Option.map
      (fun (i : Config.mtls_identity) -> i.mtls_policy)
      (Mtls.find_identity ids p)
  in
  Alcotest.(check (option string))
    "spiffe" (Some "shop")
    (pol (peer ~spiffe:"spiffe://corp.example/ns/a/sa/analytics" ~cn:"support-bot" ()));
  Alcotest.(check (option string)) "cn" (Some "other") (pol (peer ~cn:"support-bot" ()));
  Alcotest.(check (option string)) "case-sensitive" None (pol (peer ~cn:"Support-Bot" ()));
  Alcotest.(check (option string))
    "unknown" None
    (pol (peer ~spiffe:"spiffe://corp.example/x" ()));
  Alcotest.(check string)
    "subject spiffe" "spiffe://x/y"
    (Mtls.subject (peer ~spiffe:"spiffe://x/y" ~cn:"c" ()));
  Alcotest.(check string) "subject fp" "sha256:ab" (Mtls.subject (peer ()))

let mtls_cn_text () =
  let module Dn = X509.Distinguished_name in
  let cn encoding s = Mtls.cn_text (Dn.Common_name.v ~encoding s) in
  let chk = Alcotest.(check (option string)) in
  chk "utf8" (Some "caf\xc3\xa9-bot") (cn `UTF8 "caf\xc3\xa9-bot");
  chk "utf8 invalid" None (cn `UTF8 "caf\xe9");
  chk "printable" (Some "support-bot") (cn `Printable "support-bot");
  chk "printable non-ascii" None (cn `Printable "caf\xe9");
  chk "bmp" (Some "caf\xc3\xa9") (cn `BMP "\x00c\x00a\x00f\x00\xe9");
  chk "bmp surrogate pair" (Some "\xf0\x9f\x98\x80") (cn `BMP "\xd8\x3d\xde\x00");
  chk "bmp lone surrogate" None (cn `BMP "\xd8\x3d");
  chk "bmp odd length" None (cn `BMP "\x00a\x00");
  chk "universal" (Some "ab") (cn `Universal "\x00\x00\x00a\x00\x00\x00b");
  chk "universal out of range" None (cn `Universal "\x00\x11\x00\x00");
  chk "universal bad length" None (cn `Universal "\x00\x00a");
  chk "teletex refused" None (cn `Teletex "support-bot");
  chk "empty" None (cn `UTF8 "");
  chk "control char" None (cn `UTF8 "a\x00b");
  chk "newline" None (cn `UTF8 "a\nb");
  (* End to end: a certificate whose CN is a BMPString keeps its encoding through
     DER and maps to the UTF-8 identity. *)
  let key = X509.Private_key.generate `P256 in
  let now = Ptime_clock.now () in
  let dn =
    Dn.
      [
        Relative_distinguished_name.singleton
          (CN (Common_name.v ~encoding:`BMP "\x00b\x00o\x00t"));
      ]
  in
  let csr = Result.get_ok (X509.Signing_request.create dn key) in
  let valid_until = Option.get (Ptime.add_span now (Ptime.Span.of_int_s 3600)) in
  let cert =
    match X509.Signing_request.sign csr ~valid_from:now ~valid_until key dn with
    | Ok c -> c
    | Error _ -> Alcotest.fail "sign"
  in
  let cert =
    Result.get_ok (X509.Certificate.decode_der (X509.Certificate.encode_der cert))
  in
  let p = Mtls.peer_of_certificate cert in
  chk "peer cn from BMP" (Some "bot") p.Mtls.subject_cn;
  Alcotest.(check string) "subject" "bot" (Mtls.subject p)

let context_merge () =
  let authenticated = Context.[ ("tenant_id", One "acme") ] in
  let m body = Request_context.merge ~authenticated ~allowed:[ "user_id" ] ~body in
  Alcotest.(check bool)
    "allowed field added" true
    (m Context.[ ("user_id", One "u1") ]
    = Ok Context.[ ("tenant_id", One "acme"); ("user_id", One "u1") ]);
  Alcotest.(check bool)
    "identical repeat ok" true
    (m Context.[ ("tenant_id", One "acme") ] = Ok authenticated);
  Alcotest.(check bool)
    "conflict refused" true
    (m Context.[ ("tenant_id", One "evil") ] = Error [ "tenant_id" ]);
  Alcotest.(check bool)
    "unlisted refused" true
    (m Context.[ ("role", One "admin"); ("user_id", One "u"); ("x", Many []) ]
    = Error [ "role"; "x" ]);
  Alcotest.(check bool) "empty body" true (m [] = Ok authenticated)

let loopback_hosts () =
  let check h expected =
    Alcotest.(check bool) ("loopback " ^ h) expected (Haltsql_core.Loopback.is_host h)
  in
  List.iter
    (fun h -> check h true)
    [
      "localhost";
      "LOCALHOST.";
      "localhost.";
      "127.0.0.1";
      "127.0.0.1.";
      "127.255.255.254";
      "::1";
      "[::1]";
      "0:0:0:0:0:0:0:1";
      "[0:0:0:0:0:0:0:1]";
      "0000:0000:0000:0000:0000:0000:0000:0001";
      "::ffff:127.0.0.1";
      "[::ffff:127.0.0.1]";
      "::FFFF:127.1.2.3";
      "0:0:0:0:0:ffff:127.0.0.1";
    ];
  List.iter
    (fun h -> check h false)
    [
      "";
      "localhost..";
      "127.0.0.01";
      "127.01.0.1";
      "127.0.00.1";
      "::ffff:127.0.0.01";
      "::ffff:10.0.0.1";
      "0:0:0:0:0:0:0:2";
    ]

let () =
  let tc n f = Alcotest.test_case n `Quick f in
  Alcotest.run ~and_exit:true "haltsql.auth"
    [
      ("b64url", [ tc "strict codec" b64url ]);
      ("loopback", [ tc "host detection" loopback_hosts ]);
      ("jwk", [ tc "parsing" jwk_parsing; tc "compatibility" jwk_compat ]);
      ( "jwt",
        [
          tc "valid RS256/RS384/PS256/ES256/ES384/EdDSA" valid_algorithms;
          tc "alg attacks (none, HS256, allowlist, key type)" alg_attacks;
          tc "missing / unknown kid" kid_cases;
          tc "tampering and malformed" tampering;
          tc "exp / nbf / iat" time_claims;
          tc "iss / aud" iss_aud;
          tc "required claims" required_claims;
          tc "policy selection" policy_selection;
          tc "context claims" context_claims;
          tc "shape helpers" shape_helpers;
        ] );
      ( "oidc client",
        [
          tc "cache + unknown kid refresh" cache_and_unknown_kid;
          tc "stale-while-error bound" stale_while_error;
          tc "discovery" discovery;
          tc "registry" registry;
        ] );
      ("mtls", [ tc "identity mapping" mtls_mapping; tc "CN decoding" mtls_cn_text ]);
      ("context", [ tc "merge rules" context_merge ]);
    ]
