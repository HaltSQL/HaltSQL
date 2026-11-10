(* Known-answer tests for lib/auth's JWS/JWK code, through the public Jwt / Jwk / Oidc
   API only.

   vectors/rfc_vectors.json: the examples of RFC 7515 appendix A, RFC 7520 sections 3-4
   and RFC 8037 appendix A, extracted from the published RFC texts by
   vectors/extract_rfc_vectors.py (nothing retyped).

   vectors/interop_vectors.json: one key and one signed JWT per accepted algorithm,
   produced by pyca/cryptography (vectors/interop_vectors.py generate).

   Both files were verified with pyca/cryptography (interop_vectors.py check) before
   these tests relied on them, so a failing positive case here is a lib/auth bug and
   not a transcription error. *)

open Haltsql_auth
module Config = Haltsql.Config

let read_file f =
  let ic = open_in_bin f in
  let s = really_input_string ic (in_channel_length ic) in
  close_in ic;
  s

let member k = function
  | `Assoc kv -> ( match List.assoc_opt k kv with Some v -> v | None -> `Null)
  | _ -> `Null

let str k j =
  match member k j with `String s -> s | _ -> Alcotest.failf "vector has no %S" k

let rfc = Yojson.Safe.from_string (read_file "vectors/rfc_vectors.json")
let interop = Yojson.Safe.from_string (read_file "vectors/interop_vectors.json")

let vector name =
  match member name rfc with `Null -> Alcotest.failf "no vector %s" name | v -> v

let all_algs = Config.[ RS256; RS384; RS512; PS256; ES256; ES384; EdDSA ]
let private_members = [ "d"; "p"; "q"; "dp"; "dq"; "qi"; "oth"; "k" ]

let public_part = function
  | `Assoc kv -> `Assoc (List.filter (fun (k, _) -> not (List.mem k private_members)) kv)
  | j -> j

let parse_jwk what j =
  match Jwk.of_json j with Ok k -> k | Error e -> Alcotest.failf "%s: JWK: %s" what e

(* A compact JWS split by hand: the RFC 7520 and RFC 8037 payloads are plain text, which
   [Jwt.decode] (a JWT decoder) refuses, so their signatures are checked on the raw
   segments. *)
let split tok =
  match String.split_on_char '.' tok with
  | [ h; p; s ] -> (
      match (B64url.decode h, B64url.decode s) with
      | Ok hj, Ok signature -> (Yojson.Safe.from_string hj, h ^ "." ^ p, signature)
      | _ -> Alcotest.fail "vector is not base64url")
  | _ -> Alcotest.fail "vector is not a compact JWS"

let flip s i =
  let b = Bytes.of_string s in
  Bytes.set b i (Char.chr (Char.code (Bytes.get b i) lxor 1));
  Bytes.to_string b

(* The signature verifies under exactly [alg] and no other algorithm, and stops verifying
   when any single byte of the signature or one byte of the signing input changes. *)
let check_only_valid_under what alg (key : Jwk.key) ~signing_input ~signature =
  List.iter
    (fun a ->
      Alcotest.(check bool)
        (Printf.sprintf "%s as %s" what (Config.string_of_jwt_alg a))
        (a = alg)
        (Jwt.verify_signature a key ~signing_input ~signature))
    all_algs;
  for i = 0 to String.length signature - 1 do
    if Jwt.verify_signature alg key ~signing_input ~signature:(flip signature i) then
      Alcotest.failf "%s: accepted with signature byte %d flipped" what i
  done;
  List.iter
    (fun i ->
      if Jwt.verify_signature alg key ~signing_input:(flip signing_input i) ~signature
      then Alcotest.failf "%s: accepted with signing input byte %d flipped" what i)
    [ 0; String.length signing_input / 2; String.length signing_input - 1 ];
  Alcotest.(check bool)
    (what ^ ": truncated input") false
    (Jwt.verify_signature alg key
       ~signing_input:(String.sub signing_input 0 (String.length signing_input - 1))
       ~signature)

let is_malformed = function Error (Jwt.Malformed _) -> true | _ -> false

let alg_rejected what tok name =
  let header, _, _ = split tok in
  Alcotest.(check string) (what ^ ": header alg") name (str "alg" header);
  Alcotest.(check bool)
    (what ^ ": alg not allowed") true
    (Jwt.alg_of_string name = Error (Jwt.Alg_not_allowed name))

(* A provider that would accept the token if only its algorithm were acceptable. *)
let provider ?(issuer = "joe") () : Config.oidc_provider =
  {
    oidc_name = "vectors";
    issuer;
    audiences = [ "haltsql" ];
    jwks_uri = Some "https://idp.example.test/jwks";
    algorithms = all_algs;
    leeway_seconds = 0;
    jwks_cache_seconds = 300;
    oidc_policy = Config.Oidc_pinned "p";
    context_claims = [];
    required_claims = [];
    oidc_request_context_fields = [];
    allow_insecure_http = false;
  }

(* ---- RFC 7515 appendix A ---- *)

let rfc7515_positive name alg () =
  let v = vector name in
  let tok = str "token" v in
  Alcotest.(check bool)
    "the RFC's private JWK is refused" true
    (Result.is_error (Jwk.of_json (member "jwk" v)));
  let key = parse_jwk name (public_part (member "jwk" v)) in
  match Jwt.decode tok with
  | Error e -> Alcotest.failf "%s: decode: %s" name (Jwt.error_to_string e)
  | Ok t ->
      Alcotest.(check string) "alg" (Config.string_of_jwt_alg alg) t.alg_name;
      Alcotest.(check bool) "alg maps" true (Jwt.alg_of_string t.alg_name = Ok alg);
      Alcotest.(check bool) "no kid" true (t.kid = None);
      Alcotest.(check bool)
        "iss" true
        (List.assoc_opt "iss" t.claims = Some (`String "joe"));
      Alcotest.(check bool)
        "exp" true
        (Jwt.number_claim "exp" t.claims = Ok (Some 1300819380.));
      Alcotest.(check bool)
        "is_root" true
        (List.assoc_opt "http://example.com/is_root" t.claims = Some (`Bool true));
      let _, signing_input, signature = split tok in
      Alcotest.(check string) "signing input" signing_input t.signing_input;
      Alcotest.(check string) "signature bytes" signature t.signature;
      Alcotest.(check bool) "key is compatible" true (Jwk.compatible alg key);
      check_only_valid_under name alg key.key ~signing_input ~signature;
      (* The example has no kid, and haltsql-server never guesses a key. *)
      Alcotest.(check bool)
        "full verification: missing kid" true
        (Oidc.verify (provider ()) ~keys:[ { key with kid = Some "k" } ] ~now:1.3e9 tok
        = Error Jwt.Missing_kid)

let rfc7515_hs256 () =
  let v = vector "rfc7515_a1_hs256" in
  let tok = str "token" v in
  alg_rejected "A.1" tok "HS256";
  Alcotest.(check bool)
    "oct JWK refused" true
    (Result.is_error (Jwk.of_json (member "jwk" v)));
  Alcotest.(check bool)
    "oct JWK refused without k" true
    (Result.is_error (Jwk.of_json (public_part (member "jwk" v))));
  (match Jwk.set_of_json (`Assoc [ ("keys", `List [ member "jwk" v ]) ]) with
  | Ok ([], [ _ ]) -> ()
  | _ -> Alcotest.fail "an oct key must be skipped by the JWKS parser");
  Alcotest.(check bool)
    "full verification" true
    (Oidc.verify (provider ()) ~keys:[] ~now:1.3e9 tok
    = Error (Jwt.Alg_not_allowed "HS256"))

let rfc7515_unsecured () =
  let tok = str "token" (vector "rfc7515_a5_none") in
  Alcotest.(check bool)
    "ends with an empty signature" true
    (String.ends_with ~suffix:"." tok);
  Alcotest.(check bool)
    "decode refuses the empty signature" true
    (is_malformed (Jwt.decode tok));
  Alcotest.(check bool) "not JWT-shaped" false (Jwt.looks_like_jwt tok);
  Alcotest.(check bool)
    "full verification" true
    (is_malformed (Oidc.verify (provider ()) ~keys:[] ~now:1.3e9 tok));
  (* The same header and payload with some signature bytes attached. *)
  let tok' = tok ^ "AAAA" in
  alg_rejected "A.5 with a signature" tok' "none";
  Alcotest.(check bool)
    "full verification with a signature" true
    (Oidc.verify (provider ()) ~keys:[] ~now:1.3e9 tok'
    = Error (Jwt.Alg_not_allowed "none"))

let rfc7515_es512 () =
  let v = vector "rfc7515_a4_es512" in
  let tok = str "token" v in
  alg_rejected "A.4" tok "ES512";
  Alcotest.(check bool)
    "P-521 JWK refused" true
    (Result.is_error (Jwk.of_json (public_part (member "jwk" v))));
  (* its payload is the text "Payload", not a claims set *)
  Alcotest.(check bool) "decode" true (is_malformed (Jwt.decode tok))

(* ---- RFC 8037 appendix A ---- *)

let rfc8037_eddsa () =
  let v = vector "rfc8037_a4_eddsa" in
  let tok = str "token" v in
  Alcotest.(check bool)
    "private OKP JWK refused" true
    (Result.is_error (Jwk.of_json (member "private_jwk" v)));
  let key = parse_jwk "A.2" (member "jwk" v) in
  let header, signing_input, signature = split tok in
  Alcotest.(check string) "alg" "EdDSA" (str "alg" header);
  Alcotest.(check int) "signature length" 64 (String.length signature);
  Alcotest.(check string)
    "signature (the RFC's hex dump, first bytes)" "\x86\x0c\x98\xd2\x29\x7f\x30\x60"
    (String.sub signature 0 8);
  Alcotest.(check bool) "compatible" true (Jwk.compatible Config.EdDSA key);
  check_only_valid_under "RFC 8037 A.4" Config.EdDSA key.key ~signing_input ~signature;
  (* "Example of Ed25519 signing" is not a claims set *)
  Alcotest.(check bool) "decode" true (is_malformed (Jwt.decode tok))

(* ---- RFC 7520 section 4 ---- *)

let rfc7520_rs256 () =
  let v = vector "rfc7520_4_1_rs256" in
  let tok = str "token" v in
  let key = parse_jwk "figure 3" (member "jwk" v) in
  let header, signing_input, signature = split tok in
  Alcotest.(check string) "alg" "RS256" (str "alg" header);
  let kid = str "kid" header in
  Alcotest.(check string) "kid" "bilbo.baggins@hobbiton.example" kid;
  (match Jwt.select_key Config.RS256 ~kid:(Some kid) [ key ] with
  | Ok k -> Alcotest.(check bool) "selected by kid" true (k == key)
  | Error e -> Alcotest.failf "select_key: %s" (Jwt.error_to_string e));
  Alcotest.(check int) "signature length" 256 (String.length signature);
  check_only_valid_under "RFC 7520 4.1" Config.RS256 key.key ~signing_input ~signature;
  Alcotest.(check bool) "decode (text payload)" true (is_malformed (Jwt.decode tok))

let rfc7520_ps384 () =
  let v = vector "rfc7520_4_2_ps384" in
  let tok = str "token" v in
  alg_rejected "4.2" tok "PS384";
  let key = parse_jwk "figure 3" (member "jwk" v) in
  let _, signing_input, signature = split tok in
  (* a valid PS384 signature is not valid under any accepted algorithm *)
  List.iter
    (fun a ->
      Alcotest.(check bool)
        ("PS384 signature as " ^ Config.string_of_jwt_alg a)
        false
        (Jwt.verify_signature a key.key ~signing_input ~signature))
    all_algs

let rfc7520_es512 () =
  let v = vector "rfc7520_4_3_es512" in
  alg_rejected "4.3" (str "token" v) "ES512";
  Alcotest.(check bool)
    "P-521 JWK refused" true
    (Result.is_error (Jwk.of_json (member "jwk" v)))

let rfc7520_hs256 () =
  let v = vector "rfc7520_4_4_hs256" in
  alg_rejected "4.4" (str "token" v) "HS256";
  Alcotest.(check bool)
    "oct JWK refused" true
    (Result.is_error (Jwk.of_json (member "jwk" v)))

(* ---- pyca/cryptography interop ---- *)

let interop_keys () =
  match Jwk.set_of_json (member "jwks" interop) with
  | Ok (ks, []) -> ks
  | Ok (_, bad) -> Alcotest.failf "interop JWKS: skipped %s" (String.concat "; " bad)
  | Error e -> Alcotest.failf "interop JWKS: %s" e

let interop_tokens () =
  match member "tokens" interop with
  | `List l -> List.map (fun t -> (str "alg" t, str "kid" t, str "token" t)) l
  | _ -> Alcotest.fail "interop vectors have no tokens"

let interop_now = 1767225700.

let interop_full () =
  let keys = interop_keys () in
  let p = provider ~issuer:(str "issuer" interop) () in
  let toks = interop_tokens () in
  Alcotest.(check (list string))
    "one token per accepted algorithm"
    (List.map Config.string_of_jwt_alg all_algs)
    (List.map (fun (a, _, _) -> a) toks);
  List.iter
    (fun (alg, _, tok) ->
      (match Oidc.verify p ~keys ~now:interop_now tok with
      | Ok id ->
          Alcotest.(check (option string))
            (alg ^ " sub")
            (Some ("interop-" ^ alg))
            id.subject;
          Alcotest.(check (float 0.)) (alg ^ " exp") 4102444800. id.expires_at
      | Error e -> Alcotest.failf "%s: %s" alg (Jwt.error_to_string e));
      (* any change to the last signature character is a different signature *)
      let n = String.length tok in
      let c = if tok.[n - 2] = 'A' then 'B' else 'A' in
      let bad = String.sub tok 0 (n - 2) ^ String.make 1 c ^ String.sub tok (n - 1) 1 in
      Alcotest.(check bool)
        (alg ^ " tampered") true
        (Oidc.verify p ~keys ~now:interop_now bad = Error Jwt.Bad_signature);
      (* an algorithm the provider does not list *)
      let narrowed =
        {
          p with
          algorithms = List.filter (fun a -> Config.string_of_jwt_alg a <> alg) all_algs;
        }
      in
      Alcotest.(check bool)
        (alg ^ " not in the allowlist")
        true
        (Oidc.verify narrowed ~keys ~now:interop_now tok = Error (Jwt.Alg_not_allowed alg)))
    toks

(* Every token verifies under its own key and algorithm and under no other (key,
   algorithm) pair: 7 x 7 x 7 combinations, 7 of them valid. *)
let interop_matrix () =
  let keys = interop_keys () in
  let valid = ref 0 in
  List.iter
    (fun (alg, kid, tok) ->
      let _, signing_input, signature = split tok in
      List.iter
        (fun (k : Jwk.t) ->
          List.iter
            (fun a ->
              let expected = k.kid = Some kid && Config.string_of_jwt_alg a = alg in
              let got = Jwt.verify_signature a k.key ~signing_input ~signature in
              if got then incr valid;
              if got <> expected then
                Alcotest.failf "%s token, key %s, verified as %s: %b" alg
                  (Option.value k.kid ~default:"?")
                  (Config.string_of_jwt_alg a) got)
            all_algs)
        keys)
    (interop_tokens ());
  Alcotest.(check int) "valid combinations" 7 !valid

let interop_single_alg () =
  let keys = interop_keys () in
  List.iter
    (fun (alg, kid, tok) ->
      let key = List.find (fun (k : Jwk.t) -> k.kid = Some kid) keys in
      let a = Result.get_ok (Jwt.alg_of_string alg) in
      let _, signing_input, signature = split tok in
      check_only_valid_under ("interop " ^ alg) a key.key ~signing_input ~signature)
    (interop_tokens ())

let () =
  let tc n f = Alcotest.test_case n `Quick f in
  Alcotest.run "haltsql-auth-vectors"
    [
      ( "rfc7515",
        [
          tc "A.1 HS256 is rejected" rfc7515_hs256;
          tc "A.2 RS256" (rfc7515_positive "rfc7515_a2_rs256" Config.RS256);
          tc "A.3 ES256" (rfc7515_positive "rfc7515_a3_es256" Config.ES256);
          tc "A.4 ES512 is rejected" rfc7515_es512;
          tc "A.5 unsecured is rejected" rfc7515_unsecured;
        ] );
      ("rfc8037", [ tc "A.4 Ed25519" rfc8037_eddsa ]);
      ( "rfc7520",
        [
          tc "4.1 RS256" rfc7520_rs256;
          tc "4.2 PS384 is rejected" rfc7520_ps384;
          tc "4.3 ES512 is rejected" rfc7520_es512;
          tc "4.4 HS256 is rejected" rfc7520_hs256;
        ] );
      ( "interop",
        [
          tc "all seven algorithms, full verification" interop_full;
          tc "key x algorithm matrix" interop_matrix;
          tc "single-byte changes" interop_single_alg;
        ] );
    ]
