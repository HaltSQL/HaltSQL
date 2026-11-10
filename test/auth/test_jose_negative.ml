(* Negative tables for lib/auth's JWS/JWK code, in the style of Project Wycheproof: each
   row is one malformed signature, key, header or claim with the outcome it must have.

   Every row goes through the public API ([Oidc.verify], [Jwk.of_json],
   [Jwk.set_of_string], [Jwt.verify_signature]) and is run under a wrapper that turns an
   exception into a failure: a rejection must be a typed error.

   Behaviour these tables pin down on purpose:

   - ECDSA high-s signatures are ACCEPTED. JWS (RFC 7515/7518) has no low-s rule, and
     HSM-backed identity providers emit both forms, so (r, s) and (r, n - s) are both
     valid. Nothing in haltsql-server identifies a token by its signature bytes.
   - ECDSA signatures are the fixed-width r || s of RFC 7518 section 3.4, nothing else.
   - An RSA public exponent must be odd and at least 3 (e = 3 parses; e = 1, 0 and every
     even value do not); moduli must be 2048..8192 bits.
   - With several JWKS keys of one [kid], the first one compatible with the token's
     algorithm is used, in document order; the others are never tried.
   - Embedded-key headers ([jwk], [jku], [x5u], [x5c]) are ignored: the key only ever
     comes from the configured JWKS.
   - [typ] is not interpreted (it must be a string when present); ["b64": false] and any
     [crit] are refused.
   - [exp] is required; NumericDates may be fractional; a token is expired from
     [exp + leeway] on, and not yet valid while [now + leeway < nbf]. *)

open Haltsql_auth
module Config = Haltsql.Config
module Rsa = Mirage_crypto_pk.Rsa
module Zx = Mirage_crypto_pk.Z_extra
module P256 = Mirage_crypto_ec.P256.Dsa
module P384 = Mirage_crypto_ec.P384.Dsa
module Ed = Mirage_crypto_ec.Ed25519
module PSS256 = Rsa.PSS (Digestif.SHA256)
module PSS384 = Rsa.PSS (Digestif.SHA384)

let () = Mirage_crypto_rng_unix.use_default ()

(* ---- table runner ---- *)

type row = string * string * (unit -> string)
(** name, expected outcome, the case *)

let total = ref 0

let run_table (rows : row list) () =
  let failures =
    List.filter_map
      (fun (name, expected, f) ->
        incr total;
        let got = try f () with e -> "EXCEPTION " ^ Printexc.to_string e in
        if got = expected then None
        else Some (Printf.sprintf "  %s: expected %s, got %s" name expected got))
      rows
  in
  let names = List.map (fun (n, _, _) -> n) rows in
  if List.length (List.sort_uniq compare names) <> List.length names then
    Alcotest.fail "duplicate row names";
  if failures <> [] then
    Alcotest.failf "%d of %d cases failed:\n%s" (List.length failures) (List.length rows)
      (String.concat "\n" failures)

let code = function Ok _ -> "ok" | Error e -> Jwt.error_code e
let parsed = function Ok _ -> "ok" | Error (_ : string) -> "error"

(* ---- keys ---- *)

let rsa_priv = Rsa.generate ~bits:2048 ()
let rsa_pub = Rsa.pub_of_priv rsa_priv
let rsa2_priv = Rsa.generate ~bits:2048 ()
let rsa2_pub = Rsa.pub_of_priv rsa2_priv
let p256_priv, p256_pub = P256.generate ()
let p256b_priv, p256b_pub = P256.generate ()
let p384_priv, p384_pub = P384.generate ()
let p384b_priv, _ = P384.generate ()
let ed_priv, ed_pub = Ed.generate ()
let ed2_priv, _ = Ed.generate ()
let jwk ?alg ?(use = Some "sig") kid key = { Jwk.kid = Some kid; alg; use; key }

let keys =
  [
    jwk "rsa" (Jwk.Rsa rsa_pub);
    jwk "p256" (Jwk.P256 p256_pub);
    jwk "p384" (Jwk.P384 p384_pub);
    jwk "ed" (Jwk.Ed25519 ed_pub);
  ]

let all_algs = Config.[ RS256; RS384; RS512; PS256; ES256; ES384; EdDSA ]
let issuer = "https://idp.example.com"
let now = 1_800_000_000.

let provider ?(leeway = 60) () : Config.oidc_provider =
  {
    oidc_name = "corp";
    issuer;
    audiences = [ "haltsql"; "haltsql-alt" ];
    jwks_uri = Some "https://idp.example.com/jwks";
    algorithms = all_algs;
    leeway_seconds = leeway;
    jwks_cache_seconds = 300;
    oidc_policy = Config.Oidc_pinned "shop";
    context_claims = [];
    required_claims = [];
    oidc_request_context_fields = [];
    allow_insecure_http = false;
  }

let verify ?(p = provider ()) ?(at = now) ?(keys = keys) tok =
  code (Oidc.verify p ~keys ~now:at tok)

(* ---- building tokens by hand ---- *)

let b64 = B64url.encode

(* A JSON object from (name, raw JSON text) pairs: duplicates and non-standard number
   literals stay exactly as written. *)
let obj members =
  "{"
  ^ String.concat "," (List.map (fun (k, v) -> Printf.sprintf "%S:%s" k v) members)
  ^ "}"

let q s = Yojson.Safe.to_string (`String s)
let hdr ?(extra = []) alg kid = obj ([ ("alg", q alg); ("kid", q kid) ] @ extra)

let base_claims =
  [
    ("iss", q issuer);
    ("aud", q "haltsql");
    ("sub", q "user-17");
    ("exp", "1800000600");
    ("iat", "1799999990");
  ]

(* Replaces (or adds) members; [("x", None)] removes x. *)
let claims overrides =
  obj
    (List.filter (fun (k, _) -> not (List.mem_assoc k overrides)) base_claims
    @ List.filter_map (fun (k, v) -> Option.map (fun v -> (k, v)) v) overrides)

let payload = obj base_claims
let input header payload = b64 header ^ "." ^ b64 payload
let sha256 s = Digestif.SHA256.(to_raw_string (digest_string s))
let sha384 s = Digestif.SHA384.(to_raw_string (digest_string s))

let pad len s =
  if String.length s >= len then s else String.make (len - String.length s) '\x00' ^ s

let rs ?(key = rsa_priv) hash i = Rsa.PKCS1.sign ~hash ~key (`Message i)
let ps ?(key = rsa_priv) i = PSS256.sign ~key (`Message i)

let es256_rs ?(key = p256_priv) i =
  let r, s = P256.sign ~key (sha256 i) in
  (pad 32 r, pad 32 s)

let es384_rs ?(key = p384_priv) i =
  let r, s = P384.sign ~key (sha384 i) in
  (pad 48 r, pad 48 s)

let cat (r, s) = r ^ s
let ed ?(key = ed_priv) i = Ed.sign ~key i

(* [token header payload signer]: the signature is whatever [signer] makes of the signing
   input, so a header can claim one algorithm while the signature is another. *)
let token ?(payload = payload) header signer =
  let i = input header payload in
  i ^ "." ^ b64 (signer i)

let with_signature ?(payload = payload) header signature =
  input header payload ^ "." ^ b64 signature

(* ---- ECDSA ---- *)

let n256 =
  Z.of_string "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"

let n384 =
  Z.of_string
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"

let der_int s =
  let rec first i =
    if i < String.length s - 1 && s.[i] = '\x00' then first (i + 1) else i
  in
  let i = first 0 in
  let s = String.sub s i (String.length s - i) in
  let s = if Char.code s.[0] >= 0x80 then "\x00" ^ s else s in
  "\x02" ^ String.make 1 (Char.chr (String.length s)) ^ s

let der (r, s) =
  let body = der_int r ^ der_int s in
  "\x30" ^ String.make 1 (Char.chr (String.length body)) ^ body

(* A signature whose r starts with a zero byte, to tell fixed-width from minimal
   encodings apart: about one signature in 256. *)
let leading_zero_r sign header =
  let rec go i =
    if i > 20_000 then Alcotest.fail "no signature with a leading zero byte found"
    else
      let payload = claims [ ("jti", Some (string_of_int i)) ] in
      let r, s = sign (input header payload) in
      if r.[0] = '\x00' then (payload, r, s) else go (i + 1)
  in
  go 0

let ecdsa_rows label ~alg ~kid ~other_alg ~len ~n ~sign ~sign_other : row list =
  let header = hdr alg kid in
  let i = input header payload in
  let r, s = sign i in
  let z = Zx.of_octets_be and be v = Zx.to_octets_be ~size:len v in
  let zero = String.make len '\x00' and ff = String.make len '\xff' in
  let row name expected signature =
    (label ^ ": " ^ name, expected, fun () -> verify (i ^ "." ^ b64 signature))
  in
  let zp, zr, zs = leading_zero_r sign header in
  [
    row "valid" "ok" (r ^ s);
    row "the other s (n - s) is accepted: no low-s rule in JWS" "ok" (r ^ be Z.(n - z s));
    row "r = 0" "bad_signature" (zero ^ s);
    row "s = 0" "bad_signature" (r ^ zero);
    row "r = s = 0" "bad_signature" (zero ^ zero);
    row "r = n" "bad_signature" (be n ^ s);
    row "s = n" "bad_signature" (r ^ be n);
    row "r = n + 1" "bad_signature" (be Z.(n + one) ^ s);
    row "s = n + 1" "bad_signature" (r ^ be Z.(n + one));
    row "r = n - 1" "bad_signature" (be Z.(n - one) ^ s);
    row "s = n - 1" "bad_signature" (r ^ be Z.(n - one));
    row "r = 1, s = 1" "bad_signature" (be Z.one ^ be Z.one);
    row "r = 2^bits - 1" "bad_signature" (ff ^ s);
    row "s = 2^bits - 1" "bad_signature" (r ^ ff);
    row "r and s swapped" "bad_signature" (s ^ r);
    row "r || r" "bad_signature" (r ^ r);
    row "last byte dropped" "bad_signature" (String.sub (r ^ s) 0 ((2 * len) - 1));
    row "first byte dropped" "bad_signature" (String.sub (r ^ s) 1 ((2 * len) - 1));
    row "zero byte appended" "bad_signature" (r ^ s ^ "\x00");
    row "zero byte prepended" "bad_signature" ("\x00" ^ r ^ s);
    row "r only" "bad_signature" r;
    row "r || s || r || s" "bad_signature" (r ^ s ^ r ^ s);
    row "each half padded by one zero byte" "bad_signature" ("\x00" ^ r ^ "\x00" ^ s);
    row "DER SEQUENCE { r, s }" "bad_signature" (der (r, s));
    row "DER of the n - s twin" "bad_signature" (der (r, be Z.(n - z s)));
    row "signature of another message" "bad_signature"
      (cat (sign (input header (claims [ ("sub", Some (q "admin")) ]))));
    row "signature by another key of the curve" "bad_signature" (cat (sign_other i));
    ( label ^ ": r with a leading zero byte, fixed width",
      "ok",
      fun () -> verify (with_signature ~payload:zp header (zr ^ zs)) );
    ( label ^ ": r with a leading zero byte, minimal width",
      "bad_signature",
      fun () ->
        verify (with_signature ~payload:zp header (String.sub zr 1 (len - 1) ^ zs)) );
    (* the curve is bound to the algorithm: this key is never used for the other ES* *)
    ( label ^ ": header says " ^ other_alg,
      "unknown_kid",
      fun () -> verify (token (hdr other_alg kid) (fun i -> cat (sign i))) );
    ( label ^ ": header says RS256",
      "unknown_kid",
      fun () -> verify (token (hdr "RS256" kid) (fun i -> cat (sign i))) );
  ]

let ecdsa_table =
  ecdsa_rows "ES256" ~alg:"ES256" ~kid:"p256" ~other_alg:"ES384" ~len:32 ~n:n256
    ~sign:es256_rs ~sign_other:(es256_rs ~key:p256b_priv)
  @ ecdsa_rows "ES384" ~alg:"ES384" ~kid:"p384" ~other_alg:"ES256" ~len:48 ~n:n384
      ~sign:es384_rs ~sign_other:(es384_rs ~key:p384b_priv)

(* [Jwt.verify_signature] directly: the curve and the key type must match the algorithm,
   whatever the signature is. *)
let key_binding_table : row list =
  let i = input (hdr "ES256" "p256") payload in
  let signatures =
    [
      ("RS256", rs `SHA256 i);
      ("PS256", ps i);
      ("ES256", cat (es256_rs i));
      ("ES384", cat (es384_rs i));
      ("EdDSA", ed i);
      ("empty", "");
    ]
  in
  let key_name = function
    | Jwk.Rsa _ -> "RSA"
    | P256 _ -> "P-256"
    | P384 _ -> "P-384"
    | Ed25519 _ -> "Ed25519"
  in
  List.concat_map
    (fun (k : Jwk.t) ->
      List.concat_map
        (fun alg ->
          List.map
            (fun (made_as, signature) ->
              let a = Config.string_of_jwt_alg alg in
              let expected =
                match (k.key, a, made_as) with
                | Jwk.Rsa _, "RS256", "RS256"
                | Jwk.Rsa _, "PS256", "PS256"
                | Jwk.P256 _, "ES256", "ES256"
                | Jwk.P384 _, "ES384", "ES384"
                | Jwk.Ed25519 _, "EdDSA", "EdDSA" ->
                    "true"
                | _ -> "false"
              in
              ( Printf.sprintf "%s signature, verified as %s with the %s key" made_as a
                  (key_name k.key),
                expected,
                fun () ->
                  string_of_bool
                    (Jwt.verify_signature alg k.key ~signing_input:i ~signature) ))
            signatures)
        all_algs)
    keys

(* ---- RSA signatures ---- *)

let digest_info_sha256 =
  "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"

(* The raw RSA private operation on a chosen encoded message, to produce signatures
   whose padding no honest signer would emit. *)
let raw_sign em =
  if String.length em <> 256 then failwith "encoded message length";
  Rsa.decrypt ~key:rsa_priv em

let rsa_table : row list =
  let h256 = hdr "RS256" "rsa" in
  let i = input h256 payload in
  let sg = rs `SHA256 i in
  let n = rsa_pub.n in
  let be v = Zx.to_octets_be ~size:256 v in
  let row name expected signature =
    ("RS256: " ^ name, expected, fun () -> verify (i ^ "." ^ b64 signature))
  in
  let labelled name expected alg signer =
    (name, expected, fun () -> verify (token (hdr alg "rsa") signer))
  in
  let digest = sha256 i in
  let em ?(bt = "\x01") ?(ps = fun n -> String.make n '\xff') ?(sep = "\x00") ?(tail = "")
      t =
    let n = 256 - 2 - String.length sep - String.length t - String.length tail in
    "\x00" ^ bt ^ ps n ^ sep ^ t ^ tail
  in
  let crafted name expected e = row ("crafted padding: " ^ name) expected (raw_sign e) in
  let zp, zsig =
    let rec go k =
      if k > 20_000 then Alcotest.fail "no RSA signature with a leading zero byte found"
      else
        let p = claims [ ("jti", Some (string_of_int k)) ] in
        let s = rs `SHA256 (input h256 p) in
        if s.[0] = '\x00' then (p, s) else go (k + 1)
    in
    go 0
  in
  [
    row "valid" "ok" sg;
    labelled "RS384: valid" "ok" "RS384" (rs `SHA384);
    labelled "RS512: valid" "ok" "RS512" (rs `SHA512);
    labelled "PS256: valid" "ok" "PS256" ps;
    (* scheme and hash are bound to the header *)
    labelled "PKCS1 v1.5 signature presented as PS256" "bad_signature" "PS256"
      (rs `SHA256);
    labelled "PSS signature presented as RS256" "bad_signature" "RS256" ps;
    labelled "SHA-256 signature presented as RS384" "bad_signature" "RS384" (rs `SHA256);
    labelled "SHA-256 signature presented as RS512" "bad_signature" "RS512" (rs `SHA256);
    labelled "SHA-384 signature presented as RS256" "bad_signature" "RS256" (rs `SHA384);
    labelled "SHA-512 signature presented as RS256" "bad_signature" "RS256" (rs `SHA512);
    labelled "SHA-1 signature presented as RS256" "bad_signature" "RS256" (rs `SHA1);
    labelled "MD5 signature presented as RS256" "bad_signature" "RS256" (rs `MD5);
    labelled "PS256 with an empty salt" "bad_signature" "PS256" (fun i ->
        PSS256.sign ~slen:0 ~key:rsa_priv (`Message i));
    labelled "PS256 with a 20-byte salt" "bad_signature" "PS256" (fun i ->
        PSS256.sign ~slen:20 ~key:rsa_priv (`Message i));
    labelled "PS256 with a 33-byte salt" "bad_signature" "PS256" (fun i ->
        PSS256.sign ~slen:33 ~key:rsa_priv (`Message i));
    labelled "PSS-SHA384 presented as PS256" "bad_signature" "PS256" (fun i ->
        PSS384.sign ~key:rsa_priv (`Message i));
    labelled "PS384 is not an accepted algorithm" "alg_not_allowed" "PS384" (fun i ->
        PSS384.sign ~key:rsa_priv (`Message i));
    labelled "PS512 is not an accepted algorithm" "alg_not_allowed" "PS512" ps;
    labelled "RS256 signed by another RSA key" "bad_signature" "RS256"
      (rs ~key:rsa2_priv `SHA256);
    labelled "PS256 signed by another RSA key" "bad_signature" "PS256" (ps ~key:rsa2_priv);
    (* the signature is exactly as long as the modulus *)
    row "first byte dropped" "bad_signature" (String.sub sg 1 255);
    row "last byte dropped" "bad_signature" (String.sub sg 0 255);
    row "zero byte prepended" "bad_signature" ("\x00" ^ sg);
    row "zero byte appended" "bad_signature" (sg ^ "\x00");
    row "signature twice" "bad_signature" (sg ^ sg);
    row "one byte" "bad_signature" "\x01";
    ( "RS256: leading zero byte kept",
      "ok",
      fun () -> verify (with_signature ~payload:zp h256 zsig) );
    ( "RS256: leading zero byte stripped",
      "bad_signature",
      fun () -> verify (with_signature ~payload:zp h256 (String.sub zsig 1 255)) );
    ( "PS256: signature one byte short",
      "bad_signature",
      fun () ->
        let h = hdr "PS256" "rsa" in
        let i = input h payload in
        verify (i ^ "." ^ b64 (String.sub (ps i) 1 255)) );
    ( "PS256: zero byte prepended",
      "bad_signature",
      fun () ->
        let h = hdr "PS256" "rsa" in
        let i = input h payload in
        verify (i ^ "." ^ b64 ("\x00" ^ ps i)) );
    (* the signature is a number below the modulus *)
    row "signature = 0" "bad_signature" (be Z.zero);
    row "signature = 1" "bad_signature" (be Z.one);
    row "signature = n - 1" "bad_signature" (be Z.(n - one));
    row "signature = n" "bad_signature" (be n);
    row "signature = n + 1" "bad_signature" (be Z.(n + one));
    row "signature + n (257 bytes)" "bad_signature"
      (Zx.to_octets_be ~size:257 Z.(Zx.of_octets_be sg + n));
    row "all ones" "bad_signature" (String.make 256 '\xff');
    (* EMSA-PKCS1-v1_5 must be exact: 00 01 FF..FF 00 DigestInfo *)
    crafted "the correct encoding (control)" "ok" (em (digest_info_sha256 ^ digest));
    crafted "block type 02" "bad_signature" (em ~bt:"\x02" (digest_info_sha256 ^ digest));
    crafted "block type 00" "bad_signature" (em ~bt:"\x00" (digest_info_sha256 ^ digest));
    crafted "one padding byte is not FF" "bad_signature"
      (em
         ~ps:(fun n -> String.make (n - 1) '\xff' ^ "\xfe")
         (digest_info_sha256 ^ digest));
    crafted "a zero byte inside the padding" "bad_signature"
      (em
         ~ps:(fun n -> String.make 8 '\xff' ^ "\x00" ^ String.make (n - 9) '\xff')
         (digest_info_sha256 ^ digest));
    crafted "no 00 separator" "bad_signature" (em ~sep:"" (digest_info_sha256 ^ digest));
    crafted "short padding, garbage after the digest" "bad_signature"
      (em ~tail:(String.make 190 '\x5a') (digest_info_sha256 ^ digest));
    crafted "one garbage byte after the digest" "bad_signature"
      (em ~tail:"\x00" (digest_info_sha256 ^ digest));
    crafted "bare digest without DigestInfo" "bad_signature" (em digest);
    crafted "DigestInfo without the NULL parameters" "bad_signature"
      (em
         ("\x30\x2f\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x04\x20" ^ digest));
    crafted "DigestInfo with a long-form length" "bad_signature"
      (em
         ("\x30\x81\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
        ^ digest));
    crafted "DigestInfo naming SHA-384 around a SHA-256 digest" "bad_signature"
      (em
         ("\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x20"
        ^ digest));
    crafted "digest of another message" "bad_signature"
      (em (digest_info_sha256 ^ sha256 (i ^ "x")));
  ]

(* ---- RSA public keys ---- *)

let rsa_jwk ?(extra = []) ~n ~e () =
  obj ([ ("kty", q "RSA"); ("n", q (b64 n)); ("e", q (b64 e)) ] @ extra)

let of_string s =
  match Yojson.Safe.from_string s with j -> Jwk.of_json j | exception _ -> Error "json"

let rsa_key_table : row list =
  let n = rsa_pub.n in
  let nb = Zx.to_octets_be n in
  let zb v = Zx.to_octets_be v in
  let e65537 = "\x01\x00\x01" in
  let exp name expected e =
    ("RSA exponent: " ^ name, expected, fun () -> parsed (of_string (rsa_jwk ~n:nb ~e ())))
  in
  let modulus name expected n =
    ( "RSA modulus: " ^ name,
      expected,
      fun () -> parsed (of_string (rsa_jwk ~n:(zb n) ~e:e65537 ())) )
  in
  (* any odd number of the right size will do for a parse-level size check *)
  let odd bits = Z.(shift_left one (Stdlib.( - ) bits 1) + one) in
  let small bits = (Rsa.pub_of_priv (Rsa.generate ~bits ())).n in
  [
    exp "65537" "ok" e65537;
    exp "65537 with a leading zero byte" "ok" ("\x00" ^ e65537);
    exp "3" "ok" "\x03";
    exp "17" "ok" "\x11";
    exp "0" "error" "\x00";
    exp "1" "error" "\x01";
    exp "2" "error" "\x02";
    exp "4" "error" "\x04";
    exp "65536" "error" "\x01\x00\x00";
    exp "65538" "error" "\x01\x00\x02";
    exp "n" "error" nb;
    exp "n + 2" "error" (zb Z.(n + of_int 2));
    exp "n - 1 (even)" "error" (zb Z.(n - one));
    ( "RSA exponent: empty",
      "error",
      fun () ->
        parsed (of_string (obj [ ("kty", q "RSA"); ("n", q (b64 nb)); ("e", q "") ])) );
    ( "RSA exponent: missing",
      "error",
      fun () -> parsed (of_string (obj [ ("kty", q "RSA"); ("n", q (b64 nb)) ])) );
    ( "RSA exponent: a JSON number",
      "error",
      fun () ->
        parsed (of_string (obj [ ("kty", q "RSA"); ("n", q (b64 nb)); ("e", "65537") ]))
    );
    modulus "2048 bits" "ok" n;
    modulus "2048 bits, synthetic" "ok" (odd 2048);
    modulus "2047 bits, synthetic" "error" (odd 2047);
    modulus "2047 bits, a real key" "error" (small 2047);
    modulus "1024 bits, a real key" "error" (small 1024);
    modulus "512 bits" "error" (odd 512);
    modulus "4096 bits" "ok" (odd 4096);
    modulus "8192 bits" "ok" (odd 8192);
    modulus "8193 bits" "error" (odd 8193);
    modulus "16384 bits" "error" (odd 16384);
    modulus "even" "error" Z.(n + one);
    modulus "1" "error" Z.one;
    ( "RSA modulus: zero",
      "error",
      fun () -> parsed (of_string (rsa_jwk ~n:"\x00" ~e:e65537 ())) );
    ( "RSA modulus: leading zero byte (same key)",
      "true",
      fun () ->
        match of_string (rsa_jwk ~n:("\x00" ^ nb) ~e:e65537 ()) with
        | Ok { key = Jwk.Rsa k; _ } -> string_of_bool (Z.equal k.n n)
        | _ -> "error" );
    ( "RSA modulus: missing",
      "error",
      fun () -> parsed (of_string (obj [ ("kty", q "RSA"); ("e", q "AQAB") ])) );
    ( "RSA modulus: padded base64",
      "error",
      fun () ->
        parsed
          (of_string
             (obj [ ("kty", q "RSA"); ("n", q (b64 nb ^ "==")); ("e", q "AQAB") ])) );
    ( "RSA modulus: standard base64 alphabet",
      "error",
      fun () ->
        parsed
          (of_string
             (obj
                [
                  ("kty", q "RSA");
                  ( "n",
                    q
                      (String.map
                         (function '-' -> '+' | '_' -> '/' | c -> c)
                         (b64 (String.make 256 '\xff'))) );
                  ("e", q "AQAB");
                ])) );
  ]

(* ---- EdDSA ---- *)

let ed_l =
  Z.of_string "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"

let unhex h =
  String.init
    (String.length h / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub h (2 * i) 2)))

(* little-endian 32 bytes *)
let le32 v =
  let b = Z.to_bits v in
  if String.length b >= 32 then String.sub b 0 32
  else b ^ String.make (32 - String.length b) '\x00'

(* Encodings of the points of small order (order 1, 2, 4, 8): the seven encodings with
   the sign bit clear, then the same with it set. *)
let ed_small_order =
  let base =
    [
      "0000000000000000000000000000000000000000000000000000000000000000";
      "0100000000000000000000000000000000000000000000000000000000000000";
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05";
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a";
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
      "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
    ]
  in
  let set_sign h =
    String.sub h 0 62
    ^ Printf.sprintf "%02x" (int_of_string ("0x" ^ String.sub h 62 2) lor 0x80)
  in
  base @ List.map set_sign base

let okp x =
  obj [ ("kty", q "OKP"); ("crv", q "Ed25519"); ("x", q (b64 x)); ("kid", q "ed") ]

let eddsa_table : row list =
  if
    Z.to_string ed_l
    <> "7237005577332262213973186563042994240857116359379907606001950938285454250989"
  then failwith "group order L";
  let header = hdr "EdDSA" "ed" in
  let i = input header payload in
  let sg = ed i in
  let r = String.sub sg 0 32 and s = String.sub sg 32 32 in
  let zs = Z.of_bits s in
  let row name expected signature =
    ("EdDSA: " ^ name, expected, fun () -> verify (i ^ "." ^ b64 signature))
  in
  let identity = unhex (List.nth ed_small_order 1) in
  [
    row "valid" "ok" sg;
    row "S + L (non-canonical S)" "bad_signature" (r ^ le32 Z.(zs + ed_l));
    row "S + 2L" "bad_signature" (r ^ le32 Z.(zs + ed_l + ed_l));
    row "S = L" "bad_signature" (r ^ le32 ed_l);
    row "S = 0" "bad_signature" (r ^ le32 Z.zero);
    row "S = L - 1" "bad_signature" (r ^ le32 Z.(ed_l - one));
    row "S with the top bit set" "bad_signature"
      (r
      ^ String.mapi (fun k c -> if k = 31 then Char.chr (Char.code c lor 0x80) else c) s);
    row "S = 2^256 - 1" "bad_signature" (r ^ String.make 32 '\xff');
    row "R is the identity, S = 0" "bad_signature" (identity ^ le32 Z.zero);
    row "all zero" "bad_signature" (String.make 64 '\x00');
    row "R and S swapped" "bad_signature" (s ^ r);
    row "last byte dropped" "bad_signature" (String.sub sg 0 63);
    row "first byte dropped" "bad_signature" (String.sub sg 1 63);
    row "zero byte appended" "bad_signature" (sg ^ "\x00");
    row "R only" "bad_signature" r;
    row "signature twice" "bad_signature" (sg ^ sg);
    row "signature of another message" "bad_signature" (ed (i ^ "x"));
    row "signature by another key" "bad_signature" (ed ~key:ed2_priv i);
    ( "EdDSA: header says ES256",
      "unknown_kid",
      fun () -> verify (token (hdr "ES256" "ed") ed) );
    ( "EdDSA: lower-case alg",
      "alg_not_allowed",
      fun () -> verify (token (hdr "eddsa" "ed") ed) );
    ( "EdDSA: alg Ed25519",
      "alg_not_allowed",
      fun () -> verify (token (hdr "Ed25519" "ed") ed) );
    ( "Ed25519 key: valid",
      "ok",
      fun () -> parsed (of_string (okp (Ed.pub_to_octets ed_pub))) );
    ( "Ed25519 key: 31 bytes",
      "error",
      fun () -> parsed (of_string (okp (String.sub (Ed.pub_to_octets ed_pub) 0 31))) );
    ( "Ed25519 key: 33 bytes",
      "error",
      fun () -> parsed (of_string (okp (Ed.pub_to_octets ed_pub ^ "\x00"))) );
    ( "OKP key: crv Ed448",
      "error",
      fun () ->
        parsed
          (of_string
             (obj
                [
                  ("kty", q "OKP");
                  ("crv", q "Ed448");
                  ("x", q (b64 (String.make 57 '\x01')));
                ])) );
    ( "OKP key: crv X25519",
      "error",
      fun () ->
        parsed
          (of_string
             (obj
                [
                  ("kty", q "OKP");
                  ("crv", q "X25519");
                  ("x", q (b64 (Ed.pub_to_octets ed_pub)));
                ])) );
    ( "OKP key: no crv",
      "error",
      fun () ->
        parsed
          (of_string (obj [ ("kty", q "OKP"); ("x", q (b64 (Ed.pub_to_octets ed_pub))) ]))
    );
  ]
  @ List.concat_map
      (fun h ->
        let x = unhex h in
        let name = String.sub h 0 8 ^ ".." ^ String.sub h 56 8 in
        [
          ( "Ed25519 key of small order " ^ name ^ ": refused by the JWK parser",
            "error",
            fun () -> parsed (of_string (okp x)) );
          (* what the refusal prevents: with such a key, one fixed signature verifies
             for every message (identity) or for many messages (orders 2, 4, 8) *)
          ( "Ed25519 key of small order " ^ name ^ ": a forged token is not accepted",
            "unknown_kid",
            fun () ->
              let keys =
                match Jwk.set_of_string (obj [ ("keys", "[" ^ okp x ^ "]") ]) with
                | Ok (ks, _) -> ks
                | Error _ -> []
              in
              verify ~keys (with_signature header (identity ^ le32 Z.zero)) );
        ])
      ed_small_order

(* ---- EC public keys ---- *)

let ec_jwk ?(crv = "P-256") ?(extra = []) x y =
  obj ([ ("kty", q "EC"); ("crv", q crv); ("x", q (b64 x)); ("y", q (b64 y)) ] @ extra)

let ec_key_table : row list =
  let o = P256.pub_to_octets p256_pub in
  let x = String.sub o 1 32 and y = String.sub o 33 32 in
  let o384 = P384.pub_to_octets p384_pub in
  let x384 = String.sub o384 1 48 and y384 = String.sub o384 49 48 in
  let p256_p =
    Z.of_string "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
  in
  let be v = Zx.to_octets_be ~size:32 v in
  let row name expected j =
    ("EC key: " ^ name, expected, fun () -> parsed (of_string j))
  in
  let flip s =
    String.mapi
      (fun i c -> if i = String.length s - 1 then Char.chr (Char.code c lxor 1) else c)
      s
  in
  [
    row "P-256" "ok" (ec_jwk x y);
    row "P-384" "ok" (ec_jwk ~crv:"P-384" x384 y384);
    row "y off the curve" "error" (ec_jwk x (flip y));
    row "x off the curve" "error" (ec_jwk (flip x) y);
    row "x = y = 0" "error" (ec_jwk (be Z.zero) (be Z.zero));
    row "x = p" "error" (ec_jwk (be p256_p) y);
    row "x = p + 1" "error" (ec_jwk (be Z.(p256_p + one)) y);
    row "y = p" "error" (ec_jwk x (be p256_p));
    row "x one byte short" "error" (ec_jwk (String.sub x 1 31) y);
    row "y one byte long" "error" (ec_jwk x ("\x00" ^ y));
    row "P-256 coordinates labelled P-384" "error" (ec_jwk ~crv:"P-384" x y);
    row "P-384 coordinates labelled P-256" "error" (ec_jwk x384 y384);
    row "crv P-521" "error"
      (ec_jwk ~crv:"P-521" (String.make 66 '\x01') (String.make 66 '\x01'));
    row "crv secp256k1" "error" (ec_jwk ~crv:"secp256k1" x y);
    row "crv p-256 (case)" "error" (ec_jwk ~crv:"p-256" x y);
    row "crv missing" "error"
      (obj [ ("kty", q "EC"); ("x", q (b64 x)); ("y", q (b64 y)) ]);
    row "y missing" "error"
      (obj [ ("kty", q "EC"); ("crv", q "P-256"); ("x", q (b64 x)) ]);
    row "private member d" "error"
      (ec_jwk ~extra:[ ("d", q (b64 (String.make 32 '\x01'))) ] x y);
    row "kty ec (case)" "error"
      (obj [ ("kty", q "ec"); ("crv", q "P-256"); ("x", q (b64 x)); ("y", q (b64 y)) ]);
  ]

(* ---- JWK members and JWK Sets ---- *)

let rsa_n = b64 (Zx.to_octets_be rsa_pub.n)
let rsa2_n = b64 (Zx.to_octets_be rsa2_pub.n)

let rsa_members ?(n = rsa_n) extra =
  [ ("kty", q "RSA"); ("n", q n); ("e", q "AQAB") ] @ extra

let jwk_table : row list =
  let row name expected members =
    ("JWK: " ^ name, expected, fun () -> parsed (of_string (obj members)))
  in
  let secret = q (b64 "0123456789abcdef0123456789abcdef") in
  [
    row "public RSA key" "ok" (rsa_members []);
    row "unknown members are ignored" "ok"
      (rsa_members [ ("x5t", q "abc"); ("ext", "true") ]);
    row "kty oct" "error" [ ("kty", q "oct"); ("k", secret) ];
    row "kty oct without k" "error" [ ("kty", q "oct") ];
    row "kty oct with alg RS256" "error"
      [ ("kty", q "oct"); ("k", secret); ("alg", q "RS256") ];
    row "kty oct with RSA members" "error" (("kty", q "oct") :: List.tl (rsa_members []));
    row "RSA key with a symmetric k" "error" (rsa_members [ ("k", secret) ]);
    row "kty missing" "error" (List.tl (rsa_members []));
    row "kty rsa (case)" "error" (("kty", q "rsa") :: List.tl (rsa_members []));
    row "kty a number" "error" (("kty", "1") :: List.tl (rsa_members []));
    row "kty null" "error" (("kty", "null") :: List.tl (rsa_members []));
    row "kid a number" "error" (rsa_members [ ("kid", "7") ]);
    row "use a number" "error" (rsa_members [ ("use", "1") ]);
    row "alg an array" "error" (rsa_members [ ("alg", "[\"RS256\"]") ]);
    row "key_ops [verify]" "ok" (rsa_members [ ("key_ops", "[\"verify\"]") ]);
    row "key_ops [sign, verify]" "ok"
      (rsa_members [ ("key_ops", "[\"sign\",\"verify\"]") ]);
    row "key_ops [sign]" "error" (rsa_members [ ("key_ops", "[\"sign\"]") ]);
    row "key_ops [encrypt, wrapKey]" "error"
      (rsa_members [ ("key_ops", "[\"encrypt\",\"wrapKey\"]") ]);
    row "key_ops []" "error" (rsa_members [ ("key_ops", "[]") ]);
    row "key_ops [VERIFY]" "error" (rsa_members [ ("key_ops", "[\"VERIFY\"]") ]);
    row "key_ops a string" "error" (rsa_members [ ("key_ops", q "verify") ]);
    row "key_ops [verify, 1]" "error" (rsa_members [ ("key_ops", "[\"verify\",1]") ]);
    row "key_ops null" "error" (rsa_members [ ("key_ops", "null") ]);
    row "duplicate n" "error" (rsa_members [ ("n", q rsa2_n) ]);
    row "duplicate kty (RSA, oct)" "error" (rsa_members [ ("kty", q "oct") ]);
    row "duplicate kty (oct, RSA)" "error" (("kty", q "oct") :: rsa_members []);
    row "duplicate use" "error" (rsa_members [ ("use", q "enc"); ("use", q "sig") ]);
    row "duplicate kid" "error" (rsa_members [ ("kid", q "a"); ("kid", q "b") ]);
    row "duplicate unknown member" "error" (rsa_members [ ("zz", "1"); ("zz", "1") ]);
  ]
  @ List.map
      (fun m -> row ("private member " ^ m) "error" (rsa_members [ (m, q "AQAB") ]))
      [ "d"; "p"; "q"; "dp"; "dq"; "qi"; "oth"; "k" ]
  @ [
      ("JWK: a JSON array", "error", fun () -> parsed (of_string "[]"));
      ("JWK: a JSON string", "error", fun () -> parsed (of_string "\"RSA\""));
      ("JWK: null", "error", fun () -> parsed (of_string "null"));
    ]

let set_table : row list =
  let k members = obj members in
  let set name expected s =
    ( "JWK Set: " ^ name,
      expected,
      fun () ->
        match Jwk.set_of_string s with
        | Ok (ks, bad) ->
            Printf.sprintf "%d usable, %d skipped" (List.length ks) (List.length bad)
        | Error _ -> "error" )
  in
  let good = k (rsa_members [ ("kid", q "a") ]) in
  [
    set "one key" "1 usable, 0 skipped" (obj [ ("keys", "[" ^ good ^ "]") ]);
    set "no keys" "0 usable, 0 skipped" (obj [ ("keys", "[]") ]);
    set "an oct key is skipped" "1 usable, 1 skipped"
      (obj
         [
           ("keys", "[" ^ k [ ("kty", q "oct"); ("k", q "c2VjcmV0") ] ^ "," ^ good ^ "]");
         ]);
    set "non-object entries are skipped" "1 usable, 4 skipped"
      (obj [ ("keys", "[1,null,\"x\",[]," ^ good ^ "]") ]);
    set "a private key is skipped" "0 usable, 1 skipped"
      (obj [ ("keys", "[" ^ k (rsa_members [ ("d", q "AQAB") ]) ^ "]") ]);
    set "a key with duplicate members is skipped" "1 usable, 1 skipped"
      (obj [ ("keys", "[" ^ k (rsa_members [ ("e", q "AQAB") ]) ^ "," ^ good ^ "]") ]);
    set "duplicate keys member" "error"
      (obj [ ("keys", "[]"); ("keys", "[" ^ good ^ "]") ]);
    set "keys is an object" "error" (obj [ ("keys", good) ]);
    set "keys is null" "error" (obj [ ("keys", "null") ]);
    set "keys missing" "error" "{}";
    set "a bare array" "error" ("[" ^ good ^ "]");
    set "a bare key" "error" good;
    set "not JSON" "error" "<html>";
    set "empty" "error" "";
    set "trailing garbage" "error" (obj [ ("keys", "[]") ] ^ "x");
    set "truncated" "error" "{\"keys\":[";
    set "NaN as a key" "0 usable, 1 skipped" "{\"keys\":[NaN]}";
    set "NaN as the key list" "error" "{\"keys\":NaN}";
    set "deeply nested" "error" (String.make 100_000 '[');
  ]

(* Which key verifies: [use], [key_ops], [alg] and duplicate [kid]s. The token is RS256,
   kid "k", signed by [rsa_priv] unless the row says otherwise. *)
let selection_table : row list =
  let k ?(n = rsa_n) ?(kid = Some "k") extra =
    obj
      (rsa_members ~n
         ((match kid with Some i -> [ ("kid", q i) ] | None -> []) @ extra))
  in
  let ec =
    let o = P256.pub_to_octets p256_pub in
    ec_jwk ~extra:[ ("kid", q "k") ] (String.sub o 1 32) (String.sub o 33 32)
  in
  let jwks ks =
    match Jwk.set_of_string (obj [ ("keys", "[" ^ String.concat "," ks ^ "]") ]) with
    | Ok (ks, _) -> ks
    | Error e -> Alcotest.fail e
  in
  let tok ?(alg = "RS256") ?(signer = rs `SHA256) () = token (hdr alg "k") signer in
  let row name expected ?alg ?signer ks =
    ( "selection: " ^ name,
      expected,
      fun () -> verify ~keys:(jwks ks) (tok ?alg ?signer ()) )
  in
  let by2 = rs ~key:rsa2_priv `SHA256 in
  [
    row "no use, no alg" "ok" [ k [] ];
    row "use sig" "ok" [ k [ ("use", q "sig") ] ];
    row "use enc" "unknown_kid" [ k [ ("use", q "enc") ] ];
    row "use SIG (case)" "unknown_kid" [ k [ ("use", q "SIG") ] ];
    row "use empty" "unknown_kid" [ k [ ("use", q "") ] ];
    row "key_ops [verify]" "ok" [ k [ ("key_ops", "[\"verify\"]") ] ];
    row "key_ops [sign]" "unknown_kid" [ k [ ("key_ops", "[\"sign\"]") ] ];
    row "key_ops [encrypt]" "unknown_kid" [ k [ ("key_ops", "[\"encrypt\"]") ] ];
    row "key_ops []" "unknown_kid" [ k [ ("key_ops", "[]") ] ];
    row "use enc with key_ops [verify]" "unknown_kid"
      [ k [ ("use", q "enc"); ("key_ops", "[\"verify\"]") ] ];
    row "use sig with key_ops [sign]" "unknown_kid"
      [ k [ ("use", q "sig"); ("key_ops", "[\"sign\"]") ] ];
    row "JWK alg RS256" "ok" [ k [ ("alg", q "RS256") ] ];
    row "JWK alg PS256, token RS256" "unknown_kid" [ k [ ("alg", q "PS256") ] ];
    row "JWK alg RS384, token RS256" "unknown_kid" [ k [ ("alg", q "RS384") ] ];
    row "JWK alg RS256, token PS256" "unknown_kid" ~alg:"PS256" ~signer:ps
      [ k [ ("alg", q "RS256") ] ];
    row "JWK alg HS256" "unknown_kid" [ k [ ("alg", q "HS256") ] ];
    row "JWK alg none" "unknown_kid" [ k [ ("alg", q "none") ] ];
    row "JWK alg rs256 (case)" "unknown_kid" [ k [ ("alg", q "rs256") ] ];
    row "JWK alg ES256 on an RSA key" "unknown_kid" [ k [ ("alg", q "ES256") ] ];
    row "JWK without kid" "unknown_kid" [ k ~kid:None [] ];
    row "JWK with another kid" "unknown_kid" [ k ~kid:(Some "K") [] ];
    row "JWK with duplicate members" "unknown_kid" [ k [ ("e", q "AQAB") ] ];
    row "JWK with a private member" "unknown_kid" [ k [ ("d", q "AQAB") ] ];
    (* duplicate kid: the first compatible key, in document order, and only that one *)
    row "duplicate kid, signed by the first" "ok" [ k []; k ~n:rsa2_n [] ];
    row "duplicate kid, signed by the second" "bad_signature" ~signer:by2
      [ k []; k ~n:rsa2_n [] ];
    row "duplicate kid reversed, signed by the first" "ok" ~signer:by2
      [ k ~n:rsa2_n []; k [] ];
    row "duplicate kid reversed, signed by the second" "bad_signature"
      [ k ~n:rsa2_n []; k [] ];
    row "duplicate kid, the first is use enc" "ok" ~signer:by2
      [ k [ ("use", q "enc") ]; k ~n:rsa2_n [] ];
    row "duplicate kid, the first is use enc, signed by it" "bad_signature"
      [ k [ ("use", q "enc") ]; k ~n:rsa2_n [] ];
    row "duplicate kid, the first is for PS256" "ok" ~signer:by2
      [ k [ ("alg", q "PS256") ]; k ~n:rsa2_n [] ];
    row "duplicate kid across key types, RS256" "ok" [ ec; k [] ];
    row "duplicate kid across key types, ES256" "ok" ~alg:"ES256"
      ~signer:(fun i -> cat (es256_rs i))
      [ k []; ec ];
    row "the same key twice" "ok" [ k []; k [] ];
    (* symmetric keys *)
    row "oct key, HS256 token made with it" "alg_not_allowed" ~alg:"HS256"
      ~signer:(fun i -> Digestif.SHA256.(to_raw_string (hmac_string ~key:"secret" i)))
      [ obj [ ("kty", q "oct"); ("kid", q "k"); ("k", q (b64 "secret")) ] ];
    row "oct key, RS256 token" "unknown_kid"
      [ obj [ ("kty", q "oct"); ("kid", q "k"); ("k", q (b64 "secret")) ] ];
    row "oct key labelled RS256, HMAC presented as RS256" "unknown_kid"
      ~signer:(fun i -> Digestif.SHA256.(to_raw_string (hmac_string ~key:"secret" i)))
      [
        obj
          [
            ("kty", q "oct"); ("kid", q "k"); ("alg", q "RS256"); ("k", q (b64 "secret"));
          ];
      ];
    row "empty key set" "unknown_kid" [];
  ]

(* ---- headers ---- *)

let attacker_rsa = Yojson.Safe.to_string (Jwk.to_json (jwk "rsa" (Jwk.Rsa rsa2_pub)))
let attacker_ec = Yojson.Safe.to_string (Jwk.to_json (jwk "p256" (Jwk.P256 p256b_pub)))
let by_attacker = rs ~key:rsa2_priv `SHA256
let by_owner = rs `SHA256

let header_table : row list =
  let row name expected ?(signer = by_owner) header =
    ("header: " ^ name, expected, fun () -> verify (token header signer))
  in
  (* the complete header, alg and kid as raw JSON *)
  let h ?(alg = q "RS256") ?(kid = q "rsa") extra =
    obj ([ ("alg", alg); ("kid", kid) ] @ extra)
  in
  let hmac key i = Digestif.SHA256.(to_raw_string (hmac_string ~key i)) in
  let pub_json = Yojson.Safe.to_string (Jwk.to_json (jwk "rsa" (Jwk.Rsa rsa_pub))) in
  [
    row "plain RS256" "ok" (h []);
    (* alg *)
    row "alg none" "alg_not_allowed" (h ~alg:(q "none") []);
    row "alg None" "alg_not_allowed" (h ~alg:(q "None") []);
    row "alg NONE" "alg_not_allowed" (h ~alg:(q "NONE") []);
    row "alg nOnE" "alg_not_allowed" (h ~alg:(q "nOnE") []);
    row "alg none with a space" "alg_not_allowed" (h ~alg:(q "none ") []);
    row "alg empty" "alg_not_allowed" (h ~alg:(q "") []);
    ( "header: alg none, empty signature",
      "malformed",
      fun () -> verify (input (h ~alg:(q "none") []) payload ^ ".") );
    ( "header: alg none, no kid, empty signature",
      "malformed",
      fun () -> verify (input (obj [ ("alg", q "none") ]) payload ^ ".") );
    ( "header: alg none, two segments",
      "malformed",
      fun () -> verify (input (obj [ ("alg", q "none") ]) payload) );
    row "alg HS256, RSA signature" "alg_not_allowed" (h ~alg:(q "HS256") []);
    row "alg HS256, HMAC keyed with the public modulus" "alg_not_allowed"
      ~signer:(hmac (Zx.to_octets_be rsa_pub.n))
      (h ~alg:(q "HS256") []);
    row "alg HS256, HMAC keyed with the public JWK text" "alg_not_allowed"
      ~signer:(hmac pub_json)
      (h ~alg:(q "HS256") []);
    row "alg HS384" "alg_not_allowed" (h ~alg:(q "HS384") []);
    row "alg HS512" "alg_not_allowed" (h ~alg:(q "HS512") []);
    row "alg rs256" "alg_not_allowed" (h ~alg:(q "rs256") []);
    row "alg Rs256" "alg_not_allowed" (h ~alg:(q "Rs256") []);
    row "alg RS256 with a trailing space" "alg_not_allowed" (h ~alg:(q "RS256 ") []);
    row "alg RS256 with a trailing NUL" "alg_not_allowed" (h ~alg:"\"RS256\\u0000\"" []);
    row "alg RS1" "alg_not_allowed" (h ~alg:(q "RS1") []);
    row "alg ES256K" "alg_not_allowed" (h ~alg:(q "ES256K") []);
    row "alg ES512" "alg_not_allowed" (h ~alg:(q "ES512") []);
    row "alg RSA-OAEP" "alg_not_allowed" (h ~alg:(q "RSA-OAEP") []);
    row "alg dir" "alg_not_allowed" (h ~alg:(q "dir") []);
    row "alg a number" "malformed" (h ~alg:"256" []);
    row "alg null" "malformed" (h ~alg:"null" []);
    row "alg an array" "malformed" (h ~alg:"[\"RS256\"]" []);
    row "alg an object" "malformed" (h ~alg:"{\"RS256\":1}" []);
    row "alg true" "malformed" (h ~alg:"true" []);
    row "alg missing" "malformed" (obj [ ("kid", q "rsa") ]);
    row "alg twice (RS256, none)" "malformed" (h [ ("alg", q "none") ]);
    row "alg twice (none, RS256)" "malformed" (h ~alg:(q "none") [ ("alg", q "RS256") ]);
    row "alg twice, identical" "malformed" (h [ ("alg", q "RS256") ]);
    row "kid twice" "malformed" (h [ ("kid", q "rsa") ]);
    (* kid *)
    row "kid missing" "missing_kid" (obj [ ("alg", q "RS256") ]);
    row "kid empty" "unknown_kid" (h ~kid:(q "") []);
    row "kid unknown" "unknown_kid" (h ~kid:(q "rsa2") []);
    row "kid RSA (case)" "unknown_kid" (h ~kid:(q "RSA") []);
    row "kid with a trailing space" "unknown_kid" (h ~kid:(q "rsa ") []);
    row "kid of another key type" "unknown_kid" (h ~kid:(q "p256") []);
    row "kid a path" "unknown_kid" (h ~kid:(q "../../../../dev/null") []);
    row "kid with a quote" "unknown_kid" (h ~kid:(q "rsa' OR '1'='1") []);
    row "kid very long" "unknown_kid" (h ~kid:(q (String.make 4000 'k')) []);
    row "kid a number" "malformed" (h ~kid:"1" []);
    row "kid null" "malformed" (h ~kid:"null" []);
    row "kid an array" "malformed" (h ~kid:"[\"rsa\"]" []);
    (* crit *)
    row "crit [exp]" "malformed" (h [ ("crit", "[\"exp\"]") ]);
    row "crit []" "malformed" (h [ ("crit", "[]") ]);
    row "crit null" "malformed" (h [ ("crit", "null") ]);
    row "crit [b64] with b64 false" "malformed"
      (h [ ("crit", "[\"b64\"]"); ("b64", "false") ]);
    row "crit naming an unknown extension" "malformed"
      (h [ ("crit", "[\"urn:example:ext\"]"); ("urn:example:ext", "1") ]);
    (* b64 (RFC 7797) *)
    row "b64 false" "malformed" (h [ ("b64", "false") ]);
    row "b64 true" "ok" (h [ ("b64", "true") ]);
    row "b64 a string" "malformed" (h [ ("b64", q "false") ]);
    row "b64 0" "malformed" (h [ ("b64", "0") ]);
    row "b64 null" "malformed" (h [ ("b64", "null") ]);
    (* typ and cty are not interpreted *)
    row "typ JWT" "ok" (h [ ("typ", q "JWT") ]);
    row "typ jwt" "ok" (h [ ("typ", q "jwt") ]);
    row "typ at+jwt" "ok" (h [ ("typ", q "at+jwt") ]);
    row "typ application/at+jwt" "ok" (h [ ("typ", q "application/at+jwt") ]);
    row "typ something else" "ok" (h [ ("typ", q "JOSE") ]);
    row "typ a number" "malformed" (h [ ("typ", "1") ]);
    row "typ null" "malformed" (h [ ("typ", "null") ]);
    row "typ an array" "malformed" (h [ ("typ", "[\"JWT\"]") ]);
    row "cty JWT" "ok" (h [ ("cty", q "JWT") ]);
    row "unknown header member" "ok" (h [ ("x-request", "{\"a\":[1,2]}") ]);
    (* embedded keys are ignored: the key comes from the configured JWKS only *)
    row "jwk header with the attacker's key, signed by it" "bad_signature"
      ~signer:by_attacker
      (h [ ("jwk", attacker_rsa) ]);
    row "jwk header, attacker's own kid" "unknown_kid" ~signer:by_attacker
      (h ~kid:(q "attacker") [ ("jwk", attacker_rsa) ]);
    row "jwk header, no kid" "missing_kid" ~signer:by_attacker
      (obj [ ("alg", q "RS256"); ("jwk", attacker_rsa) ]);
    row "jwk header (EC), signed by it" "bad_signature"
      ~signer:(fun i -> cat (es256_rs ~key:p256b_priv i))
      (h ~alg:(q "ES256") ~kid:(q "p256") [ ("jwk", attacker_ec) ]);
    row "jwk header, signed by the configured key" "ok" (h [ ("jwk", attacker_rsa) ]);
    row "jku header, signed by the attacker" "bad_signature" ~signer:by_attacker
      (h [ ("jku", q "https://attacker.example/jwks.json") ]);
    row "jku header, signed by the configured key" "ok"
      (h [ ("jku", q "https://attacker.example/jwks.json") ]);
    row "x5u header, signed by the attacker" "bad_signature" ~signer:by_attacker
      (h [ ("x5u", q "https://attacker.example/cert.pem") ]);
    row "x5c header, signed by the attacker" "bad_signature" ~signer:by_attacker
      (h [ ("x5c", "[\"MIIB\"]") ]);
    row "x5c header, signed by the configured key" "ok" (h [ ("x5c", "[\"MIIB\"]") ]);
    row "x5t and x5t#S256 headers" "ok" (h [ ("x5t", q "abc"); ("x5t#S256", q "def") ]);
    row "jwk, jku, x5u and x5c together, signed by the attacker" "bad_signature"
      ~signer:by_attacker
      (h
         [
           ("jwk", attacker_rsa);
           ("jku", q "https://attacker.example/jwks.json");
           ("x5u", q "https://attacker.example/cert.pem");
           ("x5c", "[\"MIIB\"]");
         ]);
    (* JSON shape *)
    row "header an array" "malformed" "[\"RS256\"]";
    row "header a string" "malformed" "\"RS256\"";
    row "header null" "malformed" "null";
    row "header not JSON" "malformed" "alg=RS256";
    row "header with trailing garbage" "malformed" (h [] ^ "}");
    row "header truncated" "malformed" "{\"alg\":\"RS256\"";
    row "header empty object" "malformed" "{}";
    row "header with a nested duplicate" "malformed" (h [ ("x", "{\"a\":1,\"a\":2}") ]);
    row "header with a duplicate inside an array" "malformed"
      (h [ ("x", "[{\"a\":1,\"a\":2}]") ]);
  ]

(* ---- compact serialization ---- *)

let shape_table : row list =
  let header = hdr "RS256" "rsa" in
  let good = token header by_owner in
  let hh, pp, ss =
    match String.split_on_char '.' good with
    | [ a; b; c ] -> (a, b, c)
    | _ -> assert false
  in
  let row name expected tok = ("shape: " ^ name, expected, fun () -> verify tok) in
  let sized n =
    (* a correctly signed token of exactly [n] bytes, or the closest size above *)
    let rec go fill =
      let t =
        token
          ~payload:(claims [ ("pad", Some (q (String.make fill 'x'))) ])
          header by_owner
      in
      if String.length t >= n then t else go (fill + 1)
    in
    go (((n - String.length good) * 3 / 4) - 16)
  in
  let at_limit = sized Jwt.max_token_bytes in
  let over = sized (Jwt.max_token_bytes + 1) in
  let last_char_plus_one s =
    let n = String.length s in
    String.sub s 0 (n - 1) ^ String.make 1 (Char.chr (Char.code s.[n - 1] + 1))
  in
  [
    row "valid" "ok" good;
    row "empty" "malformed" "";
    row "two segments" "malformed" (hh ^ "." ^ pp);
    row "empty signature" "malformed" (hh ^ "." ^ pp ^ ".");
    row "empty payload" "malformed" (hh ^ ".." ^ ss);
    row "empty header" "malformed" ("." ^ pp ^ "." ^ ss);
    row "four segments" "malformed" (good ^ "." ^ ss);
    row "five segments (JWE)" "malformed" (hh ^ "..." ^ pp ^ "." ^ ss);
    row "trailing dot" "malformed" (good ^ ".");
    row "only dots" "malformed" "..";
    row "leading space" "malformed" (" " ^ good);
    row "trailing newline" "malformed" (good ^ "\n");
    row "trailing NUL" "malformed" (good ^ "\x00");
    row "newline inside the payload segment" "malformed" (hh ^ "." ^ "\n" ^ pp ^ "." ^ ss);
    row "padded signature" "malformed" (good ^ "==");
    row "padded header" "malformed" (hh ^ "=." ^ pp ^ "." ^ ss);
    row "standard alphabet in the signature" "malformed"
      (hh ^ "." ^ pp ^ "." ^ "+/" ^ String.sub ss 2 (String.length ss - 2));
    (* 256 signature bytes leave 4 unused bits in the last character: any other value
       of those bits is a second spelling of the same signature *)
    row "non-canonical last signature character" "malformed"
      (hh ^ "." ^ pp ^ "." ^ last_char_plus_one ss);
    row "Bearer prefix" "malformed" ("Bearer " ^ good);
    ( "shape: a token of exactly the size limit",
      "true",
      fun () -> string_of_bool (String.length at_limit = Jwt.max_token_bytes) );
    row "at the size limit" "ok" at_limit;
    row "over the size limit" "malformed" over;
    row "payload an array" "malformed" (token ~payload:"[]" header by_owner);
    row "payload a string" "malformed" (token ~payload:"\"x\"" header by_owner);
    row "payload a number" "malformed" (token ~payload:"1" header by_owner);
    row "payload null" "malformed" (token ~payload:"null" header by_owner);
    row "payload not JSON" "malformed" (token ~payload:"iss=x" header by_owner);
    row "payload with trailing garbage" "malformed"
      (token ~payload:(payload ^ "x") header by_owner);
    row "payload is a nested JWT" "malformed" (token ~payload:good header by_owner);
    row "payload with a duplicate claim" "malformed"
      (token ~payload:(obj (base_claims @ [ ("exp", "9999999999") ])) header by_owner);
    row "payload with a duplicate claim (iss)" "malformed"
      (token
         ~payload:(obj (("iss", q "https://evil.example") :: base_claims))
         header by_owner);
    row "payload with a nested duplicate" "malformed"
      (token
         ~payload:
           (claims [ ("realm_access", Some "{\"roles\":[],\"roles\":[\"admin\"]}") ])
         header by_owner);
    row "payload deeply nested" "ok"
      (token
         ~payload:
           (claims [ ("deep", Some (String.make 2000 '[' ^ String.make 2000 ']')) ])
         header by_owner);
  ]

(* ---- claims ---- *)

let claims_table : row list =
  let header = hdr "RS256" "rsa" in
  let row name expected ?(leeway = 60) ?(at = now) overrides =
    ( "claims: " ^ name,
      expected,
      fun () ->
        verify ~p:(provider ~leeway ()) ~at
          (token
             ~payload:(claims (List.map (fun (k, v) -> (k, Some v)) overrides))
             header by_owner) )
  in
  let without name expected k =
    ( "claims: " ^ name,
      expected,
      fun () -> verify (token ~payload:(claims [ (k, None) ]) header by_owner) )
  in
  let digits400 = "1" ^ String.make 400 '0' in
  let t d = Printf.sprintf "%.0f" (now +. d) in
  [
    row "baseline" "ok" [];
    (* exp: type and range *)
    without "exp missing" "missing_claim" "exp";
    row "exp a float" "ok" [ ("exp", "1800000600.5") ];
    row "exp in exponent notation" "ok" [ ("exp", "1.8000006e9") ];
    row "exp a string" "bad_claim" [ ("exp", "\"1800000600\"") ];
    row "exp null" "bad_claim" [ ("exp", "null") ];
    row "exp true" "bad_claim" [ ("exp", "true") ];
    row "exp an array" "bad_claim" [ ("exp", "[1800000600]") ];
    row "exp an object" "bad_claim" [ ("exp", "{}") ];
    row "exp 0" "expired" [ ("exp", "0") ];
    row "exp -1" "expired" [ ("exp", "-1") ];
    row "exp -1800000600" "expired" [ ("exp", "-1800000600") ];
    row "exp -1e300" "expired" [ ("exp", "-1e300") ];
    row "exp 2^53" "ok" [ ("exp", "9007199254740992") ];
    row "exp 2^62 (beyond a native int)" "ok" [ ("exp", "4611686018427387904") ];
    row "exp 2^63" "ok" [ ("exp", "9223372036854775808") ];
    row "exp 2^64" "ok" [ ("exp", "18446744073709551616") ];
    row "exp 1e300" "ok" [ ("exp", "1e300") ];
    row "exp -2^63 - 1" "expired" [ ("exp", "-9223372036854775809") ];
    (* not a finite number (the JSON parser reads 1e400 and the non-standard NaN and
       Infinity literals as non-finite floats) *)
    row "exp 1e400" "bad_claim" [ ("exp", "1e400") ];
    row "exp -1e400" "bad_claim" [ ("exp", "-1e400") ];
    row "exp NaN" "bad_claim" [ ("exp", "NaN") ];
    row "exp Infinity" "bad_claim" [ ("exp", "Infinity") ];
    row "exp -Infinity" "bad_claim" [ ("exp", "-Infinity") ];
    row "exp an integer of 401 digits" "bad_claim" [ ("exp", digits400) ];
    row "exp a negative integer of 401 digits" "bad_claim" [ ("exp", "-" ^ digits400) ];
    row "exp hexadecimal" "malformed" [ ("exp", "0x6B49D200") ];
    row "exp with a leading zero" "malformed" [ ("exp", "01800000600") ];
    row "exp with a plus sign" "malformed" [ ("exp", "+1800000600") ];
    (* exp: boundaries. Expired from exp + leeway on. *)
    row "exp = now, leeway 60" "ok" [ ("exp", t 0.) ];
    row "exp = now - 59, leeway 60" "ok" [ ("exp", t (-59.)) ];
    row "exp = now - 60, leeway 60" "expired" [ ("exp", t (-60.)) ];
    row "exp = now - 61, leeway 60" "expired" [ ("exp", t (-61.)) ];
    row "exp = now - 59.5, leeway 60" "ok" [ ("exp", "1799999940.5") ];
    row "now = exp + 59.999, leeway 60" "ok" ~at:(now +. 659.999) [];
    row "now = exp + 60, leeway 60" "expired" ~at:(now +. 660.) [];
    row "now = exp + 60.001, leeway 60" "expired" ~at:(now +. 660.001) [];
    row "exp = now + 1, leeway 0" "ok" ~leeway:0 [ ("exp", t 1.) ];
    row "exp = now, leeway 0" "expired" ~leeway:0 [ ("exp", t 0.) ];
    row "exp = now - 1, leeway 0" "expired" ~leeway:0 [ ("exp", t (-1.)) ];
    row "exp = now + 0.5, leeway 0" "ok" ~leeway:0 [ ("exp", "1800000000.5") ];
    row "now = exp - 0.001, leeway 0" "ok" ~leeway:0 ~at:(now +. 599.999) [];
    (* nbf *)
    row "nbf in the past" "ok" [ ("nbf", t (-100.)) ];
    row "nbf negative" "ok" [ ("nbf", "-5") ];
    row "nbf a float" "ok" [ ("nbf", "1799999999.25") ];
    row "nbf a string" "bad_claim" [ ("nbf", "\"0\"") ];
    row "nbf null" "bad_claim" [ ("nbf", "null") ];
    row "nbf false" "bad_claim" [ ("nbf", "false") ];
    row "nbf 2^63" "not_yet_valid" [ ("nbf", "9223372036854775808") ];
    row "nbf an integer of 401 digits" "bad_claim" [ ("nbf", digits400) ];
    row "nbf 1e400" "bad_claim" [ ("nbf", "1e400") ];
    row "nbf = now + 60, leeway 60" "ok" [ ("nbf", t 60.) ];
    row "nbf = now + 61, leeway 60" "not_yet_valid" [ ("nbf", t 61.) ];
    row "nbf = now + 60.5, leeway 60" "not_yet_valid" [ ("nbf", "1800000060.5") ];
    row "nbf = now, leeway 0" "ok" ~leeway:0 [ ("nbf", t 0.) ];
    row "nbf = now + 1, leeway 0" "not_yet_valid" ~leeway:0 [ ("nbf", t 1.) ];
    (* iat *)
    without "iat missing" "ok" "iat";
    row "iat negative" "ok" [ ("iat", "-1") ];
    row "iat a string" "bad_claim" [ ("iat", "\"1799999990\"") ];
    row "iat an array" "bad_claim" [ ("iat", "[]") ];
    row "iat 2^63" "issued_in_future" [ ("iat", "9223372036854775808") ];
    row "iat an integer of 401 digits" "bad_claim" [ ("iat", digits400) ];
    row "iat = now + 60, leeway 60" "ok" [ ("iat", t 60.) ];
    row "iat = now + 61, leeway 60" "issued_in_future" [ ("iat", t 61.) ];
    row "iat = now, leeway 0" "ok" ~leeway:0 [ ("iat", t 0.) ];
    row "iat = now + 1, leeway 0" "issued_in_future" ~leeway:0 [ ("iat", t 1.) ];
    (* a malformed time claim is reported before an expired one *)
    row "expired, and nbf a string" "bad_claim" [ ("exp", "1"); ("nbf", "\"x\"") ];
    (* aud *)
    row "aud a matching string" "ok" [ ("aud", q "haltsql") ];
    row "aud the second accepted audience" "ok" [ ("aud", q "haltsql-alt") ];
    row "aud another string" "wrong_audience" [ ("aud", q "other") ];
    row "aud an array containing it" "ok" [ ("aud", "[\"other\",\"haltsql\"]") ];
    row "aud a one-element array" "ok" [ ("aud", "[\"haltsql\"]") ];
    row "aud an array without it" "wrong_audience" [ ("aud", "[\"other\",\"another\"]") ];
    row "aud an empty array" "wrong_audience" [ ("aud", "[]") ];
    row "aud an array with a non-string" "wrong_audience" [ ("aud", "[\"haltsql\",1]") ];
    row "aud an array with null" "wrong_audience" [ ("aud", "[null,\"haltsql\"]") ];
    row "aud a nested array" "wrong_audience" [ ("aud", "[[\"haltsql\"]]") ];
    row "aud an object" "wrong_audience" [ ("aud", "{\"haltsql\":true}") ];
    row "aud a number" "wrong_audience" [ ("aud", "1") ];
    row "aud null" "wrong_audience" [ ("aud", "null") ];
    row "aud empty string" "wrong_audience" [ ("aud", q "") ];
    row "aud in another case" "wrong_audience" [ ("aud", q "HaltSQL") ];
    row "aud with a trailing space" "wrong_audience" [ ("aud", q "haltsql ") ];
    row "aud a prefix" "wrong_audience" [ ("aud", q "halt") ];
    row "aud space-separated" "wrong_audience" [ ("aud", q "other haltsql") ];
    without "aud missing" "wrong_audience" "aud";
    (* iss *)
    without "iss missing" "wrong_issuer" "iss";
    row "iss with a trailing slash" "wrong_issuer" [ ("iss", q (issuer ^ "/")) ];
    row "iss in another case" "wrong_issuer" [ ("iss", q "https://IDP.example.com") ];
    row "iss an array" "wrong_issuer" [ ("iss", "[" ^ q issuer ^ "]") ];
    row "iss a number" "wrong_issuer" [ ("iss", "1") ];
    row "iss null" "wrong_issuer" [ ("iss", "null") ];
    row "iss with a NUL suffix" "wrong_issuer"
      [ ("iss", "\"https://idp.example.com\\u0000\"") ];
    (* sub is not required and not interpreted *)
    without "sub missing" "ok" "sub";
    row "sub a number" "ok" [ ("sub", "17") ];
  ]

(* ---- tokens produced by another implementation with the wrong parameters ---- *)

let interop_negative_table : row list =
  let j =
    let ic = open_in_bin "vectors/interop_vectors.json" in
    let s = really_input_string ic (in_channel_length ic) in
    close_in ic;
    Yojson.Safe.from_string s
  in
  let member k = function `Assoc kv -> List.assoc k kv | _ -> `Null in
  let str k v = match member k v with `String s -> s | _ -> Alcotest.failf "no %s" k in
  let keys =
    match Jwk.set_of_json (member "jwks" j) with
    | Ok (ks, []) -> ks
    | _ -> Alcotest.fail "interop JWKS"
  in
  let p = { (provider ()) with issuer = str "issuer" j } in
  let rows = match member "negative" j with `List l -> l | _ -> [] in
  if List.length rows < 17 then failwith "negative interop vectors are missing";
  List.map
    (fun v ->
      ( "pyca/cryptography: " ^ str "name" v,
        "bad_signature",
        fun () -> verify ~p ~at:1767225700. ~keys (str "token" v) ))
    rows

(* Error messages built from attacker-controlled header values stay on one line. *)
let messages () =
  let tok = token (hdr "RS256" "a\nb\r\x1b[31m") by_owner in
  match Oidc.verify (provider ()) ~keys ~now tok with
  | Error (Jwt.Unknown_kid _ as e) ->
      let m = Jwt.error_to_string e in
      Alcotest.(check bool)
        "no control characters" true
        (String.for_all (fun c -> Char.code c >= 0x20 && Char.code c <> 0x7f) m)
  | _ -> Alcotest.fail "expected unknown_kid"

let () =
  let tc n rows = Alcotest.test_case n `Quick (run_table rows) in
  at_exit (fun () -> Printf.printf "negative table rows run: %d\n" !total);
  Alcotest.run "haltsql-auth-negative"
    [
      ( "signatures",
        [
          tc "ECDSA" ecdsa_table;
          tc "algorithm and key type binding" key_binding_table;
          tc "RSA" rsa_table;
          tc "EdDSA" eddsa_table;
          tc "wrong parameters, signed by pyca/cryptography" interop_negative_table;
        ] );
      ( "keys",
        [
          tc "RSA keys" rsa_key_table;
          tc "EC keys" ec_key_table;
          tc "JWK members" jwk_table;
          tc "JWK Sets" set_table;
          tc "key selection" selection_table;
        ] );
      ( "tokens",
        [
          tc "headers" header_table;
          tc "compact serialization" shape_table;
          tc "claims" claims_table;
          Alcotest.test_case "messages" `Quick messages;
        ] );
    ]
