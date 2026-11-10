(** Public JSON Web Keys. *)

module Config = Haltsql.Config

type key =
  | Rsa of Mirage_crypto_pk.Rsa.pub
  | P256 of Mirage_crypto_ec.P256.Dsa.pub
  | P384 of Mirage_crypto_ec.P384.Dsa.pub
  | Ed25519 of Mirage_crypto_ec.Ed25519.pub

type t = { kid : string option; alg : string option; use : string option; key : key }

let min_rsa_bits = 2048
let max_rsa_bits = 8192
let ( let* ) = Result.bind

let str_member k kv =
  match List.assoc_opt k kv with
  | None -> Ok None
  | Some (`String s) -> Ok (Some s)
  | Some _ -> Error (Printf.sprintf "JWK member %S must be a string" k)

let required_b64 k kv =
  match List.assoc_opt k kv with
  | Some (`String s) -> (
      match B64url.decode s with
      | Ok v when v <> "" -> Ok v
      | Ok _ -> Error (Printf.sprintf "JWK member %S is empty" k)
      | Error e -> Error (Printf.sprintf "JWK member %S: %s" k e))
  | Some _ -> Error (Printf.sprintf "JWK member %S must be a string" k)
  | None -> Error (Printf.sprintf "JWK member %S is missing" k)

let private_members = [ "d"; "p"; "q"; "dp"; "dq"; "qi"; "oth"; "k" ]

let has_duplicates kv =
  let keys = List.map fst kv in
  List.length (List.sort_uniq String.compare keys) <> List.length keys

(* RFC 7517 section 4.3: when present, [key_ops] must be an array of strings, and a key
   is only used for an operation it lists. *)
let check_key_ops kv =
  match List.assoc_opt "key_ops" kv with
  | None -> Ok ()
  | Some (`List ops) when List.for_all (function `String _ -> true | _ -> false) ops ->
      if List.mem (`String "verify") ops then Ok ()
      else Error "JWK \"key_ops\" does not include \"verify\""
  | Some _ -> Error "JWK member \"key_ops\" must be an array of strings"

(* The eight points of small order on edwards25519, as encoded y coordinates with the
   sign bit cleared (two of them also in their non-canonical encodings y = p and
   y = p + 1). With such a public key the verification equation holds for a fixed
   signature and many or all messages, and mirage-crypto does not reject them. *)
let ed25519_small_order =
  List.map
    (fun h ->
      String.init 32 (fun i -> Char.chr (int_of_string ("0x" ^ String.sub h (2 * i) 2))))
    [
      "0000000000000000000000000000000000000000000000000000000000000000";
      "0100000000000000000000000000000000000000000000000000000000000000";
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05";
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a";
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
      "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
    ]

let ed25519_is_small_order x =
  String.length x = 32
  &&
  let y =
    String.mapi (fun i c -> if i = 31 then Char.chr (Char.code c land 0x7f) else c) x
  in
  List.mem y ed25519_small_order

let ec_point ~len x y =
  if String.length x <> len || String.length y <> len then
    Error "EC coordinate has the wrong length"
  else Ok ("\x04" ^ x ^ y)

let of_json (j : Yojson.Safe.t) =
  match j with
  | `Assoc kv when has_duplicates kv -> Error "JWK has duplicate members"
  | `Assoc kv ->
      let* kty = str_member "kty" kv in
      let* kid = str_member "kid" kv in
      let* alg = str_member "alg" kv in
      let* use = str_member "use" kv in
      let* () = check_key_ops kv in
      if List.exists (fun m -> List.mem_assoc m kv) private_members then
        Error "JWK contains private or symmetric key material; refusing it"
      else
        let* key =
          match kty with
          | None -> Error "JWK member \"kty\" is missing"
          | Some "RSA" -> (
              let* n = required_b64 "n" kv in
              let* e = required_b64 "e" kv in
              let n = Mirage_crypto_pk.Z_extra.of_octets_be n
              and e = Mirage_crypto_pk.Z_extra.of_octets_be e in
              (* mirage-crypto accepts any 1 < e < n; an even exponent is never a valid
                 RSA public exponent. *)
              if Z.numbits n > max_rsa_bits then
                Error (Printf.sprintf "RSA key is larger than %d bits" max_rsa_bits)
              else if Z.is_even e || Z.lt e (Z.of_int 3) then
                Error "invalid RSA key: the public exponent must be odd and at least 3"
              else
                match Mirage_crypto_pk.Rsa.pub ~e ~n with
                | Error (`Msg m) -> Error ("invalid RSA key: " ^ m)
                | Ok pub ->
                    if Mirage_crypto_pk.Rsa.pub_bits pub < min_rsa_bits then
                      Error
                        (Printf.sprintf "RSA key is smaller than %d bits" min_rsa_bits)
                    else Ok (Rsa pub))
          | Some "EC" -> (
              let* crv = str_member "crv" kv in
              let* x = required_b64 "x" kv in
              let* y = required_b64 "y" kv in
              match crv with
              | Some "P-256" -> (
                  let* pt = ec_point ~len:32 x y in
                  match Mirage_crypto_ec.P256.Dsa.pub_of_octets pt with
                  | Ok p -> Ok (P256 p)
                  | Error _ -> Error "invalid P-256 point")
              | Some "P-384" -> (
                  let* pt = ec_point ~len:48 x y in
                  match Mirage_crypto_ec.P384.Dsa.pub_of_octets pt with
                  | Ok p -> Ok (P384 p)
                  | Error _ -> Error "invalid P-384 point")
              | Some c -> Error (Printf.sprintf "unsupported EC curve %S" c)
              | None -> Error "JWK member \"crv\" is missing")
          | Some "OKP" -> (
              let* crv = str_member "crv" kv in
              let* x = required_b64 "x" kv in
              match crv with
              | Some "Ed25519" -> (
                  if String.length x <> 32 then Error "Ed25519 key has the wrong length"
                  else if ed25519_is_small_order x then
                    Error "Ed25519 key is a point of small order"
                  else
                    match Mirage_crypto_ec.Ed25519.pub_of_octets x with
                    | Ok p -> Ok (Ed25519 p)
                    | Error _ -> Error "invalid Ed25519 key")
              | Some c -> Error (Printf.sprintf "unsupported OKP curve %S" c)
              | None -> Error "JWK member \"crv\" is missing")
          | Some "oct" -> Error "symmetric (oct) keys are never accepted"
          | Some k -> Error (Printf.sprintf "unsupported key type %S" k)
        in
        Ok { kid; alg; use; key }
  | _ -> Error "JWK must be a JSON object"

let set_of_json (j : Yojson.Safe.t) =
  match j with
  | `Assoc kv when has_duplicates kv -> Error "JWK Set has duplicate members"
  | `Assoc kv -> (
      match List.assoc_opt "keys" kv with
      | Some (`List keys) ->
          let ok, bad =
            List.fold_left
              (fun (ok, bad) (i, k) ->
                match of_json k with
                | Ok key -> (key :: ok, bad)
                | Error e -> (ok, Printf.sprintf "keys[%d]: %s" i e :: bad))
              ([], [])
              (List.mapi (fun i k -> (i, k)) keys)
          in
          Ok (List.rev ok, List.rev bad)
      | _ -> Error "JWK Set must have a \"keys\" array")
  | _ -> Error "JWK Set must be a JSON object"

let set_of_string s =
  match Yojson.Safe.from_string s with
  | j -> set_of_json j
  | exception _ -> Error "JWK Set is not valid JSON"

let compatible (alg : Config.jwt_alg) (k : t) =
  let family_ok =
    match (alg, k.key) with
    | (Config.RS256 | RS384 | RS512 | PS256), Rsa _ -> true
    | ES256, P256 _ -> true
    | ES384, P384 _ -> true
    | EdDSA, Ed25519 _ -> true
    | _ -> false
  in
  let use_ok = match k.use with None | Some "sig" -> true | Some _ -> false in
  let alg_ok =
    match k.alg with None -> true | Some a -> a = Config.string_of_jwt_alg alg
  in
  family_ok && use_ok && alg_ok

let to_json (k : t) : Yojson.Safe.t =
  let b64 s = `String (B64url.encode s) in
  let opt name = function Some v -> [ (name, `String v) ] | None -> [] in
  let material =
    match k.key with
    | Rsa pub ->
        [
          ("kty", `String "RSA");
          ("n", b64 (Mirage_crypto_pk.Z_extra.to_octets_be pub.n));
          ("e", b64 (Mirage_crypto_pk.Z_extra.to_octets_be pub.e));
        ]
    | P256 p ->
        let o = Mirage_crypto_ec.P256.Dsa.pub_to_octets p in
        [
          ("kty", `String "EC");
          ("crv", `String "P-256");
          ("x", b64 (String.sub o 1 32));
          ("y", b64 (String.sub o 33 32));
        ]
    | P384 p ->
        let o = Mirage_crypto_ec.P384.Dsa.pub_to_octets p in
        [
          ("kty", `String "EC");
          ("crv", `String "P-384");
          ("x", b64 (String.sub o 1 48));
          ("y", b64 (String.sub o 49 48));
        ]
    | Ed25519 p ->
        [
          ("kty", `String "OKP");
          ("crv", `String "Ed25519");
          ("x", b64 (Mirage_crypto_ec.Ed25519.pub_to_octets p));
        ]
  in
  `Assoc (material @ opt "kid" k.kid @ opt "alg" k.alg @ opt "use" k.use)
