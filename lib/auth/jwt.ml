(** Compact JWS decoding and signature verification. Pure. *)

module Config = Haltsql.Config

type error =
  | Malformed of string
  | Alg_not_allowed of string
  | Missing_kid
  | Unknown_kid of string
  | Bad_signature
  | Wrong_issuer
  | Wrong_audience
  | Expired
  | Not_yet_valid
  | Issued_in_future
  | Missing_claim of string
  | Claim_mismatch of string
  | Bad_claim of string
  | Policy_not_allowed of string
  | Keys_unavailable of string
  | Groups_overage of string
  | No_group_policy of string

let error_code = function
  | Malformed _ -> "malformed"
  | Alg_not_allowed _ -> "alg_not_allowed"
  | Missing_kid -> "missing_kid"
  | Unknown_kid _ -> "unknown_kid"
  | Bad_signature -> "bad_signature"
  | Wrong_issuer -> "wrong_issuer"
  | Wrong_audience -> "wrong_audience"
  | Expired -> "expired"
  | Not_yet_valid -> "not_yet_valid"
  | Issued_in_future -> "issued_in_future"
  | Missing_claim _ -> "missing_claim"
  | Claim_mismatch _ -> "claim_mismatch"
  | Bad_claim _ -> "bad_claim"
  | Policy_not_allowed _ -> "policy_not_allowed"
  | Keys_unavailable _ -> "keys_unavailable"
  | Groups_overage _ -> "groups_overage"
  | No_group_policy _ -> "no_group_policy"

(* Untrusted strings echoed in messages are truncated and stripped of control
   characters. *)
let sanitize s =
  let s = if String.length s > 64 then String.sub s 0 64 ^ "..." else s in
  String.map (fun c -> if Char.code c < 0x20 || Char.code c = 0x7f then '?' else c) s

let error_to_string = function
  | Malformed m -> "malformed token: " ^ m
  | Alg_not_allowed a -> Printf.sprintf "token algorithm %S is not allowed" (sanitize a)
  | Missing_kid -> "token header has no kid"
  | Unknown_kid k -> Printf.sprintf "no usable signing key with kid %S" (sanitize k)
  | Bad_signature -> "token signature is invalid"
  | Wrong_issuer -> "token issuer is not accepted"
  | Wrong_audience -> "token audience is not accepted"
  | Expired -> "token has expired"
  | Not_yet_valid -> "token is not valid yet (nbf)"
  | Issued_in_future -> "token was issued in the future (iat)"
  | Missing_claim c -> Printf.sprintf "token is missing required claim %S" (sanitize c)
  | Claim_mismatch c ->
      Printf.sprintf "token claim %S does not have a required value" (sanitize c)
  | Bad_claim c ->
      Printf.sprintf "token claim %S has an unusable type or value" (sanitize c)
  | Policy_not_allowed c ->
      Printf.sprintf "token claim %S does not name an allowed policy" (sanitize c)
  | Keys_unavailable m -> "signing keys are unavailable: " ^ m
  | Groups_overage c ->
      Printf.sprintf
        "token claim %S is incomplete: the identity provider moved the groups out of the \
         token (group overage, _claim_names/_claim_sources); configure the IdP to emit \
         fewer groups (e.g. groups assigned to the application) or a roles claim"
        (sanitize c)
  | No_group_policy c ->
      Printf.sprintf
        "none of the groups in token claim %S is mapped to a policy, and no default \
         policy is configured"
        (sanitize c)

let max_token_bytes = 16384

type token = {
  alg_name : string;
  kid : string option;
  header : (string * Yojson.Safe.t) list;
  claims : (string * Yojson.Safe.t) list;
  signing_input : string;
  signature : string;
}

let ( let* ) = Result.bind

(* Duplicate member names at any depth: two parsers may disagree on which one counts. *)
let rec has_duplicates : Yojson.Safe.t -> bool = function
  | `Assoc kv ->
      let keys = List.map fst kv in
      List.length (List.sort_uniq String.compare keys) <> List.length keys
      || List.exists (fun (_, v) -> has_duplicates v) kv
  | `List l -> List.exists has_duplicates l
  | _ -> false

(* Total: whatever the parser raises on hostile input is "not valid JSON". *)
let parse_json s =
  match Yojson.Safe.from_string s with j -> Some j | exception _ -> None

let json_object what s =
  match parse_json s with
  | None -> Error (Malformed (what ^ " is not valid JSON"))
  | Some (`Assoc _ as j) when has_duplicates j ->
      Error (Malformed (what ^ " has duplicate members"))
  | Some (`Assoc kv) -> Ok kv
  | Some _ -> Error (Malformed (what ^ " is not a JSON object"))

let b64 what s =
  match B64url.decode s with
  | Ok v -> Ok v
  | Error _ -> Error (Malformed (what ^ " is not valid base64url"))

let decode tok =
  if String.length tok > max_token_bytes then Error (Malformed "token is too long")
  else
    match String.split_on_char '.' tok with
    | [ h; p; s ] when h <> "" && p <> "" && s <> "" ->
        let* hj = b64 "header" h in
        let* pj = b64 "payload" p in
        let* signature = b64 "signature" s in
        let* header = json_object "header" hj in
        let* claims = json_object "claims" pj in
        let* alg_name =
          match List.assoc_opt "alg" header with
          | Some (`String a) -> Ok a
          | _ -> Error (Malformed "header has no string \"alg\"")
        in
        let* kid =
          match List.assoc_opt "kid" header with
          | None -> Ok None
          | Some (`String k) -> Ok (Some k)
          | Some _ -> Error (Malformed "header \"kid\" must be a string")
        in
        let* () =
          match List.assoc_opt "typ" header with
          | None | Some (`String _) -> Ok ()
          | Some _ -> Error (Malformed "header \"typ\" must be a string")
        in
        (* RFC 7797: with "b64": false the payload is not base64url-encoded and the
           signing input differs. Such a token must not be read as an ordinary one. *)
        let* () =
          match List.assoc_opt "b64" header with
          | None | Some (`Bool true) -> Ok ()
          | Some _ ->
              Error (Malformed "header \"b64\" (unencoded payload) is not supported")
        in
        if List.mem_assoc "crit" header then
          Error (Malformed "header \"crit\" extensions are not supported")
        else Ok { alg_name; kid; header; claims; signing_input = h ^ "." ^ p; signature }
    | _ -> Error (Malformed "expected three non-empty dot-separated segments")

let is_b64url_char = function
  | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '-' | '_' -> true
  | _ -> false

let looks_like_jwt tok =
  String.length tok <= max_token_bytes
  &&
  match String.split_on_char '.' tok with
  | [ h; p; s ]
    when h <> "" && p <> "" && s <> ""
         && String.for_all is_b64url_char h
         && String.for_all is_b64url_char p
         && String.for_all is_b64url_char s -> (
      match B64url.decode h with
      | Ok hj -> (
          match parse_json hj with
          | Some (`Assoc kv) -> List.mem_assoc "alg" kv
          | _ -> false)
      | Error _ -> false)
  | _ -> false

let unverified_issuer tok =
  match decode tok with
  | Ok t -> (
      match List.assoc_opt "iss" t.claims with Some (`String s) -> Some s | _ -> None)
  | Error _ -> None

let alg_of_string = function
  | "RS256" -> Ok Config.RS256
  | "RS384" -> Ok Config.RS384
  | "RS512" -> Ok Config.RS512
  | "PS256" -> Ok Config.PS256
  | "ES256" -> Ok Config.ES256
  | "ES384" -> Ok Config.ES384
  | "EdDSA" -> Ok Config.EdDSA
  | a -> Error (Alg_not_allowed a)

module PSS256 = Mirage_crypto_pk.Rsa.PSS (Digestif.SHA256)

let verify_signature (alg : Config.jwt_alg) (key : Jwk.key) ~signing_input ~signature =
  let rsa_pkcs1 hash pub =
    Mirage_crypto_pk.Rsa.PKCS1.verify
      ~hashp:(fun h -> h = hash)
      ~key:pub ~signature (`Message signing_input)
  in
  let ecdsa ~len digest verify =
    String.length signature = 2 * len
    &&
    let r = String.sub signature 0 len and s = String.sub signature len len in
    verify (r, s) digest
  in
  try
    match (alg, key) with
    | Config.RS256, Jwk.Rsa pub -> rsa_pkcs1 `SHA256 pub
    | RS384, Jwk.Rsa pub -> rsa_pkcs1 `SHA384 pub
    | RS512, Jwk.Rsa pub -> rsa_pkcs1 `SHA512 pub
    | PS256, Jwk.Rsa pub ->
        String.length signature = (Mirage_crypto_pk.Rsa.pub_bits pub + 7) / 8
        && PSS256.verify ~key:pub ~signature (`Message signing_input)
    | ES256, Jwk.P256 pub ->
        ecdsa ~len:32
          Digestif.SHA256.(to_raw_string (digest_string signing_input))
          (fun rs d -> Mirage_crypto_ec.P256.Dsa.verify ~key:pub rs d)
    | ES384, Jwk.P384 pub ->
        ecdsa ~len:48
          Digestif.SHA384.(to_raw_string (digest_string signing_input))
          (fun rs d -> Mirage_crypto_ec.P384.Dsa.verify ~key:pub rs d)
    | EdDSA, Jwk.Ed25519 pub ->
        String.length signature = 64
        && Mirage_crypto_ec.Ed25519.verify ~key:pub signature ~msg:signing_input
    | _ -> false
  with _ -> false

let select_key alg ~kid keys =
  match kid with
  | None -> Error Missing_kid
  | Some k -> (
      match
        List.find_opt (fun (j : Jwk.t) -> j.kid = Some k && Jwk.compatible alg j) keys
      with
      | Some j -> Ok j
      | None -> Error (Unknown_kid k))

let number_claim name claims =
  match List.assoc_opt name claims with
  | None -> Ok None
  | Some (`Int i) -> Ok (Some (float_of_int i))
  | Some (`Float f) when Float.is_finite f -> Ok (Some f)
  | Some (`Intlit s) -> (
      (* an integer literal of more than 308 digits converts to infinity *)
      match float_of_string_opt s with
      | Some f when Float.is_finite f -> Ok (Some f)
      | _ -> Error (Bad_claim name))
  | Some _ -> Error (Bad_claim name)

type signing_key =
  | Sign_rsa of Mirage_crypto_pk.Rsa.priv
  | Sign_p256 of Mirage_crypto_ec.P256.Dsa.priv
  | Sign_p384 of Mirage_crypto_ec.P384.Dsa.priv
  | Sign_ed25519 of Mirage_crypto_ec.Ed25519.priv

let pad len s =
  if String.length s >= len then s else String.make (len - String.length s) '\x00' ^ s

let sign ~alg ?kid ?(extra_header = []) key claims =
  let header =
    `Assoc
      (("alg", `String alg)
       :: (match kid with Some k -> [ ("kid", `String k) ] | None -> [])
      @ extra_header)
  in
  let input =
    B64url.encode (Yojson.Safe.to_string header)
    ^ "."
    ^ B64url.encode (Yojson.Safe.to_string claims)
  in
  let hash =
    match alg with
    | "RS384" | "ES384" | "PS384" | "HS384" -> `SHA384
    | "RS512" | "ES512" | "PS512" | "HS512" -> `SHA512
    | _ -> `SHA256
  in
  let signature =
    match key with
    | Sign_rsa priv ->
        if String.length alg >= 2 && String.sub alg 0 2 = "PS" then
          PSS256.sign ~key:priv (`Message input)
        else Mirage_crypto_pk.Rsa.PKCS1.sign ~hash ~key:priv (`Message input)
    | Sign_p256 priv ->
        let d = Digestif.SHA256.(to_raw_string (digest_string input)) in
        let r, s = Mirage_crypto_ec.P256.Dsa.sign ~key:priv d in
        pad 32 r ^ pad 32 s
    | Sign_p384 priv ->
        let d = Digestif.SHA384.(to_raw_string (digest_string input)) in
        let r, s = Mirage_crypto_ec.P384.Dsa.sign ~key:priv d in
        pad 48 r ^ pad 48 s
    | Sign_ed25519 priv -> Mirage_crypto_ec.Ed25519.sign ~key:priv input
  in
  input ^ "." ^ B64url.encode signature
