(** Compact JWS/JWT decoding and signature verification (RFC 7515, RFC 7519).

    This module is pure: it never performs IO and takes the current time as an argument
    where needed. The supported algorithms are exactly {!Haltsql.Config.jwt_alg}; [none]
    and every HMAC algorithm are always rejected, whatever the configuration says. *)

(** Why a token was rejected. Messages never contain the token or key material. *)
type error =
  | Malformed of string  (** not a well-formed compact JWS / JSON claims set *)
  | Alg_not_allowed of string  (** [none], HMAC, unknown, or not in the allowlist *)
  | Missing_kid  (** the header has no [kid] *)
  | Unknown_kid of string  (** no compatible key with this [kid] *)
  | Bad_signature
  | Wrong_issuer
  | Wrong_audience
  | Expired
  | Not_yet_valid  (** [nbf] in the future (beyond leeway) *)
  | Issued_in_future  (** [iat] in the future (beyond leeway) *)
  | Missing_claim of string
  | Claim_mismatch of string  (** a [required_claims] entry does not match *)
  | Bad_claim of string  (** a claim has an unusable type *)
  | Policy_not_allowed of string
      (** [policy_claim] names a policy outside the allowlist *)
  | Keys_unavailable of string  (** the JWKS could not be obtained *)
  | Groups_overage of string
      (** [policy_from_groups]: the groups claim was replaced by an Azure AD / Entra ID
          overage indicator ([_claim_names] / [_claim_sources] or [hasgroups]); the groups
          are not in the token, so the token is rejected (no Graph call is made) *)
  | No_group_policy of string
      (** [policy_from_groups]: no group in the claim is mapped, and there is no [default]
      *)

val error_code : error -> string
(** A stable snake_case code, e.g. ["expired"], ["bad_signature"]. *)

val error_to_string : error -> string
(** A human-readable message, safe to log and to return to callers. *)

val max_token_bytes : int
(** Tokens longer than this (16 KiB) are rejected as malformed. *)

type token = {
  alg_name : string;  (** the header's [alg], as written *)
  kid : string option;
  header : (string * Yojson.Safe.t) list;
  claims : (string * Yojson.Safe.t) list;
  signing_input : string;  (** [base64url(header) ^ "." ^ base64url(payload)] *)
  signature : string;  (** raw signature bytes *)
}

val decode : string -> (token, error) result
(** Splits and decodes a compact JWS without verifying it. Rejects: anything but three
    non-empty segments, invalid base64url, a header or claims set that is not a JSON
    object or has duplicate member names at any depth, a missing or non-string [alg], a
    non-string [kid] or [typ], a [b64] header other than [true] (RFC 7797 unencoded
    payloads), and any [crit] header (no extension is understood). Every other header
    member is ignored, in particular [jwk], [jku], [x5u] and [x5c]: a token never supplies
    its own key. Never raises. *)

val looks_like_jwt : string -> bool
(** Cheap shape test: three base64url segments whose first decodes to a JSON object with
    an [alg] member. *)

val unverified_issuer : string -> string option
(** The [iss] claim of a token {b without} verifying it; only used to choose which
    provider should verify the token. *)

val alg_of_string : string -> (Haltsql.Config.jwt_alg, error) result
(** Maps a header [alg] to a supported algorithm; [none], HMAC, and anything unknown are
    [Alg_not_allowed]. *)

val verify_signature :
  Haltsql.Config.jwt_alg -> Jwk.key -> signing_input:string -> signature:string -> bool
(** [true] iff the signature is valid for the algorithm and key; [false] on any key-type
    mismatch or malformed signature (never raises).

    ECDSA signatures are the fixed-width [r || s] of RFC 7518 section 3.4 (64 bytes for
    ES256, 96 for ES384); DER and any other length are invalid. Both [s] and [n - s] are
    accepted: JWS has no low-s rule. RSA signatures must be exactly as long as the
    modulus; PS256 means SHA-256, MGF1 with SHA-256 and a 32-byte salt. Ed25519 signatures
    are 64 bytes with [S] below the group order. *)

val select_key :
  Haltsql.Config.jwt_alg -> kid:string option -> Jwk.t list -> (Jwk.t, error) result
(** The first key, in list order, with exactly this [kid] that is {!Jwk.compatible} with
    the algorithm. When several keys share a [kid], only that first one is ever used. A
    token without [kid] is [Missing_kid]. *)

val number_claim : string -> (string * Yojson.Safe.t) list -> (float option, error) result
(** A NumericDate claim: [Ok None] when absent, [Bad_claim] when not a finite number
    (strings, [1e400], integers too large for a float). Fractions and negative values are
    numbers. *)

(** {1 Signing (tests and tooling)} *)

type signing_key =
  | Sign_rsa of Mirage_crypto_pk.Rsa.priv
  | Sign_p256 of Mirage_crypto_ec.P256.Dsa.priv
  | Sign_p384 of Mirage_crypto_ec.P384.Dsa.priv
  | Sign_ed25519 of Mirage_crypto_ec.Ed25519.priv

val sign :
  alg:string ->
  ?kid:string ->
  ?extra_header:(string * Yojson.Safe.t) list ->
  signing_key ->
  Yojson.Safe.t ->
  string
(** [sign ~alg key claims] produces a compact JWS. [alg] is written verbatim into the
    header (so tests can forge headers); the signature is computed with [key] according to
    the key type and the hash implied by [alg] (SHA-256 when unknown). *)
