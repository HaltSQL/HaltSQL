(** JSON Web Keys (RFC 7517) for JWT signature verification.

    Only asymmetric public signing keys are supported: RSA (at least 2048 bits), EC P-256
    / P-384 and OKP Ed25519. Symmetric ([oct]) keys are never accepted, so an HMAC
    algorithm can never be verified with a key published in a JWKS. *)

type key =
  | Rsa of Mirage_crypto_pk.Rsa.pub
  | P256 of Mirage_crypto_ec.P256.Dsa.pub
  | P384 of Mirage_crypto_ec.P384.Dsa.pub
  | Ed25519 of Mirage_crypto_ec.Ed25519.pub

type t = {
  kid : string option;
  alg : string option;  (** the JWK's [alg] member, when present *)
  use : string option;  (** the JWK's [use] member, when present *)
  key : key;
}

val min_rsa_bits : int
(** 2048. *)

val max_rsa_bits : int
(** 8192: larger moduli are refused, so a JWKS cannot make every verification arbitrarily
    slow. *)

val of_json : Yojson.Safe.t -> (t, string) result
(** Parses one public JWK. Rejects symmetric keys, keys carrying private members ([d],
    [p], [q], ...), unsupported key types or curves, malformed coordinates, objects with
    duplicate members, a [key_ops] that is not an array of strings containing ["verify"],
    RSA moduli outside {!min_rsa_bits}..{!max_rsa_bits}, RSA public exponents that are
    even or below 3, and Ed25519 points of small order. Never raises. *)

val set_of_json : Yojson.Safe.t -> (t list * string list, string) result
(** Parses a JWK Set ([{"keys":[...]}]). Unusable entries are skipped; their problems are
    returned as the second component (no key material in the messages). [Error] only when
    the document is not a JWK Set (not an object, duplicate members, no ["keys"] array).
    Entries keep the order of the document. *)

val set_of_string : string -> (t list * string list, string) result
(** [set_of_json] on JSON text. *)

val compatible : Haltsql.Config.jwt_alg -> t -> bool
(** Whether this key may verify a token signed with the algorithm: the key type must match
    the algorithm family (RS*/PS* need RSA, ES256 needs P-256, ES384 needs P-384, EdDSA
    needs Ed25519), [use] must be absent or ["sig"], and [alg], when present, must name
    the same algorithm. *)

(** {1 Encoding (for tests and tooling)} *)

val to_json : t -> Yojson.Safe.t
(** The public JWK. *)
