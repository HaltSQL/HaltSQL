(** Static bearer-token authentication ([server.auth.tokens]).

    Tokens are configured as SHA-256 hex digests, never in clear. The presented token is
    hashed and compared in constant time against every configured digest (the scan never
    stops early), so timing reveals neither which token matched nor whether one did. *)

val sha256_hex : string -> string
(** Lower-case hex SHA-256 of a string. *)

val ct_equal : string -> string -> bool
(** Equality whose running time depends only on the length of the first argument. *)

(** Result of checking an [Authorization] header. *)
type outcome =
  | Missing  (** no Authorization header *)
  | Invalid  (** malformed header or unknown token *)
  | Token of Haltsql.Config.token  (** the configured token that matched *)

val authenticate : Haltsql.Config.token list -> string option -> outcome
(** [authenticate tokens header] checks an [Authorization: Bearer <token>] header value
    (the scheme is case-insensitive). *)
