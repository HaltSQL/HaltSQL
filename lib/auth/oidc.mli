(** Pure OIDC access-token verification against one configured provider.

    Given the provider configuration, its current signing keys and the current time,
    {!verify} checks, in order: the compact JWS shape, the algorithm allowlist (never
    [none] or HMAC), the [kid] and key type, the signature, [iss] (exact match), [aud]
    (contains one of [audiences]), [exp] (required), [nbf] and [iat] (with
    [leeway_seconds]), [required_claims], then selects the policy and derives the context
    from [context_claims]. *)

type identity = {
  provider : string;  (** [oidc_name] *)
  issuer : string;
  subject : string option;  (** the [sub] claim, when it is a string *)
  policy : string;  (** the selected (pinned or claim-selected) policy *)
  context : Haltsql.Context.t;  (** derived from [context_claims] *)
  request_context_fields : string list;
      (** context fields the request body may still supply *)
  expires_at : float;  (** the [exp] claim *)
}

val verify :
  Haltsql.Config.oidc_provider ->
  keys:Jwk.t list ->
  now:float ->
  string ->
  (identity, Jwt.error) result
(** [verify provider ~keys ~now token]: the verified identity, or the first failed check
    (see the module description for the order). Pure and total: never raises, never
    performs IO. Error values never contain the token. *)

val lookup_claim : (string * Yojson.Safe.t) list -> string -> Yojson.Safe.t option
(** Looks a path up as one top-level claim name first, then as a dot path through nested
    objects. *)

val claim_matches : Yojson.Safe.t -> Haltsql.Config.claim_match -> bool
(** See {!Haltsql.Config.claim_match}. *)

val context_value : Yojson.Safe.t -> Haltsql.Context.value option
(** String or integral number -> [One]; non-empty array of those -> [Many]; anything else
    (objects, booleans, null, fractions, empty arrays) -> [None]. *)
