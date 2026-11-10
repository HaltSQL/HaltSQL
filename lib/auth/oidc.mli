(** Pure OIDC access-token verification against one configured provider.

    Given the provider configuration, its current signing keys and the current time,
    {!verify} checks, in order: the compact JWS shape, the algorithm allowlist (never
    [none] or HMAC), the [kid] and key type, the signature, [iss] (exact match), [aud] (a
    string, or an array of strings, containing one of [audiences]), [exp] (required),
    [nbf] and [iat] (with [leeway_seconds]), [required_claims], then selects the policy
    and derives the context from [context_claims].

    With [~groups] (the provider's [policy_from_groups], see
    {!Haltsql.Config.groups_policy_of}) the policy is selected by {!Group_policy.select}
    instead of [oidc_policy]; its errors ({!Jwt.Groups_overage}, {!Jwt.No_group_policy},
    [Missing_claim], [Bad_claim]) reject the token. Without it, a provider configured with
    [policy_from_groups] carries a placeholder [oidc_policy] that rejects every token
    (fail closed). *)

type identity = {
  provider : string;  (** [oidc_name] *)
  issuer : string;
  subject : string option;  (** the [sub] claim, when it is a string *)
  policy : string;  (** the selected (pinned or claim-selected) policy *)
  context : Haltsql.Context.t;  (** derived from [context_claims] *)
  request_context_fields : string list;
      (** context fields the request body may still supply *)
  expires_at : float;  (** the [exp] claim *)
  matched_group : string option;
      (** with [policy_from_groups]: the group whose rule selected [policy] ([None] when
          the default policy was used, and for pinned or claim-selected policies) *)
}

val verify :
  ?groups:Haltsql.Config.groups_policy ->
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

val claim_matches : ?name:string -> Yojson.Safe.t -> Haltsql.Config.claim_match -> bool
(** See {!Haltsql.Config.claim_match}. *)

val context_value : Yojson.Safe.t -> Haltsql.Context.value option
(** String or integral number -> [One]; non-empty array of those -> [Many]; anything else
    (objects, booleans, null, fractions, empty arrays) -> [None]. *)
