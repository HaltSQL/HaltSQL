(** Selecting an OIDC caller's policy from its IdP groups
    ([server.auth.oidc[].policy_from_groups]).

    Pure: works on the claims of a token whose signature, issuer, audience and lifetime
    {!Oidc.verify} has already checked.

    {1 Rules}

    + {b Overage.} When the identity provider signals that the groups did not fit in the
      token, the token is rejected with {!Jwt.Groups_overage}. Azure AD / Entra ID does
      this by omitting the groups claim and adding [_claim_names] (an object whose key is
      the claim name, e.g. [{"groups": "src1"}]) and [_claim_sources] (the Microsoft Graph
      endpoint to call), or, for implicit-flow tokens, [hasgroups: true]. HaltSQL never
      calls Graph: a partial group list could select the wrong policy, so it fails closed.
      The check runs first, even when the claim itself is also present.
    + {b Lookup.} The claim ([groups_claim], default ["groups"]) is looked up like
      [context_claims]: first as one top-level claim name (so
      ["https://corp.example/groups"] works), then as a dot path through nested objects
      (["realm_access.roles"], Keycloak). A missing claim is {!Jwt.Missing_claim}.
    + {b Shape.} A string is one group (never split on spaces); an array must contain only
      strings (it may be empty). Anything else is {!Jwt.Bad_claim}.
    + {b Selection.} The rules are walked in configuration order; the first rule whose
      group the token has wins, whatever the order of the groups in the token. Without a
      match the [default] policy is used; without a default the token is rejected with
      {!Jwt.No_group_policy}. Groups are compared exactly (case-sensitive). *)

type selection = {
  policy : string;
  matched_group : string option;  (** [None] when the default policy was used *)
  groups : string list;  (** the token's groups, as found in the claim *)
}

val lookup_claim : (string * Yojson.Safe.t) list -> string -> Yojson.Safe.t option
(** Exact top-level claim name first, then a dot path (at least two non-empty segments)
    through nested objects. *)

val overage : claim:string -> (string * Yojson.Safe.t) list -> bool
(** [true] when the claims carry a group-overage indicator for [claim]: [_claim_names] is
    an object with a key equal to [claim] or to its first dot-path segment, or [claim]'s
    first segment is ["groups"] and [hasgroups] is [true]. A [_claim_names] that is not an
    object is also treated as overage (fail closed). *)

val groups :
  Haltsql.Config.groups_policy ->
  (string * Yojson.Safe.t) list ->
  (string list, Jwt.error) result
(** The token's groups after the overage, lookup and shape checks. *)

val select :
  Haltsql.Config.groups_policy ->
  (string * Yojson.Safe.t) list ->
  (selection, Jwt.error) result
(** {!groups} then first-match selection. *)

val resolve :
  Haltsql.Config.groups_policy ->
  (string * Yojson.Safe.t) list ->
  (string, Jwt.error) result
(** The selected policy name ([(select g claims).policy]). *)
