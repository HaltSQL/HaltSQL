(** Merging the authenticated context with the context supplied in a request body.

    When the caller's identity carries context (OIDC [context_claims] or a static mTLS
    [context]), the request body may only supply the fields listed in the identity's
    [request_context_fields]. Anything else is refused, never silently overridden. A body
    field that repeats an authenticated field with exactly the same value is accepted as a
    no-op, so clients that always send their context keep working. *)

val merge :
  authenticated:Haltsql.Context.t ->
  allowed:string list ->
  body:Haltsql.Context.t ->
  (Haltsql.Context.t, string list) result
(** [Ok ctx] is the authenticated context followed by the permitted body fields.
    [Error fields] lists, in body order, every body field that is neither permitted nor an
    identical repeat of an authenticated field. *)
