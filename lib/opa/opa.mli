(** The optional Open Policy Agent check ([opa] in the server configuration).

    After {!Haltsql.verify} has {b allowed} a query, the server asks OPA for a second
    opinion with [POST {url}/v1/data/{decision_path}] and the body [{"input": ...}] (see
    {!input_to_json}). OPA can only turn an allow into a deny, never the reverse: a query
    HaltSQL denies is denied without asking OPA ({!check} returns [Skipped]).

    {1 Decision}

    The response must be HTTP 200 with a JSON object. Its [result] must be either a
    boolean, or an object with a boolean [allow] and an optional [reasons] array of
    strings (no other keys). A missing [result] (undefined decision, e.g. a wrong
    [decision_path]), any other shape, a non-200 status, a timeout or a connection failure
    is an {e error}, handled by [on_error]: [deny] (the default) denies the query,
    [allow_haltsql_verdict] keeps HaltSQL's verdict.

    {1 What is sent}

    Only verdict metadata: the caller's name and type, the policy name and version, the
    statement kind, tables, columns, reason codes, [allowed], the SQL's SHA-256 and
    fingerprint, and the {e names} of the context fields. Never the SQL text, the context
    values, tokens or the subject. Error strings never contain header values. *)

type caller = {
  caller_name : string;
  caller_type : string;  (** token|oidc|mtls|anonymous *)
}

type input = {
  caller : caller;
  policy : string;
  policy_version : string;
  statement_kind : string option;
  tables : string list;
  columns : string list;
  reasons : string list;  (** reason codes of [verdict.reasons] *)
  shadow_reasons : string list;  (** reason codes of [verdict.shadow_reasons] *)
  allowed : bool;
  sql_sha256 : string;
  fingerprint : string option;
  context_keys : string list;  (** sorted, unique field names; never values *)
}

val input_of_verdict :
  caller:caller -> context:Haltsql.Context.t -> Haltsql.Verdict.t -> input

val input_to_json : input -> Yojson.Safe.t
(** The [input] document:
    [{"caller": {"name", "type"}, "policy", "policy_version", "statement_kind", "tables",
     "columns", "reasons", "shadow_reasons", "allowed", "sql_sha256", "fingerprint",
     "context_keys"}] ([statement_kind] and [fingerprint] may be [null]). *)

(** {1 Pure parts} *)

type decision = Allow | Deny of string list  (** OPA's reasons, sanitized *)

val max_reasons : int
(** At most 16 reasons are kept; each is truncated to 200 bytes and stripped of control
    characters. *)

val parse_response : status:int -> string -> (decision, string) result
(** See the module documentation. *)

val decision_url : Haltsql.Config.opa -> (Uri.t, string) result
(** [{url}/v1/data/{decision_path}] (a trailing [/] of [url] is dropped). Re-checks that
    [url] is https or loopback http without credentials, query or fragment. *)

type outcome =
  | Skipped  (** HaltSQL denied the query; OPA was not asked *)
  | Allowed  (** OPA allowed *)
  | Denied of string list  (** OPA denied, with its reasons *)
  | Failed_open of string  (** OPA failed; [on_error: allow_haltsql_verdict] *)
  | Failed_closed of string  (** OPA failed; [on_error: deny] *)

val outcome_of_result : Haltsql.Config.opa -> (decision, string) result -> outcome

val outcome_label : outcome -> string
(** ["skipped"], ["allowed"], ["denied"], ["error_allowed"], ["error_denied"]: for metrics
    and logs. *)

val reasons_of_outcome :
  code:Haltsql.Reason.code -> Haltsql.Config.opa -> outcome -> Haltsql.Reason.t list
(** The reasons a denying outcome adds (rule ["opa.decision"]): one per OPA reason, or one
    generic reason when OPA gave none or failed. [[]] for the other outcomes. [code] is
    the external-policy reason code. *)

val apply :
  code:Haltsql.Reason.code ->
  mode:Haltsql.Policy.mode ->
  Haltsql.Config.opa ->
  Haltsql.Verdict.t ->
  outcome ->
  Haltsql.Verdict.t
(** Combines HaltSQL's verdict with OPA's outcome. A denying outcome ([Denied],
    [Failed_closed]) on an allowed verdict sets [allowed = false], clears [bind_params]
    and appends {!reasons_of_outcome} to [reasons] in enforce mode, or appends them to
    [shadow_reasons] (leaving [allowed] true) in shadow mode. Every other combination
    returns the verdict unchanged; in particular [apply] never sets [allowed] to [true].
*)

(** {1 IO} *)

val check : cfg:Haltsql.Config.opa -> input:input -> outcome Lwt.t
(** [Skipped] when [input.allowed] is false; otherwise one decision request with
    [timeout_ms] as the hard deadline, the configured [headers] and, for an https url with
    [tls.ca_file], only that CA trusted. Never raises. *)

val enforce :
  code:Haltsql.Reason.code ->
  mode:Haltsql.Policy.mode ->
  cfg:Haltsql.Config.opa ->
  caller:caller ->
  context:Haltsql.Context.t ->
  Haltsql.Verdict.t ->
  (Haltsql.Verdict.t * outcome) Lwt.t
(** [check] then [apply]: what the server calls right after [Haltsql.verify]. *)
