(** Conservative policy suggestions from denied and shadow-denied audit records.

    Only four kinds of change are ever suggested, each backed by evidence counts:
    - add a column to an already-listed table ([E_COLUMN_DENIED]);
    - add a function to [functions.allow] ([E_FUNCTION_DENIED]), never one with side
      effects or server access, and never a schema-qualified (user-defined) function;
    - raise [require_limit.max] ([E_LIMIT_TOO_HIGH]) to the largest constant LIMIT seen,
      within [limit_factor] times the current maximum and [limit_ceiling];
    - add a table ([E_TABLE_DENIED]) with the columns the queries actually read. In a
      policy with tenancy the new table is always tenant-scoped (on the tenant column(s)
      every existing tenant-scoped table uses); when that cannot be decided the suggestion
      is not applicable.

    Never suggested: anything about tenancy ([E_TENANT_*], [E_CONTEXT_MISSING]), writes or
    statement kinds, and anything for codes that need a query fix ([E_PARAM_UNBOUND],
    [E_UNSUPPORTED], [E_PARSE], ...). Columns that the PII lookup flags are reported in
    [pii_flagged] instead of being suggested. *)

open Haltsql_core

type change =
  | Add_column of { schema : string; table : string; column : string }
  | Add_function of string
  | Set_limit_max of { current : int; proposed : int }
  | Add_table of {
      schema : string;
      table : string;
      columns : string list;
      tenant_columns : (string * string) list;  (** (column, tenancy key) *)
    }

type evidence = {
  records : int;
  denied : int;
  shadow_denied : int;
  callers : (string * int) list;  (** most frequent first *)
  queries : int;  (** distinct fingerprints *)
}

type suggestion = {
  id : string;  (** stable, e.g. ["shop/column/app.orders.region"]; used by --accept *)
  policy : string;
  code : string;
  change : change;
  evidence : evidence;
  summary : string;  (** one sentence with the counts and the change *)
  yaml : string;  (** the exact YAML to merge into the policy *)
  notes : string list;  (** what to review *)
  applicable : bool;  (** [--apply-to] may apply it automatically *)
}

type category =
  | Pii  (** sensitive column: flagged, never suggested *)
  | Unsafe  (** e.g. a function with side effects, a system catalog *)
  | Query_fix  (** the query must change, not the policy *)
  | Never_weaken  (** tenancy, context, writes: never relaxed *)
  | Already_allowed  (** the loaded policy already allows it (older records) *)
  | Needs_review  (** a policy change might be right, but not automatically *)

type item = {
  i_policy : string;
  i_code : string;
  target : string;  (** e.g. ["app.customers.email"], ["pg_sleep"], ["LIMIT $1"] *)
  category : category;
  reason : string;
  i_evidence : evidence;
}

type code_row = {
  c_code : string;
  c_category : category;
  c_records : int;  (** records carrying the code *)
  advice : string;
}

type t = {
  suggestions : suggestion list;  (** most evidence first *)
  pii_flagged : item list;
  not_suggested : item list;  (** every other category *)
  codes : code_row list;
      (** per code that is never turned into a suggestion (query fixes and never-weaken),
          with advice *)
  missing_detail : int;
      (** denied records with a policy-fixable code but no detailed reasons: the report
          cannot name the object (enable raw SQL in the audit log and pass the policy, or
          read reports from the server endpoint) *)
}

type config = {
  policies : (string * Policy.t) list;  (** by policy name *)
  pii : Pii.lookup;
  verify : (Policy.t -> Context.t -> string -> Verdict.t) option;
      (** used to find the columns a query reads on a table that is not in the policy yet
          (probe with the table added); without it table suggestions are not applicable *)
  min_records : int;  (** evidence threshold, default 1 *)
  limit_factor : int;  (** default 10 *)
  limit_ceiling : int;  (** default 100000 *)
}

val default_config : config
val category_to_string : category -> string

val classify : Reason.code -> category option
(** [None] for the policy-fixable codes ([E_COLUMN_DENIED], [E_FUNCTION_DENIED],
    [E_LIMIT_TOO_HIGH], [E_TABLE_DENIED]); otherwise why the code never yields a
    suggestion. *)

val code_advice : Reason.code -> string

val unsafe_function : string -> string option
(** [Some why] for functions that must never be suggested. *)

val probe_context : Policy.t -> Context.t
(** A context with a placeholder for every tenancy field (used for re-verification when
    only the named objects matter, never for allow decisions). *)

val compute : config -> Record.t list -> t
val to_json : t -> Yojson.Safe.t
val evidence_to_json : evidence -> Yojson.Safe.t

val yaml_scalar : string -> string
(** A YAML scalar that loads back as exactly this string (plain when safe). *)
