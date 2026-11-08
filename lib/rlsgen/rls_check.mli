(** Drift detection between a HaltSQL policy (as planned by {!Rls_gen.plan}) and a live
    database. Read-only: everything runs inside [BEGIN READ ONLY ... ROLLBACK] and only
    reads the system catalogs and the [has_*_privilege] functions.

    Privileges are checked as EFFECTIVE privileges of the role (role membership and grants
    to PUBLIC included), so a grant made to PUBLIC or to a role the agent role is a member
    of is reported as over-broad too. *)

type severity =
  | Critical  (** the database grants more than the policy, or RLS does not hold *)
  | Warning  (** the database grants less than the policy (fails closed) *)

type finding = {
  kind : string;
      (** stable identifier: [role_missing], [role_bypasses_rls], [role_can_login],
          [schema_missing], [missing_grant], [over_broad_grant], [table_missing],
          [column_missing], [rls_disabled], [rls_not_forced], [role_owns_table],
          [policy_missing], [policy_mismatch], [unexpected_policy], [foreign_policy] *)
  severity : severity;
  obj : string;  (** the object concerned, e.g. ["app.orders"] *)
  message : string;
}

val severity_to_string : severity -> string

val check : Pg_wire.t -> Rls_gen.plan -> finding list Lwt.t
(** Findings sorted by (object, kind, message). Empty = no drift. Raises
    {!Pg_wire.Pg_error} / {!Pg_wire.Protocol_error} on database errors. *)

val finding_to_json : finding -> Yojson.Safe.t

val expression_matches : Rls_gen.tenant_term list -> string -> bool
(** Heuristic check that a deparsed policy expression ([pg_get_expr]) compares every
    tenant column with its setting: each setting literal and each column (as a whole
    identifier) occurs, there is exactly one [current_setting(] per term, and nothing that
    could widen a pure conjunction appears ([OR], [NOT], [IS], [CASE], or [true] other
    than the [missing_ok] argument of each [current_setting]). *)
