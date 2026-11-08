(** Policy analysis of one parsed statement: the second stage of the verification
    pipeline, after [Haltsql_parse.Pg_parse] and before [Haltsql.verify] builds the
    verdict.

    {2 Guarantees}

    - {b Deny by default.} A statement is allowed only if every rule below positively
      accepts it; anything the analyzer does not understand ([Unsupported*] nodes, unknown
      statement kinds, ambiguous names) is denied.
    - {b Total.} {!analyze} never raises. Any exception escaping a rule (an analyzer bug,
      or [Stack_overflow] / [Out_of_memory]) is turned into a single [E_INTERNAL] reason,
      so a failure always denies.
    - {b Pure.} No I/O and no global mutable state: one private accumulator per call, so
      it is safe to call from many domains at once. The result depends only on its
      arguments. *)

open Haltsql_core

type analysis = {
  reasons : Reason.t list;
      (** empty iff the statement is allowed; in emission order, identical reasons removed
      *)
  statement_kind : Policy.stmt_kind option;
      (** for SELECT / INSERT / UPDATE / DELETE (also under EXPLAIN) *)
  tables : string list;  (** qualified relations touched, sorted, unique *)
  columns : string list;  (** ["schema.table.column"] read, sorted, unique *)
  bind_params : (int * Context.value) list;
      (** bound tenancy mode: [(n, value)] the caller must bind to [$n], sorted by [n].
          Only meaningful when [reasons = []]. *)
}

val analyze : Policy.t -> Context.t -> Ast.stmt -> analysis
(** [analyze policy ctx stmt] checks [stmt] against [policy] for the caller described by
    [ctx]. All violations are collected, not just the first.

    Rule families (internal module that implements each in brackets):
    - A statement kinds and EXPLAIN (never EXPLAIN ANALYZE) [Analyzer, Rules]
    - B SELECT hygiene: locking clauses, SELECT INTO, unsupported nodes [Walk]
    - C [require_limit] on the outermost SELECT [Rules]
    - D name resolution and scopes [Scope, Walk]
    - E column permissions, including [*] and whole-row references [Walk]
    - F functions and SQL value functions [Rules]
    - G operators [Rules]
    - H casts [Rules]
    - I join budget ([limits.max_joins]) [Analyzer; joins counted by Walk]
    - J parameters: every [$n] must be a tenant placeholder bound by a tenancy proof, and
      a tenant placeholder may appear only as the value of its tenant predicate (any other
      use could change the type PostgreSQL infers for it) [Analyzer]
    - K tenancy proofs [Tenancy]
    - L data-modifying CTEs [Walk]
    - M writes [Walk, Tenancy]

    A placeholder that would have to be bound to two different values is denied
    ([E_TENANT_MISMATCH]). *)
