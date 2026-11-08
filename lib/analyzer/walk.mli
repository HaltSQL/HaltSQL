(** The statement walker.

    Walks one statement top-down, building scopes level by level ({!Scope}), resolving
    every relation and column reference, applying the per-node rules ({!Rules}) and
    invoking the tenancy prover ({!Tenancy}) for each SELECT / DML level. Violations are
    emitted into the {!Env.t}; the walk never stops early, so every violation is reported.

    Rules implemented here:
    - B: SELECT hygiene (locking clauses, SELECT INTO, unsupported nodes);
    - D: relation resolution through the policy's search path, CTE visibility, column
      resolution (deny anything ambiguous);
    - E: column permissions, including [*] and whole-row references;
    - L: data-modifying statements inside WITH;
    - M: writes (target table, written and updated columns, tenant columns).

    {2 Invariants}

    - Every [match] over an AST type lists its constructors explicitly (no wildcard arms),
      so adding a constructor to {!Haltsql_core.Ast} breaks the build here instead of
      being silently accepted.
    - Every [Unsupported*] node and every unknown statement kind is denied
      ([E_UNSUPPORTED]).
    - Relations that are not policy tables are denied ([E_TABLE_DENIED]); an unqualified
      name resolves to a policy table only if no earlier search-path schema could contain
      a relation of that name (proved with a trusted catalog snapshot), and [pg_]-prefixed
      names that would resolve to [pg_catalog] are denied.
    - Catalog entries are trusted as complete column lists only when they carry column
      types (i.e. come from [haltsql schema pull]), so a [SELECT *] can never pass on the
      strength of a hand-written or derived column list.
    - WITH RECURSIVE is denied (its work cannot be bounded by LIMIT). *)

open Haltsql_core

type cx
(** Walk context: the visible scope levels and CTE names. *)

val empty_cx : cx
(** The context of a top-level statement: no enclosing levels, no CTEs. *)

val walk_select : Env.t -> cx -> outermost:bool -> Ast.select -> Scope.knowledge
(** Walks a SELECT (including its WITH, set operations and VALUES) and returns what is
    known about its output columns. [outermost] enables rule C ({!Rules.check_limit}). *)

val walk_insert : Env.t -> cx -> Ast.insert -> Scope.knowledge
(** Walks an INSERT. Only [INSERT ... VALUES] (and DEFAULT VALUES for tables without
    tenant columns) is analyzed; [INSERT ... SELECT] and [ON CONFLICT] are denied as
    unsupported. The column list must be explicit, every written column must be readable
    under the policy, and every tenant column must be set to the tenant value in every row
    ({!Tenancy.check_insert_value}). Returns the RETURNING list's knowledge. *)

val walk_update : Env.t -> cx -> Ast.update -> Scope.knowledge
(** Walks an UPDATE: the target must allow updates, assigned columns must be updatable,
    tenant columns may never be assigned, and the target (and every FROM item) needs a
    tenant proof in the WHERE. Returns the RETURNING list's knowledge. *)

val walk_delete : Env.t -> cx -> Ast.delete -> Scope.knowledge
(** Walks a DELETE: the target must allow deletes, and the target (and every USING item)
    needs a tenant proof in the WHERE. Returns the RETURNING list's knowledge. *)
