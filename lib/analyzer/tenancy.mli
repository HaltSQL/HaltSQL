(** Tenant isolation proofs (PLAN section 6.3, rule K) and tenant writes (rule M).

    This is the core security property of HaltSQL: every read of a tenant-scoped table
    must carry a predicate that provably restricts it to the caller's tenant, in the same
    SELECT level, and every write must keep rows inside the caller's tenant. The prover is
    deliberately syntactic and conservative: anything it cannot prove is denied
    ([E_TENANT_MISSING]), never assumed.

    {2 Read proofs}

    For every occurrence of a tenant-scoped policy table, in its own SELECT level, every
    tenant column must be proven by a conjunct of one of the occurrence's candidate
    locations. The walker computes the candidate locations:
    - the WHERE of the level whose FROM contains the occurrence (for UPDATE / DELETE:
      their WHERE, for the target and the FROM / USING items);
    - the ON quals of an INNER (or CROSS with quals) join on the path from the occurrence
      to the FROM root;
    - the ON quals of a LEFT join where the occurrence is on the right (nullable) side,
      and of a RIGHT join where it is on the left side. Never: ON quals of the preserved
      side, FULL join quals, HAVING, outer queries, inner subqueries.

    Inside a location only top-level AND chains are flattened; OR, NOT, CASE and
    everything else are opaque (a conjunct that is an OR proves nothing).

    A conjunct proves [col] for the occurrence when it has one of the shapes (operands may
    be reversed for [=]):
    - [col = <value>]
    - [col = ANY (<value>)]
    - [col IN (<values>)] where [col] is a column reference that resolves to exactly this
      occurrence's column (qualified by its alias/name, or unqualified and resolving to
      it), with no cast or COLLATE around it (a cast on the column side can change
      equality semantics), and where the operator is [=] or [pg_catalog.=].

    The value side may be wrapped in casts to a small set of value-preserving types
    ([text], [int2], [int4], [int8], [smallint], [integer], [int], [bigint], [uuid]);
    casts that could truncate or round (varchar(n), char(n), numeric(p,s), ...) or COLLATE
    break the proof, because the type modifier is not visible in the AST and a truncated
    tenant id would select a different tenant.

    Bound mode: the value is a placeholder [$n]; the proof binds [$n] to the context value
    ([= $n] and [IN ($n)] need a single context value; a [Many] context requires
    [= ANY($n)], which binds [Many]; [= ANY($n)] with a [One v] context binds [Many [v]]).
    Literals never prove in bound mode.

    Literal mode: the value is a string or integer literal. Integer literals are compared
    after integer normalization; string literals are compared exactly. With [Many vs],
    every literal of an IN list / ARRAY must be in [vs]. A literal that does not match is
    [E_TENANT_MISMATCH]. *)

open Haltsql_core

val check_level :
  Env.t ->
  Scope.t ->
  items:Scope.item list ->
  where:Ast.expr option ->
  quals:(int * Ast.expr) list ->
  unit
(** [check_level env scope ~items ~where ~quals] proves every tenant column of every
    tenant-scoped base occurrence among [items] (one SELECT level, or the target level of
    an UPDATE / DELETE). [where] is the level's WHERE; [quals] maps item ids to the join
    quals that are candidate locations for them (computed by the walker with the outer
    join rules above). [scope] must be the scope in which [where] and [quals] are
    resolved.

    For each (occurrence, tenant column) it emits [E_CONTEXT_MISSING] (once per tenancy
    key) when the context lacks the value, [E_TENANT_MISMATCH] for a conjunct that
    compares the column to a wrong value (or to a literal in bound mode), and
    [E_TENANT_MISSING] when no conjunct proves the column. In bound mode each proof
    records a placeholder binding with {!Env.add_binding}. *)

val check_insert_value :
  Env.t ->
  tb:Policy.table ->
  col:string ->
  key:string ->
  loc:int ->
  Ast.expr option ->
  unit
(** Rule M (INSERT): [check_insert_value env ~tb ~col ~key ~loc e] checks the value [e]
    written to tenant column [col] (tenancy key [key]) of table [tb] in one VALUES row
    ([None]: the row has no value for it). Bound mode requires a [$n] placeholder (bound
    to the single context value; a multi-valued context is denied as ambiguous); literal
    mode requires a literal equal to a context value. Anything else is [E_TENANT_WRITE].
*)
