(** Context-free rules: statement kinds (A), LIMIT (C), functions and SQL value functions
    (F), operators (G) and casts (H).

    Each [check_*] function inspects one node and {!Env.emit}s a reason for every
    violation; none of them raises or stops the walk. Allowlists are exact: a name is
    allowed only if it is listed (deny by default). *)

open Haltsql_core

val kind_allowed : Env.t -> Policy.stmt_kind -> bool
(** Whether the policy's [statements] list contains the kind. *)

val allowed_kinds_text : Env.t -> string
(** The allowed statement kinds as text, for hints (["none"] if empty). *)

val check_stmt_kind : Env.t -> Policy.stmt_kind -> int -> unit
(** Rule A: a SELECT / INSERT / UPDATE / DELETE must be listed in [policy.statements]
    ([E_STATEMENT_KIND]). *)

val check_function : Env.t -> Ast.qname -> int -> unit
(** Rule F: an unqualified or [pg_catalog.]-qualified function must be in
    [policy.functions] by bare name (a ["pg_catalog.f"] entry is accepted too); a function
    in any other schema [s] must be listed as ["s.f"] ([E_FUNCTION_DENIED]). *)

val check_sql_value : Env.t -> string -> int -> unit
(** Rule F: SQL value functions. Date/time values (CURRENT_DATE, CURRENT_TIME[STAMP],
    LOCALTIME[STAMP]) are allowed; identity and session values (CURRENT_USER,
    SESSION_USER, USER, CURRENT_ROLE, CURRENT_CATALOG, CURRENT_SCHEMA) are denied
    ([E_FUNCTION_DENIED]). *)

val check_operator_name : Env.t -> string list -> int -> unit
(** Rule G: an operator name ([["="]] or [["pg_catalog"; "="]]) must be in
    [policy.operators]; an operator qualified with any other schema is always denied
    ([E_OPERATOR_DENIED]). *)

val check_aexpr : Env.t -> Ast.aexpr_kind -> string list -> int -> unit
(** Rule G for an [A_expr]: operator kinds (including LIKE [~~], ILIKE [~~*] and SIMILAR
    TO [~] and their negations) are checked with {!check_operator_name}; IS [NOT] DISTINCT
    FROM, NULLIF and the BETWEEN forms are built-in syntax and always allowed. *)

val type_base : Ast.type_name -> string
(** Lower-cased last component of a type name ([pg_catalog.int4] -> ["int4"]). *)

val check_cast : Env.t -> Ast.type_name -> int -> unit
(** Rule H: a cast to a type in [policy.deny_casts] (compared by {!type_base}) is denied
    ([E_CAST_DENIED]). *)

val check_limit : Env.t -> Ast.select -> unit
(** Rule C: when the policy has [require_limit = Some max], the outermost SELECT must have
    an integer constant [LIMIT n] with [0 <= n <= max] (casts around the constant are
    accepted). A missing LIMIT, [LIMIT ALL] or [LIMIT NULL] is [E_LIMIT_REQUIRED]; any
    other value is [E_LIMIT_TOO_HIGH]. *)
