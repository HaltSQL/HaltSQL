(** Pure AST helpers: locations and PostgreSQL-compatible output column names. *)

open Haltsql_core

val expr_loc : Ast.expr -> int
(** Byte offset of an expression ([-1] if unknown). *)

val target_name : Ast.target -> string
(** Output column name of a target, derived the way PostgreSQL's [FigureColname] does: the
    alias, else a name derived from the expression, else ["?column?"]. Only names
    PostgreSQL would produce are returned; when unsure the result is ["?column?"], which
    can only cause a conservative resolution failure, never a mis-resolution. *)

val is_star_target : Ast.target -> bool
(** [*] or [t.*]. *)

val syntactic_columns : Ast.select -> Scope.knowledge
(** Output columns of a SELECT computed from its syntax alone (no FROM resolution), used
    to pre-bind recursive CTEs before their bodies are analyzed. [At_least] when a [*]
    target is present. *)

val stmt_kind_of : Ast.stmt -> Policy.stmt_kind option
(** The policy statement kind of SELECT / INSERT / UPDATE / DELETE; [None] otherwise. *)
