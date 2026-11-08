(** Small pure helpers shared by the analyzer modules. All functions are total. *)

val sort_uniq_strings : string list -> string list
(** Sorted, without duplicates. *)

val dedupe : 'a list -> 'a list
(** Removes structurally equal elements, keeping the first occurrence and the original
    order. Quadratic; used on short lists (reasons, bound values). *)

val last : 'a list -> 'a option
(** Last element, if any. *)

val drop : int -> 'a list -> 'a list
(** [drop n l] is [l] without its first [n] elements ([[]] if [l] is shorter; [l] if
    [n <= 0]). *)

val index_of : string -> string list -> int option
(** 0-based position of the first element equal to the string. *)

val is_int_literal : string -> bool
(** An optional sign followed by at least one ASCII digit, and nothing else. *)

val normalize_int : string -> string
(** Canonical decimal text of an integer literal: no ['+'], no leading zeros, ["-0"] ->
    ["0"]. Works on arbitrarily long digit strings (no overflow). Strings that are not
    integer literals are returned unchanged. Used to compare tenant literals with context
    values. *)

val contains_ci : sub:string -> string -> bool
(** ASCII case-insensitive substring test; the empty [sub] is contained in everything. *)

val opt_list : 'a option -> 'a list
(** [[x]] for [Some x], [[]] for [None]. *)

val is_unsupported_kind : string -> bool
(** Whether a statement kind is the parser's [Unsupported:<what>] marker (see
    {!Haltsql_core.Ast.Other}). *)

val unsupported_what : string -> string
(** The [<what>] of an [Unsupported:<what>] kind; other kinds are returned unchanged. *)
