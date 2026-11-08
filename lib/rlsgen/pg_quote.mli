(** SQL quoting with exactly PostgreSQL's rules.

    [quote_ident] behaves like the server's [quote_ident()]: a name is left bare only when
    it consists of lower-case ASCII letters, digits and underscores, does not start with a
    digit, and is not a reserved / column-name / type-function-name keyword of the
    PostgreSQL 17 grammar. Everything else is double-quoted with embedded quotes doubled.
    Bare output is therefore always parsed back to the identical stored name. *)

val quoted_keywords : string list
(** Keywords that force quoting (every non-[UNRESERVED_KEYWORD] keyword). *)

val is_quoted_keyword : string -> bool
(** Membership in {!quoted_keywords} (lower-case input). *)

val needs_quotes : string -> bool
(** [true] iff {!quote_ident} would add double quotes. *)

val quote_ident : string -> string
(** Quote a stored identifier for use in SQL text. Raises [Invalid_argument] if the name
    contains a NUL byte. *)

val quote_qualified : schema:string -> name:string -> string
(** [schema.name], each part quoted with {!quote_ident}. *)

val quote_literal : string -> string
(** A string literal that is correct whatever [standard_conforming_strings] is set to:
    single quotes are doubled and, when the value contains a backslash, the literal uses
    the [E'...'] form with backslashes doubled (like the server's [quote_literal()]).
    Raises [Invalid_argument] if the value contains a NUL byte. *)

val dollar_quote : string -> string
(** [dollar_quote body] wraps [body] in a dollar-quote tag ([$haltsql$], or [$haltsqlN$])
    that does not occur inside [body]. *)
