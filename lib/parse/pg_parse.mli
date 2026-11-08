(** PostgreSQL parsing via libpg_query, converted into {!Haltsql_core.Ast}.

    This is the first stage of the verification pipeline: [Haltsql.verify] calls {!parse}
    and hands the single resulting statement to [Haltsql_analyzer.Analyzer].

    {2 Fail-closed conversion}

    Every libpg_query node is checked against the exact set of fields the converter
    understands. Any unknown field, enum value or node type becomes an [Unsupported*]
    constructor (or [Other {kind = "Unsupported:..."}] for statements), which the analyzer
    always denies. Nothing that could carry semantics is silently dropped.

    {2 Totality}

    {!parse} and {!fingerprint} never raise. Every parse failure is an [Error reason]
    whose code is [E_PARSE] (syntax error), [E_LIMIT] (size or nesting limit) or
    [E_INTERNAL] (unexpected parser output). Empty input (only whitespace or comments) is
    [Ok []]. *)

open Haltsql_core

val parse : limits:Policy.limits -> string -> (Ast.stmt list, Reason.t) result
(** [parse ~limits sql] parses [sql] into statements, in source order.

    Limits are enforced in this order, each before any work that depends on it:
    + [limits.max_bytes] on the raw input;
    + a hard lexical bound on bracket nesting (cheap protection for the C parser);
    + [limits.max_depth] and [limits.max_nodes] on the libpg_query tree, measured
      iteratively before the recursive conversion runs.

    [Stack_overflow] and [Out_of_memory] raised while converting are reported as
    [E_LIMIT]; any other exception as [E_INTERNAL]. *)

val fingerprint : string -> string option
(** [fingerprint sql] is libpg_query's fingerprint of [sql] (equal for queries that differ
    only in literal values), or [None] if it does not parse, is unreasonably large, or
    nests too deeply. Used only to group verdicts; never for a security decision. *)

val postgres_version : string
(** PostgreSQL version of the bundled grammar, e.g. ["17.7"]. *)
