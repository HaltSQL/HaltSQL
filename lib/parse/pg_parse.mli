(** PostgreSQL parsing via libpg_query, converted into {!Haltsql_core.Ast}.

    Total: never raises. Every failure is an [Error reason] whose code is one of
    [E_PARSE], [E_EMPTY], [E_LIMIT] or [E_INTERNAL]. *)

open Haltsql_core

val parse : limits:Policy.limits -> string -> (Ast.stmt list, Reason.t) result
(** Parse [sql] into statements. Enforces [limits.max_bytes] before parsing and
    [limits.max_depth] / [limits.max_nodes] on the parse tree. Nodes the converter does
    not map become [Unsupported*] / [Other] constructors — never silently dropped. *)

val fingerprint : string -> string option
(** libpg_query fingerprint of [sql] (literals normalized), if it parses. *)

val postgres_version : string
(** Postgres grammar version of the bundled libpg_query, e.g. ["13"]. *)
