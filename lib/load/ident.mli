(** SQL identifiers as written in policy and catalog documents.

    Policy documents name tables, columns, schemas and tenancy keys with SQL identifier
    syntax, and the loader stores them exactly as PostgreSQL would:
    - unquoted names are folded to lower case (ASCII only, like PostgreSQL);
    - double-quoted names keep their case; [""] inside quotes is a literal quote;
    - a name is at most 63 bytes (PostgreSQL's [NAMEDATALEN - 1]); longer names are
      rejected rather than silently truncated.

    Getting this right matters for security: the analyzer compares these stored names with
    the names libpg_query produces from the SQL, so a mismatch in folding rules would make
    an allowlist entry match the wrong relation or none at all.

    Used by the policy and catalog loaders and by [haltsql.catalog_tools]. *)

val parse_parts : ?lower_unquoted:bool -> string -> (string list, string) result
(** [parse_parts s] splits a dot-separated identifier path such as [app."Odd.Name"] into
    its parts ([["app"; "Odd.Name"]]). [lower_unquoted] (default [true]) folds unquoted
    parts to lower case; catalog snapshots pass [false] because they already hold names as
    PostgreSQL stores them. [Error msg] describes the first syntax problem (empty part,
    unterminated quote, unexpected character, name too long). *)

val parse_one : string -> (string, string) result
(** [parse_one s] parses a single (unqualified) identifier, folding it like [parse_parts].
*)

val render : string -> string
(** [render name] writes a stored name so that {!parse_one} gives it back: bare if that
    round-trips (e.g. [orders]), otherwise double-quoted with embedded quotes doubled
    (e.g. ["Orders"] or ["odd.name"]). *)

val render_qualified : string -> string -> string
(** [render_qualified schema name] is [render schema ^ "." ^ render name]. *)
