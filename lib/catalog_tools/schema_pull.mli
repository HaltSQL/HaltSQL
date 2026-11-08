(** [haltsql schema pull]: build a catalog snapshot from a live PostgreSQL database.

    Reads [pg_catalog] (not [information_schema.columns], which silently hides columns the
    connecting role has no privilege on: an incomplete column list would be trusted by the
    analyzer as complete). Every relation that a query can name in [FROM] is included:
    tables, partitioned tables, partitions, views, materialized views, foreign tables and
    sequences, so that the analyzer's search-path shadowing checks see the whole schema.
    Column types are [lower(format_type(atttypid, atttypmod))]; ordering is by schema,
    relation (byte order), then column position.

    The work runs in a [READ ONLY] [REPEATABLE READ] transaction (and the session is
    opened with [default_transaction_read_only=on]); it is always rolled back. *)

type row = {
  nspname : string;
  relname : string;
  relkind : char;  (** pg_class.relkind *)
  relispartition : bool;
  attname : string option;  (** [None] for a relation without columns *)
  atttype : string option;
}

val catalog_query : string
(** The introspection query; [$1] is a JSON array of schema names, or NULL for every user
    schema. *)

val build :
  ?database:string ->
  ?server_version:string ->
  schemas:string list ->
  row list ->
  Snapshot.t * string list
(** Pure part: rows -> snapshot plus warnings (relations without columns are skipped;
    requested schemas without relations are reported). *)

val pull :
  ?timeout:float ->
  ?schemas:string list ->
  Pg_dsn.t ->
  (Snapshot.t * string list, string) result
(** Connects, introspects, disconnects. [timeout] bounds the connection (default 10 s);
    the query runs with [statement_timeout = 120s]. Errors never contain the password. *)
