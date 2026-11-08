(** A small, read-mostly PostgreSQL client (frontend/backend protocol 3.0, simple query
    protocol, text results).

    It exists because [pgx] cannot authenticate against servers that use [scram-sha-256]
    (the PostgreSQL 14+ default). Supports SCRAM-SHA-256 (with server signature
    verification), MD5, and cleartext passwords (cleartext only over TLS), and TLS via
    [sslmode]. Passwords are never included in error messages. *)

type sslmode =
  | Disable
  | Prefer  (** TLS when the server offers it, without certificate verification *)
  | Require  (** TLS mandatory, without certificate verification (libpq semantics) *)
  | Verify_full  (** TLS mandatory, system CA trust store, host name checked *)

type dsn = {
  host : string;  (** host name, IP address, or a directory holding the Unix socket *)
  port : int;
  user : string;
  password : string option;
  database : string;
  sslmode : sslmode;
  connect_timeout : float;  (** seconds *)
}

val parse_dsn : ?env:(string -> string option) -> string -> (dsn, string) result
(** Parses [postgres://user:password@host:port/dbname?sslmode=...&connect_timeout=...]
    (also [postgresql://]). Percent-escapes are decoded. Missing parts default like libpq:
    host [localhost], port [5432], user [$PGUSER] or [$USER], password [$PGPASSWORD],
    database = user, sslmode [prefer]. Unknown query parameters are rejected. [env]
    defaults to [Sys.getenv_opt]. *)

val dsn_to_string_redacted : dsn -> string
(** [postgres://user@host:port/db?sslmode=...] without the password. *)

exception Pg_error of { code : string; message : string; detail : string option }
(** An ErrorResponse from the server (SQLSTATE [code]). *)

exception Protocol_error of string
(** Connection, TLS, authentication or protocol failure. *)

type t

val connect : dsn -> t Lwt.t
(** Connects and authenticates. Raises {!Protocol_error} or {!Pg_error}. *)

val query : t -> string -> string option list list Lwt.t
(** Runs a simple query (may contain several statements) and returns the data rows of the
    last result set. Raises {!Pg_error} if any statement failed (the server then has
    rolled back the implicit transaction, or aborted the explicit one). *)

val exec : t -> string -> unit Lwt.t
(** [query] ignoring rows. *)

val close : t -> unit Lwt.t
(** Sends Terminate and closes the socket. Never raises. *)

val with_connection : dsn -> (t -> 'a Lwt.t) -> 'a Lwt.t
(** [connect], run, [close] (also on exceptions). *)
