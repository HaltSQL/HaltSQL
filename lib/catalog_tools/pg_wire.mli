(** Minimal PostgreSQL frontend/backend protocol (v3) client, just enough for catalog
    introspection and test setup.

    Supports TLS ([sslmode] from {!Pg_dsn}), SCRAM-SHA-256 (with server-signature
    verification), MD5 and trust authentication. Cleartext password authentication is
    refused unless the connection is TLS-protected or to a loopback host. Results are
    returned in text format.

    Every function may fail with {!Error}; messages never contain the password. *)

exception Error of string

type conn

val connect : ?timeout:float -> ?read_only:bool -> Pg_dsn.t -> conn Lwt.t
(** Connects and authenticates. [timeout] (seconds; default: the DSN's [connect_timeout],
    else 10) bounds the TCP connect, TLS handshake and authentication. Extra startup
    settings sent to the server: [application_name], [client_encoding=UTF8] and, unless
    [read_only] is [false] (default [true]; only tests set it),
    [default_transaction_read_only=on]. *)

val server_parameter : conn -> string -> string option
(** A [ParameterStatus] value reported by the server, e.g. ["server_version"]. *)

val tls : conn -> bool
(** Whether the connection is encrypted. *)

type row = string option array

val simple_query : conn -> string -> row list Lwt.t
(** Runs one or more ';'-separated statements with the simple query protocol and returns
    the rows of the last statement that returned rows. Raises {!Error} with the server's
    message (["ERROR 42P01: ..."]) on failure; the connection stays usable. *)

val query : conn -> string -> params:string option list -> row list Lwt.t
(** One statement with [$1..$n] text parameters (extended query protocol). Parameters are
    sent out of band, never interpolated into SQL. *)

val close : conn -> unit Lwt.t
(** Sends Terminate and closes the socket; never raises. *)

val with_conn :
  ?timeout:float -> ?read_only:bool -> Pg_dsn.t -> (conn -> 'a Lwt.t) -> 'a Lwt.t
(** [connect], run, then [close] (also on failure). *)
