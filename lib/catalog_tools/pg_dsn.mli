(** PostgreSQL connection strings.

    Accepts both libpq forms:
    - URL: [postgres://user:password@host:port/dbname?sslmode=require]
      ([postgresql://] too; percent-encoding is decoded; IPv6 hosts in brackets);
    - keyword/value: [host=db.internal port=5432 user=ro dbname=app sslmode=verify-full]
      (values may be single-quoted, with [\\'] and [\\\\] escapes).

    Missing fields fall back to the libpq environment variables [PGHOST], [PGPORT],
    [PGUSER], [PGDATABASE], [PGPASSWORD], [PGSSLMODE], [PGSSLROOTCERT], then to built-in
    defaults. Unknown parameters are rejected (fail closed: a typo such as [sslmod=] must
    not silently disable TLS).

    SECURITY: the password is never part of any string this module produces; use
    {!redacted} for messages. *)

type sslmode =
  | Disable  (** never use TLS *)
  | Prefer  (** TLS if the server supports it (no certificate check), else plaintext *)
  | Require  (** TLS required, certificate not verified (libpq semantics) *)
  | Verify_ca  (** TLS required, chain verified against [sslrootcert] or system CAs *)
  | Verify_full  (** as [Verify_ca], plus the host name must match the certificate *)

val sslmode_to_string : sslmode -> string

val sslmode_of_string : string -> sslmode option
(** ["allow"] is accepted as an alias of ["prefer"]. *)

type t = {
  host : string;
      (** host name, IP address, or a Unix-socket directory (starts with [/]) *)
  port : int;
  user : string;
  password : string option;
  dbname : string;
  sslmode : sslmode;
  sslrootcert : string option;  (** PEM file with trusted CA certificates *)
  connect_timeout : float option;  (** seconds *)
  application_name : string option;
}

val parse : ?env:(string -> string option) -> string -> (t, string) result
(** [env] defaults to [Sys.getenv_opt]. When the DSN gives no [sslmode] (and [PGSSLMODE]
    is unset) the default is [Prefer] for loopback hosts and Unix sockets and [Require]
    for everything else. Error messages never contain the password. *)

val is_loopback : string -> bool
(** [localhost], [127.0.0.0/8], [::1], or a Unix-socket directory. *)

val redacted : t -> string
(** [postgres://user@host:port/dbname?sslmode=...], without the password. *)
