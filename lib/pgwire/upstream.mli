(** Connections from the proxy to the real PostgreSQL server, using the service
    credentials from the config (never the client's).

    Supports TLS ([disable] / [require] / [verify-full]) and trust, cleartext (only over
    TLS), MD5 and SCRAM-SHA-256 authentication. The server's SCRAM signature is verified
    (mutual authentication). The startup always sets [client_encoding=UTF8] so the bytes
    HaltSQL verified are interpreted as UTF-8 by the server, and [search_path] so the
    server resolves unqualified names the way the verifier did. *)

exception Upstream_error of string
(** Connection, TLS or authentication failure. The message is safe to log (no secrets). *)

val connect :
  ?search_path:string list ->
  Proxy_config.upstream ->
  application_name:string option ->
  Io.t Lwt.t
(** Connects, negotiates TLS, sends the startup packet and completes authentication.
    Returns once AuthenticationOk was received; the caller then reads ParameterStatus /
    BackendKeyData / ReadyForQuery. [search_path] (see {!pinned_search_path}) is sent as
    the [search_path] startup parameter, which overrides any [ALTER ROLE] /
    [ALTER DATABASE] default; the caller must still confirm it took effect
    ({!search_path_matches}) before forwarding client statements. Sessions always pass it;
    without it the server's default applies (plain client use, e.g. benchmarks). *)

val pinned_search_path : string list -> string list
(** The schema list the upstream session is pinned to for a policy [search_path]: the
    policy's list, with [pg_temp] appended unless the policy places it itself. Listing
    [pg_temp] last stops PostgreSQL from searching temporary relations first, ahead of the
    schemas the verifier resolved the name in. [pg_catalog], when not listed, is searched
    first by both PostgreSQL and the verifier. *)

val search_path_value : string list -> (string, string) result
(** The GUC value: every name double-quoted (embedded quotes doubled), joined with [", "].
    [Error] for a name that cannot be sent (NUL byte). *)

val parse_search_path : string -> string list option
(** Splits a [search_path] value as PostgreSQL does (unquoted names lower-cased, quoted
    names verbatim). [None] when it is not a valid identifier list. *)

val search_path_matches : expected:string list -> string -> bool
(** Does a value reported by the server ([SHOW search_path], or a [search_path]
    ParameterStatus on PostgreSQL 18+) denote exactly the [expected] schema list? *)

val send_cancel : Proxy_config.upstream -> pid:int -> key:int -> unit Lwt.t
(** Opens a fresh connection (TLS if configured) and sends a CancelRequest. Never raises.
*)

val md5_password : user:string -> password:string -> salt:string -> string
(** ["md5" ^ md5hex(md5hex(password ^ user) ^ salt)]. *)
