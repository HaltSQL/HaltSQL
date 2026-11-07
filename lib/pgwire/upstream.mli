(** Connections from the proxy to the real PostgreSQL server, using the service
    credentials from the config (never the client's).

    Supports TLS ([disable] / [require] / [verify-full]) and trust, cleartext (only over
    TLS), MD5 and SCRAM-SHA-256 authentication. The server's SCRAM signature is verified
    (mutual authentication). The startup always sets [client_encoding=UTF8] so the bytes
    HaltSQL verified are interpreted as UTF-8 by the server. *)

exception Upstream_error of string
(** Connection, TLS or authentication failure. The message is safe to log (no secrets). *)

val connect : Proxy_config.upstream -> application_name:string option -> Io.t Lwt.t
(** Connects, negotiates TLS, sends the startup packet and completes authentication.
    Returns once AuthenticationOk was received; the caller then reads ParameterStatus /
    BackendKeyData / ReadyForQuery. *)

val send_cancel : Proxy_config.upstream -> pid:int -> key:int -> unit Lwt.t
(** Opens a fresh connection (TLS if configured) and sends a CancelRequest. Never raises.
*)

val md5_password : user:string -> password:string -> salt:string -> string
(** ["md5" ^ md5hex(md5hex(password ^ user) ^ salt)]. *)
