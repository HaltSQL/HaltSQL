(** The haltsql-proxy listener: accepts connections, enforces [limits.max_connections],
    runs one {!Session} per connection and shuts down gracefully. *)

type t

val start : Proxy_config.t -> t Lwt.t
(** Binds [listen] (port 0 picks a free port) and starts accepting. Raises [Failure] if
    the TLS configuration is unusable or the address cannot be bound. *)

val port : t -> int
(** The bound port. *)

val active : t -> int
(** Number of open client connections. *)

val shutdown : t -> unit Lwt.t
(** Stops accepting, waits up to [shutdown_grace_seconds] for sessions to finish, then
    closes the remaining ones. Idempotent. *)

val wait : t -> unit Lwt.t
(** Resolves when {!shutdown} has completed. *)
