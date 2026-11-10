(** The haltsql-proxy listener: accepts connections, enforces [limits.max_connections],
    runs one {!Session} per connection and shuts down gracefully. *)

type t

val start :
  ?reload:(unit -> (Proxy_config.t, string list) result) -> Proxy_config.t -> t Lwt.t
(** Binds [listen] (port 0 picks a free port), opens the audit sinks and starts accepting.
    Raises [Failure] if the TLS configuration is unusable, an audit sink cannot be opened
    or the address cannot be bound.

    [reload] loads a fresh configuration (the config file and its policies); without it
    {!reload} is unavailable. With it, and [reload.watch] in the config, the files in
    [source_files] are polled every [reload.poll_interval] seconds and a change triggers
    {!reload}. *)

val reload : t -> trigger:string -> (unit, string list) result Lwt.t
(** Loads a new configuration and makes it the snapshot for new connections. Live sessions
    that it changes ({!Session.stale}) are asked to end at their next transaction boundary
    unless [reload.terminate_changed_sessions] is false; the others keep their snapshot.
    On any error (load, validation, TLS material) the current configuration stays in
    force, the error is logged and counted. A changed listen address or audit sink list is
    ignored with a warning (both need a restart). Reloads are serialized. [trigger] (e.g.
    ["sighup"], ["watch"]) is logged. *)

val generation : t -> int
(** 1 at start, +1 per successful reload. *)

val config : t -> Proxy_config.t
(** The current configuration (what new connections get). *)

val reload_stats : t -> Yojson.Safe.t
(** [{generation, reloads, reload_failures, last_reload_error?}]. *)

val port : t -> int
(** The bound port. *)

val active : t -> int
(** Number of open client connections. *)

val unauthenticated : t -> int
(** How many of them have not finished authentication. Each source address may hold at
    most [limits.max_unauthenticated_per_ip] of these; further connections from it are
    refused with FATAL 53300 until one authenticates or closes. *)

val shutdown : t -> unit Lwt.t
(** Stops accepting, waits up to [shutdown_grace_seconds] for sessions to finish, closes
    the remaining ones, then flushes and closes the audit sinks. Idempotent. *)

val wait : t -> unit Lwt.t
(** Resolves when {!shutdown} has completed. *)
