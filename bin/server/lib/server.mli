(** Listener, connection limits, signals, hot-reload watcher and process lifecycle for
    haltsql-server.

    {b Connections.} The server runs its own accept loop over cohttp. Each listener
    accepts at most [max_connections] connections at once; at the limit it stops accepting
    (clients wait in the kernel's listen backlog) rather than accepting and refusing.
    cohttp has no timeouts or size limits of its own, so each connection's byte streams
    are wrapped:
    - between requests a connection may stay silent for [idle_timeout] seconds;
    - once the first byte of a request has arrived, its head and body must arrive within
      [request_timeout] seconds, and the head may not exceed [max_header_bytes]
      (slowloris, unbounded headers);
    - a response write that makes no progress for [idle_timeout] seconds fails;
    - the TLS handshake must complete within 10 seconds.

    On any of these the connection is closed.

    {b Shutdown.} On SIGTERM or SIGINT the listeners close, {!State.t.draining} is set
    ([/readyz] answers 503 and responses carry [connection: close]), idle keep-alive
    connections are closed, and in-flight requests get [shutdown_timeout] seconds to
    complete before the remaining connections are closed. Batching audit sinks and the
    OTLP exporter are then flushed. *)

exception Startup_error of string
(** A configuration problem detected while starting (bad listen address, bind failure,
    invalid telemetry endpoint). *)

val parse_listen : string -> (string * int, string) result
(** Parses ["host:port"], ["[v6]:port"], [":port"] or ["*:port"] (the last two bind every
    IPv4 address). *)

val bind_listen : string -> Lwt_unix.file_descr * int
(** Binds and listens on an address; returns the socket and the actual port (useful with
    port 0). Raises {!Startup_error}. *)

(** {1 Limits} *)

type limits = {
  max_connections : int;  (** simultaneous connections on the main listener *)
  request_timeout : float;
      (** seconds to receive a request's head and body once its first byte arrived *)
  idle_timeout : float;
      (** seconds a connection may stay silent between requests, or a write may stall *)
  max_header_bytes : int;  (** maximum size of a request head *)
  shutdown_timeout : float;  (** seconds in-flight requests get on shutdown *)
}

val default_limits : limits
(** 1024 connections, 30 s request timeout, 60 s idle timeout, 64 KiB request heads, 15 s
    shutdown timeout. *)

val health_max_connections : int
(** Connection limit of the [--health-listen] listener (64), separate from the main
    listener's so probes keep working while it is saturated. *)

val validate_limits : limits -> (unit, string) result
(** Rejects non-positive limits. *)

(** {1 Running} *)

val serve :
  ?watch_interval:float ->
  ?health_fd:Lwt_unix.file_descr ->
  ?limits:limits ->
  State.t ->
  Lwt_unix.file_descr ->
  stop:unit Lwt.t ->
  unit Lwt.t
(** [serve st fd ~stop] serves HTTP (or HTTPS when [st.tls] is set) on an already-bound
    socket until [stop] resolves, then drains as described above and returns.
    [watch_interval] (default 2 s) is the polling period of the file watcher, which runs
    when [server.reload.watch] is on. [health_fd] is an optional extra plain-HTTP listener
    serving only [/healthz] and [/readyz] (e.g. for kubelet probes when the main port
    requires client certificates). *)

val main : ?health_listen:string -> ?limits:limits -> sources:State.sources -> unit -> int
(** The whole process lifecycle: loads the configuration, binds, installs signal handlers
    (SIGTERM/SIGINT: graceful shutdown; SIGHUP: reload), serves, and flushes the audit
    sinks and telemetry on the way out. Returns the exit code: 0 after a graceful
    shutdown, 2 if the limits or the configuration are invalid or the listener cannot
    start. *)
