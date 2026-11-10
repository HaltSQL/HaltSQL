(** One client connection: startup, TLS upgrade, client authentication, upstream
    connection and the enforcing message relay. *)

type shared = {
  cfg : Proxy_config.t;
      (** the configuration snapshot this session runs under, from accept to close. A
          reload never changes it, and in particular never rebinds a live session to
          another policy: a session whose credentials or policy a reload changed is ended
          instead (see {!stale}), so the policy that verifies its statements is always the
          one its upstream [search_path] was pinned for *)
  generation : int;  (** config generation (1 at start, +1 per successful reload) *)
  tls_server : Tls.Config.server option;
  audit : Paudit.t;  (** process-wide: one chain per sink across every generation *)
  mock_secret : string;  (** per-process secret for SCRAM mock authentication *)
  cancel_table : (int, int * int * int * Proxy_config.upstream) Hashtbl.t;
      (** proxy pid -> (proxy key, upstream pid, upstream key, upstream it runs on);
          shared across generations *)
}

type principal = User of string | Identity of Proxy_config.identity_match

type live = {
  live_id : string;  (** the session id used in logs and audit records *)
  principal : principal;  (** who authenticated *)
  credential : string;
      (** what they authenticated with: the SCRAM verifier text ([""] for certificates) *)
  live_binding : Proxy_config.binding;  (** policy and context, fixed for the session *)
  live_cfg : Proxy_config.t;  (** the snapshot the session runs under *)
  terminate : string -> unit;
      (** [terminate reason] asks the session to end: at its next transaction boundary
          (immediately if it is idle outside a transaction), or after
          [limits.termination_grace_seconds] at the latest, the client gets
          [FATAL 57P01 terminating connection: <reason> (haltsql-proxy); reconnect] and
          both connections are closed. Idempotent; the first reason wins. *)
}
(** An authenticated session, as the listener sees it. *)

val stale : Proxy_config.t -> live -> string option
(** [stale cfg l]: why session [l] must not go on under the newly loaded [cfg], if so: its
    user or certificate identity is gone, its SCRAM verifier or (for certificate sessions)
    the client CA bundle changed, it is bound to another policy, the policy's content
    ([version]) or the context changed, the upstream (address, database, role, password,
    TLS mode or CA) changed, or [allow_transaction_control] changed. [None] when the
    reload changed nothing this session depends on. *)

val handle :
  ?on_authenticated:(live -> unit) ->
  shared ->
  id:string ->
  Lwt_unix.file_descr ->
  unit Lwt.t
(** Serves the connection to completion and closes it. Never raises. [on_authenticated] is
    called once, when client authentication succeeded.

    A session also ends itself [limits.max_session_lifetime_seconds] after authentication,
    the same way {!live.terminate} does. *)

val shutdown_sqlstate : string
(** ["57P01"] ([admin_shutdown]): the FATAL error of sessions ended by a reload or by the
    lifetime limit. Drivers and pools treat it as a reason to reconnect. *)

val audit_sqlstate : string
(** ["58030"] ([io_error]): statements refused because their audit record could not be
    written (fail closed). *)

val sentinel_prefix : string
(** Statements injected upstream in place of denied ones start with this prefix. *)
