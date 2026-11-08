(** Server state: static settings, the hot-reloadable snapshot (policies, tokens, OIDC
    providers, mTLS identities, TLS material), audit sinks, and the reload logic.

    {b Reload is atomic.} {!reload} loads every source into a fresh value and, only if
    everything loaded, replaces {!t.snap} (and {!t.tls}) with a single assignment;
    otherwise the last good configuration stays. Because the server runs on one Lwt thread
    and {!reload} itself never yields, a request sees either the old or the new snapshot,
    never a mix; handlers read [snap] once per request ({!Http}). Concurrent {!reload_lwt}
    calls (SIGHUP and the file watcher) are serialised. *)

open Haltsql

type snapshot = {
  policies : (string * Policy.t) list;
  tokens : Config.token list;
  default_policy : string option;
  oidc : Haltsql_auth.Oidc_client.registry;
  mtls : Config.mtls_identity list;
  allow_unauthenticated : bool;
      (** [server.auth.allow_unauthenticated]; reloadable so that turning anonymous access
          off takes effect without a restart *)
  watched : string list;  (** files whose changes trigger a reload *)
  opa : Config.opa option;  (** [opa]; reloadable *)
  admin : Config.admin;  (** [server.admin]; reloadable *)
}
(** The settings that hot reload replaces. *)

type sources = {
  config_file : string option;
  policy_files : string list;  (** from [--policy] flags *)
  overrides : Config.t -> Config.t;  (** command-line flags, applied last *)
}
(** Where the configuration comes from; re-read on every reload. *)

type t = {
  cfg : Config.t;
      (** effective settings at startup (listen, audit, limits, ...). Reloadable settings
          (policies, tokens, OIDC, mTLS, allow_unauthenticated) must be read from [snap],
          never from here. *)
  sources : sources;
  mutable snap : snapshot;  (** current reloadable settings; replaced atomically *)
  mutable signatures : (string * (float * int * int)) list;
      (** internal: (mtime, size, inode) of the watched files at the last reload *)
  mutable tls : Tls.Config.server option;
      (** current TLS configuration; [Some] iff TLS was configured at startup *)
  sinks : Audit.sink list;
  started : float;  (** Unix time the state was created *)
  mutable draining : bool;
      (** set when graceful shutdown begins: readiness fails and responses close their
          connection *)
  report : Admin_report.t;  (** shadow analytics window for [GET /v1/admin/report] *)
  mutable remote : (string * (string * Policy.t) list) list;
      (** policies of the last accepted bundle of each [bundle_source], by source id *)
  mutable bundle_sources : Haltsql_bundle_source.t list;
      (** running pollers (started by {!Bundle_sources.start}) *)
  mutable generation : int;  (** incremented by every successful reload *)
  reload_lock : Lwt_mutex.t;
      (** internal: serialises {!reload_lwt}, so a reload that waits on the secret
          prefetch never commits a [remote] computed before another reload committed *)
  mutable audit_restart_pending : bool;
      (** the last successful reload carried different audit sinks than the running ones;
          they only take effect after a restart (the running sinks stay) *)
}

(** {1 Integration hooks}

    Set by {!Integrations.install} before {!Server.main} loads the configuration. Each
    fails closed when unset (the feature reports that this build cannot use it). *)

val secret_resolver : (Config.secrets -> (Config.resolver, string) result) option ref
(** Builds a blocking resolver for secret-provider placeholders (startup). *)

val remote_sink :
  (Config.sink_kind -> on_error:Config.on_error -> (Audit.sink, string) result) option ref
(** Opens an S3 / GCS audit sink. *)

val bundle_loader :
  (Config.bundle_ref -> ((string * Policy.t) list, string) result) option ref
(** Verifies and loads a signed policy bundle (policies unprefixed). *)

val oidc_fetch : Haltsql_auth.Oidc_client.fetch option ref
(** HTTP fetcher for OIDC discovery and JWKS (tests substitute a fake). *)

val stream_sink : (Config.stream_sink -> (Audit.sink, string) result) option ref
(** Opens a SIEM streaming audit sink ([audit.streams]). *)

val secret_prefetch : (file:string -> Config.secrets -> Config.resolver Lwt.t) option ref
(** Asynchronous secret resolution for reloads, which run inside the Lwt loop: fetches
    every provider placeholder of [file] concurrently and returns a resolver serving only
    those values. *)

(** {1 Loading} *)

val load :
  ?resolver:Config.resolver ->
  ?remote:(string * (string * Policy.t) list) list ->
  sources ->
  (Config.t, string list) result
(** Loads the config file (or only [HALTSQL_*] variables without one), signed bundles, the
    policies of the remote bundle sources already fetched ([remote], by source id) and the
    [--policy] files, applies the overrides and checks that every policy referenced by
    tokens, [default_policy], OIDC providers and mTLS identities is loaded. Bundle
    policies may not shadow config-file policies or each other; [--policy] files replace
    policies of the same name. *)

val load_unchecked :
  ?resolver:Config.resolver ->
  ?remote:(string * (string * Policy.t) list) list ->
  sources ->
  (Config.t, string list) result
(** {!load} without the policy-reference check (used at startup to read [bundle_sources]
    before they are fetched). *)

val check_policy_refs : Config.t -> (unit, string list) result
(** Every policy referenced by tokens, [default_policy], OIDC providers and mTLS
    identities must be loaded. *)

val create : ?sources:sources -> Config.t -> t
(** Builds the state: loads TLS material and opens the audit sinks. Raises [Failure] on
    unusable TLS material or a sink that cannot be opened (sinks already opened are
    closed). *)

val close : t -> unit
(** Closes the audit sinks. *)

(** {1 Reloading} *)

val reload :
  ?reason:string ->
  ?resolver:Config.resolver ->
  ?remote:(string * (string * Policy.t) list) list ->
  t ->
  (unit, string list) result
(** Reloads every source and swaps the snapshot atomically if all of it loaded. TLS can be
    rotated but not switched on or off without a restart. [remote] (default {!t.remote})
    replaces the bundle-source policies and is committed only on success. Logs and counts
    the outcome. *)

val reload_lwt :
  ?reason:string ->
  ?update_remote:
    ((string * (string * Policy.t) list) list -> (string * (string * Policy.t) list) list) ->
  t ->
  (unit, string list) result Lwt.t
(** {!reload} from inside the Lwt loop (file watcher, SIGHUP, bundle sources): secrets
    from providers are prefetched asynchronously first, with a fresh cache, so rotated
    secrets are picked up. Serialised with other calls; [update_remote] derives the new
    [remote] from {!t.remote} as it is once the lock is held. *)

val changed : t -> bool
(** Whether a watched file changed since the last reload attempt. *)

(** {1 Lookups} *)

val snapshot_find_policy : snapshot -> string -> Policy.t option
(** A loaded policy by name. *)

val snapshot_default_policy : snapshot -> string option
(** The policy used when a request names none: [default_policy], or the only loaded
    policy. *)

val find_policy : t -> string -> Policy.t option
(** {!snapshot_find_policy} on the current snapshot. *)

val default_policy : t -> string option
(** {!snapshot_default_policy} on the current snapshot. *)
