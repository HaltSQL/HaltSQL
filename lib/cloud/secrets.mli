(** Secret resolution for the Config [?resolve] hook ([${vault:..}], [${aws-sm:..}],
    [${gcp-sm:..}]).

    {1 Typical use}

    CLI (outside any Lwt loop):
    {[
      match Haltsql_cloud.Secrets.load_config_blocking file with
      | Ok cfg -> ...
      | Error errs -> (* Load_error.t list, exit 2 *)
    ]}

    Server (inside the Lwt loop, e.g. on reload):
    {[
      Haltsql_cloud.Secrets.load_config file >>= function Ok cfg -> ... | Error errs -> ...
    ]}

    Both perform the two-pass load: [Config.secrets_of_file] decodes the [secrets]
    section, a {!t} is built from it, every provider placeholder found in the raw file
    text is fetched (concurrently), and [Config.of_file ~resolve] is run with a resolver
    that serves those cached values. [Config.of_file] is synchronous; serving it from a
    prefetched cache is what makes the async server path safe (no nested [Lwt_main.run]).

    {1 Guarantees}

    Each distinct [(scheme, reference)] is fetched at most once per {!t} (errors are
    cached too); create a fresh {!t} per load so rotated secrets are picked up. Error
    messages name the reference and the failure, never a secret value or token. A provider
    that is not configured in [secrets] is an error naming the missing section. *)

type t

val create :
  ?env:(string -> string option) ->
  ?now:(unit -> float) ->
  ?timeout:float ->
  ?aws_credentials:Aws_creds.t ->
  ?gcp_auth:Gcp_auth.t ->
  Haltsql_load.Config.secrets ->
  t
(** [timeout] bounds each HTTP request (default 10 s). *)

val resolve : t -> scheme:string -> reference:string -> (string, string) result Lwt.t
(** Fetches (or returns the cached result for) one placeholder. *)

val fetch_count : t -> int
(** Number of provider fetches performed (cache misses). *)

val scan_placeholders : string -> (string * string) list
(** The distinct [(scheme, reference)] provider placeholders in a text, honouring the
    [$${] escape, in order of first appearance. *)

val prefetch : t -> (string * string) list -> unit Lwt.t
(** Resolves these placeholders concurrently into the cache. Never fails (errors are
    cached and reported by the resolver). *)

val cached_resolver : t -> Haltsql_load.Config.resolver
(** Serves only cached results; a miss is an error. Safe inside Lwt. *)

val blocking_resolver : t -> Haltsql_load.Config.resolver
(** Serves cached results and fetches misses with [Lwt_main.run]. Must not be called while
    an [Lwt_main.run] is active (use {!load_config} there). *)

val load_config :
  ?env:(string -> string option) ->
  ?timeout:float ->
  string ->
  (Haltsql_load.Config.t, Haltsql_core.Load_error.t list) result Lwt.t
(** Loads a runtime configuration whose [${vault:...}], [${aws-sm:...}] and
    [${gcp-sm:...}] placeholders are prefetched concurrently and then substituted. Secret
    values never appear in the returned errors. *)

val load_config_blocking :
  ?env:(string -> string option) ->
  ?timeout:float ->
  string ->
  (Haltsql_load.Config.t, Haltsql_core.Load_error.t list) result
(** [Lwt_main.run (load_config ...)]; for the CLI. *)
