(** OIDC providers at runtime: discovery, JWKS fetching and caching, and token
    verification (the IO around the pure {!Oidc.verify}).

    {1 Key cache}

    - Keys are cached for [jwks_cache_seconds] after a successful fetch.
    - A token whose [kid] is unknown triggers one forced refresh, at most once per
      {!forced_refresh_interval} seconds per provider, then verification is retried once.
    - When a refresh fails, the previous keys keep being used (stale-while-error) for at
      most [min jwks_cache_seconds 3600] seconds past their expiry; after that every token
      is rejected with {!Jwt.Keys_unavailable} (fail closed). Failed fetches are retried
      at most every {!failed_retry_interval} seconds.
    - Concurrent refreshes are coalesced into one fetch.

    {1 Discovery}

    When [jwks_uri] is not configured, it is read from
    [<issuer>/.well-known/openid-configuration] (trailing [/] of the issuer removed). The
    document's [issuer] must equal the configured issuer exactly, and its [jwks_uri] must
    be [https] (or [http] with [allow_insecure_http]) without credentials. *)

type fetch = Uri.t -> (string, string) result Lwt.t
(** Fetches a URL's body. [Error] messages must not contain secrets. *)

val http_fetch : ?timeout:float -> ?max_bytes:int -> unit -> fetch
(** An HTTP(S) GET via cohttp-lwt-unix: default timeout 5 s, body cap 1 MiB, only [200]
    accepted, redirects are not followed. *)

val forced_refresh_interval : float
(** 30 seconds. *)

val failed_retry_interval : float
(** 5 seconds. *)

val set_logger : ([ `Info | `Warn ] -> string -> (string * string) list -> unit) -> unit
(** Where the client reports fetch failures and refreshes (default: nowhere). Fields never
    contain tokens or key material. *)

(** {1 One provider} *)

type provider

val provider :
  ?fetch:fetch -> ?now:(unit -> float) -> Haltsql.Config.oidc_provider -> provider
(** [fetch] defaults to [http_fetch ()], [now] to [Unix.gettimeofday]. No IO happens until
    the first verification or {!refresh}. *)

val config : provider -> Haltsql.Config.oidc_provider
(** The provider's configuration. *)

val refresh : provider -> (int, string) result Lwt.t
(** Fetches (discovery if needed, then) the JWKS now; [Ok n] is the number of usable keys.
    Useful to warm the cache at startup. *)

val verify : provider -> string -> (Oidc.identity, Jwt.error) result Lwt.t
(** Verifies a token with the cached keys, refreshing them as described in the module
    description. Never fails the promise: transport problems become
    [Error (Keys_unavailable _)]. *)

(** {1 Several providers} *)

type registry

val registry :
  ?fetch:fetch -> ?now:(unit -> float) -> Haltsql.Config.oidc_provider list -> registry
(** One {!type-provider} per configuration entry, sharing [fetch] and [now]. *)

val update : registry -> Haltsql.Config.oidc_provider list -> registry
(** A registry for a new provider list that keeps the key caches of providers whose
    configuration is unchanged (used on hot reload). *)

val providers : registry -> provider list
(** The providers, in configuration order. *)

val is_empty : registry -> bool
(** [true] when no provider is configured. *)

val authenticate :
  registry ->
  string ->
  [ `Not_applicable | `Verified of Oidc.identity | `Rejected of Jwt.error ] Lwt.t
(** [`Not_applicable] when the registry is empty, the token does not look like a JWT, or
    no provider's issuer equals the token's (unverified) [iss]; the caller then falls back
    to static tokens. Otherwise the providers with that issuer are tried in order and the
    first success wins; if all fail, the first provider's error is returned. *)
