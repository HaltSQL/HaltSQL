(** Remote signed policy bundles: the [policies[].bundle_source] config entries (see
    docs/policy-bundles.md, "Bundle sources").

    A source is an OCI artifact, an S3 (or S3-compatible) object or an HTTPS URL. A {!t}
    fetches it (conditionally: OCI manifest digest, HTTP/S3 ETag), verifies the detached
    Ed25519 signature with {!Haltsql_bundle} {e before} anything is parsed or handed over,
    refuses rollbacks, hands the verified policies to [on_update], and then keeps the
    bundle in [cache_dir] so a restart can start from the last verified bundle while the
    source is down. Every failure keeps the last good bundle.

    {b Rollback protection.} Once a bundle is current, a new one is accepted only when it
    has the same [metadata.name] and a strictly greater [metadata.version] in the order of
    {!compare_versions}; an equal version with different content is refused too. The
    bundle restored from the cache counts as current. [~allow_downgrade:true] disables
    this check (the signature is still required). *)

module Oci_ref = Oci_ref
module Www_auth = Www_auth
module Fetch_error = Fetch_error
module Content_digest = Content_digest
module Registry = Registry
module Oci_artifact = Oci_artifact
module Remote = Remote
module Cache = Cache

(** {1 Updates and errors} *)

type origin = From_cache | From_source

type update = {
  source : string;  (** {!source_id} *)
  bundle : Haltsql_bundle.t;  (** verified; policies carry the [name_prefix] *)
  policies : (string * Haltsql_core.Policy.t) list;  (** name -> policy, bundle order *)
  signed_by : string;  (** key id of the trusted key that verified the signature *)
  revision : string option;  (** OCI manifest digest, or HTTP / S3 ETag *)
  origin : origin;
}

type error =
  | Fetch_failed of Fetch_error.t
  | Verification_failed of Haltsql_bundle.error
      (** bad or untrusted signature, digest, structure or policy *)
  | Rollback_refused of string
  | Rejected of string  (** [on_update] refused the bundle *)
  | Cache_failed of string  (** reading or writing the cache (never fatal) *)

val error_code : error -> string
(** Stable codes: [bundle_source_unavailable], [bundle_source_denied],
    [bundle_source_not_found], [bundle_source_integrity], [bundle_source_protocol],
    [bundle_source_signature], [bundle_source_invalid], [bundle_source_rollback],
    [bundle_source_rejected], [bundle_source_cache]. *)

val error_to_string : error -> string
(** Never contains credentials, tokens or key material. *)

(** {1 Version order} *)

val compare_versions : string -> string -> int
(** Natural order: versions are split into runs of digits (compared numerically) and runs
    of other characters (compared bytewise), so [1.9.0 < 1.10.0],
    [2026.11.07 < 2026.11.08] and [build-99 < build-100]. When one version is a prefix of
    the other, the longer one is greater unless its remainder starts with [-] or [~] (a
    pre-release: [1.4.0-rc.1 < 1.4.0]). *)

val check_rollback :
  allow_downgrade:bool ->
  current:Haltsql_bundle.metadata option ->
  Haltsql_bundle.metadata ->
  (unit, string) result

(** {1 Sources} *)

type t

val create :
  ?allow_downgrade:bool ->
  ?ca_file:string ->
  ?timeout:float ->
  ?jitter:float ->
  ?poll_interval:float ->
  ?env:(string -> string option) ->
  ?now:(unit -> float) ->
  ?aws_credentials:Haltsql_cloud.Aws_creds.t ->
  Haltsql_load.Config.bundle_source ->
  (t, string) result Lwt.t
(** Decodes the public keys (any undecodable key, or none, is an error) and prepares the
    client. Nothing is fetched yet.
    - [allow_downgrade] (default false): see the module doc.
    - [ca_file]: trust only these PEM CA certificates for HTTPS (registry, URL or S3
      endpoint) instead of the system store.
    - [timeout]: per HTTP request, default 30 s.
    - [jitter] (default 0.1): each wait is [poll_interval * (1 +- jitter)], uniformly.
    - [poll_interval]: overrides [poll_interval_s] (seconds; for tests).
    - [aws_credentials]: overrides the provider built from [s3.credentials]. *)

val source_id : t -> string
(** [oci:<reference>], [s3://<bucket>/<key>] (with [@<endpoint>] when set) or the HTTPS
    URL. *)

val current : t -> update option
(** The bundle currently handed over, if any. *)

type status = {
  checks : int;  (** completed polls, successful or not *)
  last_success : float option;  (** time of the last poll that reached the source *)
  last_error : error option;  (** of the last poll; [None] after a successful one *)
}

val status : t -> status

type outcome = Unchanged | Updated of update

type on_update = update -> (unit, string) result Lwt.t
(** Called with each newly verified bundle; returning [Error] (or raising) rejects it: it
    does not become current and is not cached. *)

val verify : t -> bundle:string -> signature:string -> (update, error) result
(** Signature first, then {!Haltsql_bundle.parse_unverified} with the source's
    [name_prefix]; [origin] is [From_source] and [revision] [None]. Size limits are
    checked before anything else. *)

val load_cache : t -> on_update:on_update -> (outcome, error) result Lwt.t
(** Restores the cached bundle (verified again with the current keys). [Ok Unchanged] when
    there is no [cache_dir], no entry, or a bundle is already current. *)

val poll_once :
  t ->
  on_update:on_update ->
  ?on_warning:(error -> unit) ->
  unit ->
  (outcome, error) result Lwt.t
(** One conditional fetch. Polls never overlap. A failure to write the cache after an
    accepted update is reported to [on_warning] and does not fail the poll. *)

val start :
  t -> on_update:on_update -> on_error:(error -> unit) -> (unit, error) result Lwt.t
(** Restores the cache, polls once, then keeps polling in the background every
    [poll_interval_s] (with jitter) until {!stop}. Resolves after the first poll: [Ok ()]
    when a bundle is current (from the source or the cache), else the error of the first
    poll. Every failure, including those of background polls and cache problems, is also
    passed to [on_error]. *)

val stop : t -> unit
(** Stops the background polling (a poll in progress completes). *)
