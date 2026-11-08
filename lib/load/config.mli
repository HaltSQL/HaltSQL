(** Runtime configuration document ([kind: Config]) for the CLI and server.

    {1 Placeholders}

    String values may contain placeholders, resolved at load time:
    - [${env:NAME}] — an environment variable (built in);
    - [${file:/path}] — file contents minus one trailing newline (built in);
    - [${vault:<path>#<field>}] — a HashiCorp Vault secret field;
    - [${aws-sm:<secret-id>[#<json-key>]}] — AWS Secrets Manager;
    - [${gcp-sm:<resource-or-secret>[#<json-key>]}] — Google Secret Manager;
    - [$${] is a literal [${].

    Placeholders are never allowed in inline policies.

    {1 Secret providers: the two-pass design}

    This module stays pure: it never talks to Vault or a cloud provider. The [vault],
    [aws-sm] and [gcp-sm] schemes are delegated to a caller-supplied [?resolve] function.
    Because the resolver itself is configured by the document's [secrets] section, loading
    is done in two passes:

    + [secrets_of_json] (or [secrets_of_file]) decodes only the [secrets] section,
      resolving [${env:..}]/[${file:..}] inside it (provider placeholders are rejected
      there: they cannot configure themselves);
    + the caller builds a resolver from those {!type-secrets} (e.g. logs into Vault) and
      passes it as [?resolve] to [of_json]/[of_file], which decode the whole document and
      call [resolve ~scheme ~reference] for every provider placeholder outside the
      [secrets] section. [scheme] is ["vault"], ["aws-sm"] or ["gcp-sm"]; [reference] is
      the text after the colon, e.g. ["secret/data/app#token"]. Each distinct
      [(scheme, reference)] is resolved at most once per load.

    A provider placeholder with no [?resolve] given is a located error ("secret provider
    not configured"). A resolver [Error msg] becomes a located error carrying [msg];
    resolvers must never put secret values in their error messages.

    {1 Precedence}

    flags > HALTSQL_* env vars > file > defaults; this module handles file + env, callers
    apply flags. *)

open Haltsql_core

(** {1 Legacy types (unchanged)} *)

type token = {
  token_name : string;
  token_sha256 : string;  (** lower-case hex SHA-256 of the bearer token *)
  token_policy : string;  (** name of the policy this token is pinned to *)
}

type audit_sink = Audit_stdout | Audit_file of string

(** {1 server.tls} *)

(** A PEM value: a path (absolute after loading) or inline PEM text (a value starting with
    [-----BEGIN], e.g. from [${file:..}] or a secret provider). *)
type pem = Pem_path of string | Pem_inline of string

type client_auth = Client_auth_none | Client_auth_optional | Client_auth_required
type tls_version = Tls_1_2 | Tls_1_3

type tls = {
  cert : pem;
  key : pem;
  client_ca : pem option;  (** CA bundle used to verify client certificates *)
  client_auth : client_auth;
      (** default [Client_auth_none]; optional/required need [client_ca] *)
  min_version : tls_version;  (** default [Tls_1_2] *)
}

(** {1 server.auth.oidc} *)

type jwt_alg = RS256 | RS384 | RS512 | PS256 | ES256 | ES384 | EdDSA

val string_of_jwt_alg : jwt_alg -> string

(** How a verified token selects its policy. *)
type oidc_policy =
  | Oidc_pinned of string  (** [policy: NAME] *)
  | Oidc_from_claim of { claim : string; allowed : string list }
      (** [policy_claim] + [allowed_policies] (non-empty) *)

(** A required claim: [Claim_one v] matches when the claim equals [v], or the claim is an
    array containing [v], or a space-separated string (e.g. [scope]) containing [v].
    [Claim_all vs] requires every value of [vs] to match that way. *)
type claim_match = Claim_one of string | Claim_all of string list

type oidc_provider = {
  oidc_name : string;  (** unique among providers *)
  issuer : string;  (** https URL (http only with [allow_insecure_http]) *)
  audiences : string list;  (** non-empty; the token's [aud] must contain one *)
  jwks_uri : string option;
      (** [None]: discover from [issuer ^ "/.well-known/openid-configuration"] *)
  algorithms : jwt_alg list;  (** default [[RS256; ES256]]; never [none] or HS* *)
  leeway_seconds : int;  (** default 60, 0..300 *)
  jwks_cache_seconds : int;  (** default 300, 10..86400 *)
  oidc_policy : oidc_policy;
  context_claims : (string * string) list;
      (** context field -> claim path. A path is first looked up as one top-level claim
          name (so ["https://corp.example/tenant"] works), then as a dot path
          (["org.id"]). *)
  required_claims : (string * claim_match) list;
  oidc_request_context_fields : string list;
      (** context fields the request body may still supply; default [[]] *)
  allow_insecure_http : bool;  (** default false; tests only *)
}

(** {1 server.auth.mtls} *)

type mtls_match =
  | Spiffe_id of string  (** exact URI SAN, e.g. [spiffe://corp.example/ns/a/sa/b] *)
  | Subject_cn of string  (** exact subject common name *)

type mtls_identity = {
  mtls_match : mtls_match;
  mtls_policy : string;
  mtls_context : Context.t;  (** static context values for this identity *)
  mtls_request_context_fields : string list;  (** default [[]] *)
}

(** {1 telemetry.otlp} *)

type otlp = {
  otlp_endpoint : string;  (** http(s) URL, e.g. [http://collector:4318] *)
  otlp_headers : (string * string) list;  (** resolved values; secret, redacted *)
  service_name : string;  (** default ["haltsql"] *)
  otlp_traces : bool;  (** default true *)
  otlp_metrics : bool;  (** default true *)
  export_interval_seconds : int;  (** default 15, 1..3600 *)
  timeout_seconds : int;  (** default 5, 1..300 *)
}

(** {1 audit.sinks} *)

type on_error =
  | Fail_closed  (** refuse requests when the sink cannot be written (default) *)
  | Buffer  (** buffer records in memory and retry *)

type batch = {
  max_records : int;  (** default 500, 1..100000 *)
  max_seconds : int;  (** default 10, 1..3600 *)
}

type object_lock_mode = Governance | Compliance
type object_lock = { lock_mode : object_lock_mode; retain_days : int  (** 1..36500 *) }

type s3_credentials =
  | S3_env  (** default: AWS_ACCESS_KEY_ID etc. from the environment *)
  | S3_static of {
      access_key_id : string;
      secret_access_key : string;
      session_token : string option;
    }
  | S3_web_identity
  | S3_instance

type s3_sink = {
  s3_bucket : string;
  s3_prefix : string;  (** default ["haltsql/audit/"] *)
  s3_region : string;
  s3_endpoint : string option;  (** S3-compatible endpoint (MinIO, tests) *)
  s3_object_lock : object_lock option;
  s3_batch : batch;
  s3_credentials : s3_credentials;
  s3_spool_dir : string option;
      (** absolute; local spool for crash safety and for continuing the audit hash chain
          and object sequence across restarts. Default none: each process starts a new
          chain. *)
}

type gcs_credentials =
  | Gcs_metadata  (** default: the metadata server *)
  | Gcs_service_account_file of string  (** absolute path *)

type gcs_sink = {
  gcs_bucket : string;
  gcs_prefix : string;  (** default ["haltsql/audit/"] *)
  gcs_batch : batch;
  gcs_credentials : gcs_credentials;
  gcs_spool_dir : string option;  (** absolute; as [s3_spool_dir] *)
}

type sink_kind =
  | Sink_stdout
  | Sink_file of string  (** absolute path *)
  | Sink_s3 of s3_sink
  | Sink_gcs of gcs_sink

type sink = { sink : sink_kind; on_error : on_error  (** default [Fail_closed] *) }

(** {1 secrets} *)

type vault_auth =
  | Vault_token of string
  | Vault_kubernetes of {
      role : string;
      jwt_path : string;
          (** default [/var/run/secrets/kubernetes.io/serviceaccount/token] *)
      mount : string;  (** default ["kubernetes"] *)
    }
  | Vault_approle of {
      role_id : string;
      secret_id : string;
      mount : string;  (** default ["approle"] *)
    }

type vault = {
  vault_address : string;  (** https URL; http only for loopback hosts *)
  vault_namespace : string option;
  vault_auth : vault_auth;
  vault_ca_file : string option;  (** absolute path *)
}

type aws_secrets = { aws_region : string; aws_endpoint : string option }
type gcp_secrets = { gcp_project : string option; gcp_endpoint : string option }

type secrets = {
  vault : vault option;
  aws : aws_secrets option;
  gcp : gcp_secrets option;
}

val no_secrets : secrets

(** {1 policies: signed bundles} *)

(** An ed25519 public key: a file path (absolute after loading), inline PEM
    ([-----BEGIN PUBLIC KEY-----]), or the base64 of the 32 raw key bytes. *)
type public_key = Key_path of string | Key_pem of string | Key_base64 of string

type bundle_ref = {
  bundle_path : string;  (** absolute path of the [.haltsqlbundle] file *)
  public_keys : public_key list;  (** non-empty *)
  name_prefix : string option;
      (** prepended to the names of the policies loaded from this bundle *)
}

(** {1 The configuration} *)

type t = {
  listen : string;  (** ["host:port"], default ["127.0.0.1:8080"] *)
  tls_cert : string option;  (** legacy view of [server.tls.cert] as written *)
  tls_key : string option;  (** legacy view of [server.tls.key] as written *)
  tokens : token list;
  allow_unauthenticated : bool;  (** default false; only for local development *)
  policies : (string * Policy.t) list;  (** policy name -> compiled policy *)
  policy_files : string list;  (** absolute paths, for hot reload *)
  default_policy : string option;  (** used by unauthenticated requests *)
  reload_watch : bool;
  audit_sinks : audit_sink list;
      (** legacy projection of [sinks]: only the stdout and file sinks. Consumers that
          support cloud sinks must use [sinks]. *)
  log_raw_sql : bool;
  log_level : string;  (** debug | info | warn | error *)
  log_format : string;  (** json | text *)
  metrics : bool;
  max_request_bytes : int;
  tls : tls option;  (** [Some] when both [server.tls.cert] and [.key] are set *)
  oidc : oidc_provider list;
  mtls : mtls_identity list;  (** [server.auth.mtls.identities] *)
  otlp : otlp option;  (** from [telemetry.otlp] or legacy [telemetry.otlp_endpoint] *)
  sinks : sink list;  (** every audit sink; default [[{Sink_stdout; Fail_closed}]] *)
  secrets : secrets;
  policy_bundles : bundle_ref list;
      (** Bundle references, parsed but neither loaded nor verified. When this is
          non-empty, policy names referenced by tokens, OIDC, mTLS and [default_policy]
          that are not among the plain policies are accepted at load time (restricted to
          the bundles' [name_prefix]es when every bundle has one); the server must
          re-validate them after loading the bundles. *)
}

val default : t

type resolver = scheme:string -> reference:string -> (string, string) result
(** Resolves a [vault] / [aws-sm] / [gcp-sm] placeholder; see the module doc. *)

val of_json :
  ?file:string ->
  ?base_dir:string ->
  ?env:(string -> string option) ->
  ?resolve:resolver ->
  Yojson.Safe.t ->
  (t, Load_error.t list) result

val of_file :
  ?env:(string -> string option) ->
  ?resolve:resolver ->
  string ->
  (t, Load_error.t list) result

val secrets_of_json :
  ?file:string ->
  ?base_dir:string ->
  ?env:(string -> string option) ->
  Yojson.Safe.t ->
  (secrets, Load_error.t list) result
(** First pass: decode only the [secrets] section of a whole Config document ([no_secrets]
    when absent). Other sections are not validated. *)

val secrets_of_file :
  ?env:(string -> string option) -> string -> (secrets, Load_error.t list) result

val to_json_redacted : t -> Yojson.Safe.t
(** Effective config for [haltsql config show]; secrets replaced by ["<redacted>"]: token
    hashes, the TLS key, OTLP header values, static S3 credentials, Vault tokens, role ids
    and secret ids. *)
