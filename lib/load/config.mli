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

(** {1 audit.sinks: streaming sinks (elasticsearch, kafka)}

    These are listed in the same [audit.sinks] list as the stdout/file/s3/gcs sinks but
    are decoded into {!t.stream_sinks}, so existing consumers of {!t.sinks} are
    unaffected. *)

type stream_on_error =
  | Stream_fail_closed  (** refuse requests when the sink cannot be written (default) *)
  | Stream_buffer  (** keep up to [max_buffer_records] in memory and retry *)
  | Stream_drop
      (** drop records the sink cannot take (counted, logged); not fail closed *)

type stream_batch = {
  batch_max_records : int;  (** default 500, 1..100000 *)
  batch_max_bytes : int;  (** default 5 MiB, 1024..100 MiB *)
  flush_interval_ms : int;  (** default 1000, 10..60000 *)
}

type es_auth =
  | Es_api_key of string
      (** secret: the encoded API key sent as [Authorization: ApiKey <value>] *)
  | Es_basic of { username : string; password : string  (** secret *) }

type es_target = Es_index of string | Es_data_stream of string

type es_sink = {
  es_urls : string list;
      (** non-empty, unique; https, or http for loopback hosts only; no query *)
  es_target : es_target;
  es_auth : es_auth option;
  es_pipeline : string option;  (** ingest pipeline name *)
  es_ca : pem option;  (** [tls.ca_file]; only with an https URL *)
  es_timeout_ms : int;  (** default 10000, 100..120000 *)
  es_batch : stream_batch;
}

type kafka_acks = Acks_all  (** default *) | Acks_leader  (** [acks: 1] *)
type sasl_mechanism = Sasl_plain | Sasl_scram_sha_256 | Sasl_scram_sha_512

type kafka_tls = {
  kafka_ca : pem option;
  kafka_cert : pem option;  (** client certificate; set together with [kafka_key] *)
  kafka_key : pem option;  (** redacted *)
}

type kafka_sasl = {
  sasl_mechanism : sasl_mechanism;
  sasl_username : string;
  sasl_password : string;  (** secret *)
}

type kafka_sink = {
  kafka_brokers : string list;  (** non-empty, unique [host:port] *)
  kafka_topic : string;
  kafka_client_id : string;  (** default ["haltsql"] *)
  kafka_acks : kafka_acks;
  kafka_tls : kafka_tls option;  (** [Some] when TLS is enabled *)
  kafka_sasl : kafka_sasl option;
      (** PLAIN without TLS is only accepted when every broker is a loopback address *)
  kafka_batch : stream_batch;
}

type stream_sink_kind = Stream_elasticsearch of es_sink | Stream_kafka of kafka_sink

type stream_sink = {
  stream : stream_sink_kind;
  stream_on_error : stream_on_error;
  max_buffer_records : int;
      (** default [max 10000 batch_max_records], 1..1000000, >= batch max_records. Only
          settable with [on_error: buffer]. *)
  sink_index : int;  (** position in [audit.sinks], for messages *)
}

(** {1 policies: remote bundle sources} *)

type oci_source = {
  oci_reference : string;  (** as written, e.g. [ghcr.io/corp/policies:prod] *)
  oci_registry : string;  (** [host[:port]] *)
  oci_repository : string;
  oci_tag : string option;
  oci_digest : string option;  (** [sha256:<hex>] or [sha512:<hex>] *)
  oci_plain_http : bool;  (** default false; only for loopback registries *)
}

type s3_source = {
  src_bucket : string;
  src_key : string;
  src_region : string;
  src_endpoint : string option;  (** S3-compatible endpoint (MinIO) *)
  src_credentials : s3_credentials;  (** default [S3_env] *)
}

type bundle_location =
  | Source_oci of oci_source
  | Source_s3 of s3_source
  | Source_https of string  (** https URL (http for loopback only), no query *)

type source_auth =
  | Source_basic of { username : string; password : string  (** secret *) }
  | Source_token of string  (** secret bearer token *)

type bundle_source = {
  location : bundle_location;
  source_public_keys : public_key list;
      (** non-empty: signature verification is mandatory *)
  source_name_prefix : string option;
  poll_interval_s : int;  (** default 60, 10..86400 *)
  cache_dir : string option;  (** absolute *)
  source_auth : source_auth option;  (** oci and https only *)
}

(** {1 server.auth.oidc[].policy_from_groups} *)

type group_rule = { group : string; group_policy : string }

type groups_policy = {
  groups_claim : string;
      (** default ["groups"]; looked up like [context_claims] paths (exact claim name,
          then dot path) *)
  group_rules : group_rule list;  (** non-empty, ordered, unique groups *)
  group_default : string option;  (** policy when no rule matches; [None]: reject *)
}

(** {1 opa} *)

type opa_on_error =
  | Opa_deny  (** default: an OPA failure denies the query *)
  | Opa_allow_haltsql_verdict  (** an OPA failure keeps HaltSQL's verdict *)

type opa = {
  opa_url : string;  (** base URL, https or loopback http, no query *)
  decision_path : string;  (** below [/v1/data], e.g. [haltsql/allow] *)
  opa_timeout_ms : int;  (** default 500, 10..5000 *)
  opa_on_error : opa_on_error;
  opa_headers : (string * string) list;  (** resolved values; secret, redacted *)
  opa_ca : pem option;  (** [tls.ca_file]; only with an https url *)
}

(** {1 server.admin} *)

type admin_caller =
  | Admin_token of string  (** [token:<name>]: a [server.auth.tokens] name *)
  | Admin_oidc of string  (** [oidc:<provider>]: any token verified by that provider *)
  | Admin_mtls of mtls_match
      (** [mtls:<spiffe-id>] or [mtls:<CN>]: a configured mTLS identity *)

type admin = {
  admin_enabled : bool;  (** default false *)
  admin_callers : admin_caller list;  (** non-empty when enabled; each must exist *)
  report_window_seconds : int;  (** [report_window], default 24h, 1m..30d *)
  max_tracked_queries : int;  (** default 10000, 1..1000000 *)
}

val default_admin : admin

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
  sinks : sink list;
      (** the stdout, file, s3 and gcs audit sinks; default [[{Sink_stdout; Fail_closed}]]
          when [audit.sinks] is absent. Streaming sinks are in [stream_sinks]. *)
  secrets : secrets;
  policy_bundles : bundle_ref list;
      (** Bundle references, parsed but neither loaded nor verified. When this is
          non-empty, policy names referenced by tokens, OIDC, mTLS and [default_policy]
          that are not among the plain policies are accepted at load time (restricted to
          the bundles' [name_prefix]es when every bundle has one); the server must
          re-validate them after loading the bundles. The same applies to
          [bundle_sources]. *)
  stream_sinks : stream_sink list;
      (** elasticsearch and kafka entries of [audit.sinks] (they are not in [sinks]) *)
  bundle_sources : bundle_source list;
      (** remote signed bundles, neither fetched nor verified *)
  oidc_group_policies : (string * groups_policy) list;
      (** OIDC provider name -> [policy_from_groups]. For such a provider [oidc_policy] is
          the fail-closed placeholder [Oidc_from_claim { claim; allowed = [] }], which
          accepts no token, so a consumer that does not look here rejects every token of
          that provider. Use {!groups_policy_of}. *)
  opa : opa option;
  admin : admin;  (** [server.admin]; default {!default_admin} (disabled) *)
}

val default : t

val groups_policy_of : t -> oidc_provider -> groups_policy option
(** The provider's [policy_from_groups], if it has one. *)

val groups_of_claim : Yojson.Safe.t -> string list option
(** The groups in a claim value: a string is one group (never split on spaces), an array
    must contain only strings. Anything else is [None] (malformed; reject the token). *)

val select_group_policy : groups_policy -> string list -> string option
(** The policy of the first rule (in config order) whose group is in [groups], else
    [group_default]. [None]: no policy, reject the token. *)

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
    and secret ids, Elasticsearch API keys and passwords, the Kafka SASL password and TLS
    key, bundle source passwords/tokens (and static S3 credentials) and OPA header values.
    Stream sinks are listed after the other sinks in [audit.sinks]. *)
