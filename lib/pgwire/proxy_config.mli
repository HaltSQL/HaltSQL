(** The [kind: ProxyConfig] document for [haltsql-proxy] (YAML or JSON, read with
    {!Haltsql.Docload}). See docs/proxy.md for the full reference.

    Validation is strict: unknown keys, missing required keys, wrong types, unreadable TLS
    material, unknown policy names and context values that do not cover a policy's tenancy
    keys are all errors. Strings may use [${env:NAME}] and [${file:/path}] placeholders
    (resolved here, never inside inline policies); ["$${"] is a literal ["${"]. *)

open Haltsql

type client_auth = Client_cert_none | Client_cert_optional | Client_cert_require

type client_tls = {
  certificates : X509.Certificate.t list * X509.Private_key.t;
      (** from [tls.cert] / [tls.key]: each is a path to a PEM file or inline PEM (a value
          containing [-----BEGIN], e.g. the expansion of [${file:...}]). Load errors never
          echo the configured value or key bytes. *)
  client_ca : X509.Certificate.t list;  (** empty when not configured *)
  client_auth : client_auth;
  tls_required : bool;
      (** default true: plaintext clients are refused once TLS is configured *)
}

type upstream_tls_mode = Tls_disable | Tls_require | Tls_verify_full

type upstream = {
  host : string;
  port : int;
  database : string;
  user : string;
  password : string option;  (** [None]: trust auth only *)
  tls_mode : upstream_tls_mode;
  tls_ca : X509.Certificate.t list;  (** required for verify-full *)
  connect_timeout : float;  (** seconds *)
}

type binding = { policy_name : string; policy : Policy.t; context : Context.t }
(** What a session runs under: a policy and the authenticated context. *)

type user = { user_name : string; verifier : Scram.verifier; user_binding : binding }
type identity_match = Subject_cn of string | Spiffe_id of string
type identity = { id_match : identity_match; id_binding : binding }
type auth = Scram_users of user list | Cert_identities of identity list

type limits = {
  max_connections : int;  (** default 100 *)
  max_message_bytes : int;  (** default 1 MiB; applies to client messages *)
  idle_timeout : float;  (** seconds; 0 = none (default) *)
  auth_timeout : float;  (** seconds to finish startup + auth; default 30 *)
}

type audit_sink =
  | Audit_stdout
  | Audit_file of string
  | Audit_none
      (** Legacy single-sink view of {!t.audit_sinks}: the first stdout or file sink. *)

type audit_on_error =
  | Audit_fail_closed
      (** default: a record that cannot be written refuses the statement (SQLSTATE 58030)
          until the sink accepts writes again *)
  | Audit_buffer
      (** keep records in memory (in order, sealed when written) and retry; refuse
          statements only once [max_buffer_records] are waiting *)
  | Audit_drop
      (** drop records the sink cannot take; every drop is counted and logged at warn
          level (never silent), and statements keep flowing *)

type audit_sink_spec = {
  sink : Config.sink_kind;
      (** decoded by {!Haltsql.Config} exactly like the server's [audit.sinks] entries;
          always [Sink_stdout], [Sink_file], [Sink_s3] or [Sink_gcs] *)
  sink_on_error : audit_on_error;
  max_buffer_records : int;
      (** buffer bound for [Audit_buffer]: default 10000 (stdout/file) or 100000 (s3/gcs,
          and never less than the sink's [batch.max_records]) *)
}

type reload = {
  watch : bool;  (** default false: poll {!t.source_files} and reload on change *)
  poll_interval : float;  (** seconds, default 2, 0.1..3600 *)
}

type t = {
  listen_host : string;
  listen_port : int;
  tls : client_tls option;
  upstream : upstream;
  policies : (string * Policy.t) list;
  auth : auth;
  limits : limits;
  deny_sqlstate : string;  (** default ["42501"] *)
  allow_transaction_control : bool;
      (** default true: plain BEGIN/COMMIT/ROLLBACK pass without a policy check (see
          {!Enforce.transaction_control}) *)
  audit : audit_sink;  (** legacy projection of [audit_sinks]; default stdout *)
  audit_sinks : audit_sink_spec list;
      (** default one stdout sink with [Audit_fail_closed]; [[]] for [type: none] *)
  log_raw_sql : bool;  (** default false: audit records carry only the SQL hash *)
  log_level : string;  (** debug | info | warn | error *)
  shutdown_grace : float;  (** seconds; default 10 *)
  reload : reload;
  source_files : string list;
      (** absolute paths of the config file (with {!of_file}) and every file it pulled in:
          policy files, TLS material and [${file:...}] placeholders *)
}

val kind : string
(** ["ProxyConfig"] *)

val of_json :
  ?file:string ->
  ?base_dir:string ->
  ?env:(string -> string option) ->
  Yojson.Safe.t ->
  (t, Load_error.t list) result
(** Decodes and validates a ProxyConfig document, collecting every error. Relative paths
    resolve against [base_dir]; [${env:...}] and [${file:...}] placeholders are expanded
    with [env]. *)

val of_file : ?env:(string -> string option) -> string -> (t, Load_error.t list) result
(** {!of_json} on a YAML or JSON file; relative paths resolve against the file's
    directory. *)

val sink_name : Config.sink_kind -> string
(** ["stdout"], the file path, ["s3://bucket/prefix"] or ["gs://bucket/prefix"]. *)

val on_error_name : audit_on_error -> string

val to_json_redacted : t -> Yojson.Safe.t
(** Effective configuration with secrets (password, verifiers, keys) redacted. *)
