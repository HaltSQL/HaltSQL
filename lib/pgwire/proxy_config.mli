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

type audit_sink = Audit_stdout | Audit_file of string | Audit_none

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
  audit : audit_sink;  (** default stdout *)
  log_raw_sql : bool;  (** default false: audit records carry only the SQL hash *)
  log_level : string;  (** debug | info | warn | error *)
  shutdown_grace : float;  (** seconds; default 10 *)
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

val to_json_redacted : t -> Yojson.Safe.t
(** Effective configuration with secrets (password, verifiers, keys) redacted. *)
