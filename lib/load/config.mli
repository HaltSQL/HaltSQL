(** Runtime configuration document ([kind: Config]) for the CLI and server. Supports
    [${env:NAME}] and [${file:/path}] placeholders (never allowed in policies).
    Precedence: flags > HALTSQL_* env vars > file > defaults; this module handles file +
    env, callers apply flags. *)

open Haltsql_core

type token = {
  token_name : string;
  token_sha256 : string;  (** lower-case hex SHA-256 of the bearer token *)
  token_policy : string;  (** name of the policy this token is pinned to *)
}

type audit_sink = Audit_stdout | Audit_file of string

type t = {
  listen : string;  (** ["host:port"], default ["127.0.0.1:8080"] *)
  tls_cert : string option;
  tls_key : string option;
  tokens : token list;
  allow_unauthenticated : bool;  (** default false; only for local development *)
  policies : (string * Policy.t) list;  (** policy name -> compiled policy *)
  policy_files : string list;  (** absolute paths, for hot reload *)
  default_policy : string option;  (** used by unauthenticated requests *)
  reload_watch : bool;
  audit_sinks : audit_sink list;
  log_raw_sql : bool;
  log_level : string;  (** debug | info | warn | error *)
  log_format : string;  (** json | text *)
  metrics : bool;
  max_request_bytes : int;
}

val default : t

val of_json :
  ?file:string ->
  ?base_dir:string ->
  ?env:(string -> string option) ->
  Yojson.Safe.t ->
  (t, Load_error.t list) result

val of_file : ?env:(string -> string option) -> string -> (t, Load_error.t list) result

val to_json_redacted : t -> Yojson.Safe.t
(** Effective config for [haltsql config show]; secrets replaced by ["<redacted>"]. *)
