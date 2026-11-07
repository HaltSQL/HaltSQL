(** AWS Secrets Manager reader for [${aws-sm:<secret-id>[#<json-key>]}] placeholders.

    Calls [GetSecretValue] (JSON 1.1 protocol, SigV4 service [secretsmanager]) on
    [https://secretsmanager.<region>.amazonaws.com] or the configured endpoint. Returns
    [SecretString] (or the decoded [SecretBinary]); with [#key], the value is parsed as a
    JSON object and that key's scalar is returned. Credential errors invalidate the cached
    credentials and are retried once. *)

type t

val create :
  ?env:(string -> string option) ->
  ?now:(unit -> float) ->
  ?timeout:float ->
  ?credentials:Aws_creds.t ->
  Haltsql_load.Config.aws_secrets ->
  t
(** [credentials] defaults to {!Aws_creds.default_chain} in the configured region. *)

val get : t -> string -> (string, string) result Lwt.t
