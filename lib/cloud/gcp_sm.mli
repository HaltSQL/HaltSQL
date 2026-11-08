(** Google Secret Manager reader for [${gcp-sm:<name>[#<json-key>]}] placeholders.

    [<name>] is [projects/P/secrets/S/versions/V], [projects/P/secrets/S] (latest
    version), or a short [S] / [S/versions/V] resolved in [secrets.gcp.project]. Calls
    [GET /v1/<name>:access] on [https://secretmanager.googleapis.com] (or the configured
    endpoint) with an OAuth2 token, base64-decodes [payload.data] and checks
    [payload.dataCrc32c] when present. A 401 refreshes the token once. *)

type t

val create :
  ?env:(string -> string option) ->
  ?now:(unit -> float) ->
  ?timeout:float ->
  ?auth:Gcp_auth.t ->
  Haltsql_load.Config.gcp_secrets ->
  t
(** [auth] defaults to {!Gcp_auth.default} (created on first use). *)

val resource_name : project:string option -> string -> (string, string) result
val get : t -> string -> (string, string) result Lwt.t
