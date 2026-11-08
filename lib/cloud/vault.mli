(** HashiCorp Vault KV v2 reader for [${vault:<path>#<field>}] placeholders.

    {1 Paths}

    A reference [<mount>/<path>#<field>] reads [GET /v1/<mount>/data/<path>] and returns
    [data.data.<field>]. If the second segment is already [data]
    (["secret/data/app#token"]) the path is used as written. Mounts with several segments
    must therefore be written in the explicit [.../data/...] form. Segments may not be
    empty, ["."] or [".."] and are percent-encoded.

    {1 Authentication}

    [token] uses the configured token. [kubernetes] posts [{role, jwt}] (the JWT read from
    [jwt_path]) to [/v1/auth/<mount>/login]; [approle] posts [{role_id, secret_id}]. The
    client token is cached until 30 s before its lease ends; a 403 on a read triggers one
    re-login. [X-Vault-Namespace] is sent when a namespace is configured, and [ca_file]
    replaces the system trust store. Errors carry Vault's error strings and HTTP status,
    never secret values or tokens. *)

type t

val create : ?now:(unit -> float) -> ?timeout:float -> Haltsql_load.Config.vault -> t

val read : t -> string -> (string, string) result Lwt.t
(** [read t "secret/app#token"]. *)

val api_path : string -> (string, string) result
(** The [/v1/...] request path for a reference path (without [#field]). *)
