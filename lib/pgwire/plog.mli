(** Structured JSON-lines logging (stderr). The hash-chained audit log is {!Paudit}.

    Log records never contain secrets: no passwords, verifiers, SCRAM messages, TLS keys,
    bind values or (unless [log_raw_sql]) SQL text. *)

type level = Debug | Info | Warn | Error

val set_level : string -> unit
(** ["debug" | "info" | "warn" | "error"]; unknown strings leave the level unchanged. *)

val log : level -> string -> (string * Yojson.Safe.t) list -> unit
(** [log level msg fields] writes one JSON object to stderr if [level] is enabled. *)

val now_rfc3339 : unit -> string
(** Current UTC time, RFC 3339 with milliseconds. *)
