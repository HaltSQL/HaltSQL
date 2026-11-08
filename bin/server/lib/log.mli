(** Structured logging to stderr.

    Two formats, chosen at startup with {!setup}:
    - ["json"] (default): one JSON object per line, [{"ts", "level", "msg", ...fields}];
    - ["text"]: [ts LEVEL msg key=value ...]. Values containing spaces, [=], quotes or
      control characters are written as JSON strings, so a record always stays on one line
      (request paths, for instance, are attacker-controlled).

    Logging is process-wide and synchronous. Callers must never pass secrets (tokens, key
    material, secret values) or raw SQL as fields. *)

type level = Debug | Info | Warn | Error

val setup : level:string -> format:string -> unit
(** [setup ~level ~format] sets the minimum level (["debug"], ["info"], ["warn"] /
    ["warning"], ["error"]; anything else means ["info"]) and the format (["text"], or
    JSON for anything else). *)

val enabled : level -> bool
(** Whether records at this level are currently emitted. *)

val rfc3339 : float -> string
(** A Unix time as RFC 3339 UTC with milliseconds, e.g. [2026-01-31T12:00:00.123Z]. *)

val emit : level -> string -> (string * Yojson.Safe.t) list -> unit
(** [emit level msg fields] writes one record if [level] is enabled. *)

val debug : ?fields:(string * Yojson.Safe.t) list -> string -> unit
(** [emit Debug]. *)

val info : ?fields:(string * Yojson.Safe.t) list -> string -> unit
(** [emit Info]. *)

val warn : ?fields:(string * Yojson.Safe.t) list -> string -> unit
(** [emit Warn]. *)

val error : ?fields:(string * Yojson.Safe.t) list -> string -> unit
(** [emit Error]. *)
