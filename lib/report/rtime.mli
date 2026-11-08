(** Timestamps of audit records (RFC 3339, UTC) and the [--since]/[--until] bounds. No
    dependency on [Unix]. *)

val parse_rfc3339 : string -> float option
(** [YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)] (a space instead of [T] and a lower-case
    [t]/[z] are accepted) to Unix seconds. [None] for anything else. *)

val to_rfc3339 : float -> string
(** UTC, second precision: [2024-06-01T12:00:00Z]. *)

val parse_bound : now:float -> string -> (float, string) result
(** A time bound: an RFC 3339 timestamp, a date [YYYY-MM-DD] (midnight UTC), or a duration
    before [now] such as [30m], [24h], [7d] or [90s]. *)

val parse_duration : string -> (int, string) result
(** [90s], [30m], [24h], [7d] to seconds (positive). *)
