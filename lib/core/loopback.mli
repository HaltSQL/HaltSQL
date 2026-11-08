(** Loopback host names, for the rules that allow plain text (http, plain Kafka, a
    registry without TLS) only on loopback. *)

val is_ipv4_loopback : string -> bool
(** A dotted-quad IPv4 address in 127.0.0.0/8: exactly four decimal octets (1-3 digits,
    0-255), the first one [127]. ["127.evil.example"], ["127.0.0.1.nip.io"] and ["127.1"]
    are not. *)

val is_host : string -> bool
(** [localhost], [::1] / [[::1]], or {!is_ipv4_loopback} (case-insensitive). Any other
    name is not loopback, even when it resolves to a loopback address. *)
