(** Standard base64 (RFC 4648 alphabet, padded). Used by the SCRAM exchange. *)

val encode : string -> string

val decode : string -> string option
(** [None] on malformed input (bad length, characters or padding). *)
