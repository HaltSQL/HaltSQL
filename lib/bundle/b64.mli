(** Strict standard base64 (RFC 4648 alphabet, padded). *)

val encode : string -> string
(** Standard alphabet, padded. *)

val decode : string -> string option
(** [None] unless the input is the canonical padded encoding of some byte string (no
    whitespace, no missing or extra padding, no non-zero trailing bits). *)
