(** OCI content digests ([sha256:<hex>], [sha512:<hex>]). *)

type algorithm = Sha256 | Sha512

val algorithm_of : string -> algorithm option
(** The algorithm of a well-formed digest ([None] for anything else, including upper-case
    hex or a wrong length). *)

val compute : algorithm -> string -> string
val sha256 : string -> string

val matches : expected:string -> string -> bool
(** [matches ~expected content]: [expected] is well formed and is the digest of [content]
    under its own algorithm. *)
