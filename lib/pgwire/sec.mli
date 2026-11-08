(** Small security helpers shared by the proxy: constant-time comparison, base64, hex,
    randomness and MD5/SHA-256 wrappers. *)

val ct_equal : string -> string -> bool
(** Constant-time in the content (the length is not secret). *)

val b64_encode : string -> string
(** Standard alphabet with padding (RFC 4648 section 4). *)

val b64_decode : string -> string option
(** Strict: padding required, no whitespace, no non-alphabet characters, and the unused
    bits before padding must be zero (canonical encodings only). *)

val hex : string -> string
(** Lower-case hex. *)

val init_rng : unit -> unit
(** Seeds the process-wide CSPRNG (idempotent). Must run before {!random}. *)

val random : int -> string
(** [random n] is [n] bytes from the CSPRNG. *)

val random_hex : int -> string
(** [random_hex n] is [2n] hex characters. *)

val random_int32 : unit -> int
(** A random signed 32-bit integer. *)

val md5_hex : string -> string
(** Lower-case hex MD5 (only for PostgreSQL's legacy md5 password exchange). *)

val sha256 : string -> string
(** Raw 32-byte SHA-256 digest. *)

val hmac_sha256 : key:string -> string -> string
(** Raw 32-byte HMAC-SHA-256. *)

val xor : string -> string -> string
(** Byte-wise XOR of two equal-length strings. Raises [Invalid_argument] on a length
    mismatch. *)
