(** SCRAM-SHA-256 client (RFC 5802 / RFC 7677) as used by PostgreSQL authentication,
    without channel binding (gs2 header ["n,,"]).

    Pure: the caller supplies the client nonce and drives the message exchange. *)

type state

val client_first : user:string -> nonce:string -> state * string
(** Returns the client-first-message (["n,,n=<user>,r=<nonce>"]). PostgreSQL ignores the
    SCRAM user name (it uses the startup user), so callers pass [""] there. [nonce] must
    be printable ASCII without [','] (e.g. base64 of 18 random bytes). *)

val client_final :
  state -> password:string -> server_first:string -> (state * string, string) result
(** Validates server-first-message (the server nonce must extend ours, iteration count
    sane) and returns client-final-message with the proof. *)

val verify_server_final : state -> string -> (unit, string) result
(** Checks the server signature in server-final-message ([v=...]) in constant time. Must
    succeed before the connection is trusted. *)

val pbkdf2_sha256 : password:string -> salt:string -> iterations:int -> string
(** 32-byte PBKDF2-HMAC-SHA-256 (exposed for tests). *)

val constant_time_equal : string -> string -> bool
