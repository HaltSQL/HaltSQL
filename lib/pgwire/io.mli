(** Buffered byte transport over a plain socket or a TLS session, with PostgreSQL message
    framing and size limits. *)

exception Closed
(** The peer closed the connection (EOF). *)

exception Too_large of int
(** A message announced a length above the configured limit. *)

type t

val of_fd : Lwt_unix.file_descr -> t
(** Plaintext transport over a connected socket. *)

val of_tls : Lwt_unix.file_descr -> Tls_lwt.Unix.t -> t
(** Transport over an established TLS session on that socket. *)

val fd : t -> Lwt_unix.file_descr
(** The underlying socket. *)

val tls : t -> Tls_lwt.Unix.t option
(** The TLS session, when the transport is encrypted. *)

val buffered : t -> int
(** Bytes read from the peer but not yet consumed. Must be 0 right before a TLS upgrade
    (otherwise a man in the middle could inject plaintext; CVE-2021-23214/23222). *)

val read_exact : t -> int -> string Lwt.t
(** [read_exact t n] is exactly [n] bytes; fails with {!Closed} on EOF. Callers bound [n]
    (see {!read_message}). *)

val read_byte : t -> char Lwt.t
(** One byte; fails with {!Closed} on EOF. *)

val read_startup : t -> max:int -> string Lwt.t
(** Untagged startup-phase packet body (without its 4-byte length). Lengths below 8 raise
    {!Wire.Malformed}; above [max], {!Too_large}. *)

val read_message : t -> max:int -> (char * string) Lwt.t
(** Tagged message: [(tag, payload)]. The announced length is validated before the payload
    buffer is allocated: below 4 (including negative values) raises {!Wire.Malformed}; a
    payload above [max] bytes raises {!Too_large}. *)

val write : t -> string -> unit Lwt.t
(** Writes all bytes. Serialized by an internal mutex, so concurrent writers never
    interleave messages. *)

val close : t -> unit Lwt.t
(** Idempotent; never raises. *)
