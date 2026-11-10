(** SCRAM client (RFC 5802) for SCRAM-SHA-256 and SCRAM-SHA-512 (RFC 7677), without
    channel binding (GS2 header [n,,]), as Kafka uses it. The protocol is
    {!Haltsql_scram}; this module adds the CSPRNG nonce.

    User names are escaped ([=] as [=3D], [,] as [=2C]); no SASLprep is applied (Kafka's
    own client does not apply it either), so user names and passwords are used as raw
    UTF-8. The server's signature is always verified (constant-time comparison): a broker
    that cannot prove it knows the password is refused. *)

type hash = Sha256 | Sha512

type client_first = Haltsql_scram.client_first = {
  nonce : string;
  bare : string;  (** [n=<user>,r=<nonce>] *)
  message : string;  (** [n,,] ^ [bare] *)
}

val client_first : ?nonce:string -> username:string -> unit -> client_first
(** [nonce] defaults to 24 random bytes, base64-encoded. *)

val client_final :
  hash ->
  password:string ->
  client_first ->
  server_first:string ->
  (string * string, string) result
(** [(client_final_message, expected_server_signature_base64)]. Fails on a malformed
    server-first message, a server nonce that does not extend the client nonce, a
    mandatory extension, or an iteration count outside 4096..600_000. *)

val verify_server_final : expected:string -> string -> (unit, string) result
(** Checks [v=<signature>] against [expected]; [e=<error>] and anything else fail. *)

val hi : hash -> password:string -> salt:string -> iterations:int -> string
(** PBKDF2 with HMAC (the [Hi] function), raw bytes. *)
