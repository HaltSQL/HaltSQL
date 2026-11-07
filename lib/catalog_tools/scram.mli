(** SCRAM-SHA-256 client (RFC 5802 / RFC 7677) as used by PostgreSQL authentication.

    Pure functions; the caller supplies the client nonce. Channel binding is not used (GS2
    header ["n,,"]). The password is used as given (no SASLprep normalization), which is
    exact for ASCII passwords; PostgreSQL itself falls back to the raw bytes when a
    password is not valid SASLprep input. *)

type client_first = { message : string;  (** full client-first message *) bare : string }

val client_first : user:string -> nonce:string -> client_first
(** PostgreSQL ignores the SCRAM user name; pass [""] for it. *)

type client_final = {
  final_message : string;  (** client-final message to send *)
  expected_server_signature : string;  (** raw bytes *)
}

val client_final :
  password:string ->
  client_first:client_first ->
  client_nonce:string ->
  server_first:string ->
  (client_final, string) result
(** Validates the server-first message (the combined nonce must extend ours; the iteration
    count must be between 1 and 10_000_000) and computes the proof. *)

val verify_server_final : client_final -> string -> (unit, string) result
(** Checks [v=<signature>] in constant time; [e=...] server errors are reported. *)

val pbkdf2_sha256 : password:string -> salt:string -> iterations:int -> string
(** PBKDF2-HMAC-SHA-256 with a 32-byte output. Exposed for tests. *)

val equal_ct : string -> string -> bool
(** Constant-time string equality (length is not secret). *)
