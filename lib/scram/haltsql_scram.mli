(** SCRAM (RFC 5802) with SHA-256 and SHA-512 (RFC 7677), without channel binding.

    Pure: no IO and no randomness. The caller supplies nonces and salts (from a CSPRNG)
    and moves the messages. Nothing here raises on malformed peer input.

    Rules that hold for both roles:
    - Channel binding is not offered. The client sends the GS2 header ["n,,"]; the server
      refuses ["p=..."] and accepts ["n"] and ["y"].
    - Mandatory extensions ([m=]) are refused.
    - Attributes are parsed by position, as the RFC grammar orders them. A part that is
      not [<letter>=<value>] makes the whole message malformed.
    - Base64 values must be the canonical padded encoding.
    - Secrets are compared with [Eqaf] (constant time).
    - A message longer than {!max_message_length} is refused.
    - SASLprep is not applied: user names and passwords are used as the bytes given. That
      is exact for ASCII, and it is what PostgreSQL falls back to and what Kafka's client
      does. User names are escaped ([=] as [=3D], [,] as [=2C]). *)

type hash = SHA256 | SHA512

val mechanism : hash -> string
(** ["SCRAM-SHA-256"] or ["SCRAM-SHA-512"]. *)

val max_message_length : int
(** 4096 bytes. *)

val default_min_iterations : int
(** 4096, the RFC 7677 minimum. *)

val default_max_iterations : int
(** 600_000. Bounds the work a hostile server can make the client do. *)

val nonce_entropy_bytes : int
(** 24. Callers generate this many CSPRNG bytes and pass them to {!nonce_of_entropy}. *)

val nonce_of_entropy : string -> string
(** Base64 of the given random bytes: a valid SCRAM nonce. *)

val hi : hash -> password:string -> salt:string -> iterations:int -> string
(** RFC 5802 [Hi]: PBKDF2-HMAC with one output block. An iteration count below 1 is
    treated as 1. *)

val equal_ct : string -> string -> bool
(** Constant-time equality ([Eqaf.equal]). The lengths are not secret. *)

type error =
  | Message_too_long
  | Malformed_client_first
  | Malformed_server_first
  | Malformed_client_final
  | Malformed_server_final
  | Unsupported_extension  (** a mandatory extension ([m=]) *)
  | Channel_binding_unsupported  (** the client asked for it ([p=]) *)
  | Authzid_unsupported
  | Channel_binding_mismatch  (** [c=] is not the GS2 header the client sent *)
  | Invalid_nonce  (** empty, or not printable ASCII without [','] *)
  | Nonce_not_extended  (** client: the server nonce does not extend ours *)
  | Nonce_mismatch  (** server: the client-final nonce is not the one we issued *)
  | Invalid_salt  (** not canonical base64, or empty *)
  | Invalid_iteration_count  (** not decimal digits *)
  | Iteration_count_out_of_range of { count : int; min : int; max : int }
  | Invalid_proof
  | Server_error of string
      (** the server's [e=] value; bytes outside printable ASCII are replaced by ['?'] *)
  | Server_signature_mismatch
  | Authentication_failed  (** wrong proof, or an unknown user *)

val error_to_string : error -> string

(** {1 Client} *)

type client_first = {
  nonce : string;
  bare : string;  (** [n=<user>,r=<nonce>] *)
  message : string;  (** client-first-message: ["n,,"] followed by [bare] *)
}

val client_first : ?user:string -> nonce:string -> unit -> client_first
(** [user] defaults to [""] (PostgreSQL ignores it and uses the startup packet's). An
    invalid [nonce] is reported by {!client_final} as [Invalid_nonce]. *)

type client_final = {
  final_message : string;  (** client-final-message, with the proof *)
  server_signature : string;  (** the raw signature the server must send back *)
}

val client_final :
  ?min_iterations:int ->
  ?max_iterations:int ->
  hash ->
  client_first ->
  password:string ->
  server_first:string ->
  (client_final, error) result
(** Checks the server-first-message ([r=...,s=...,i=...] in that order): the nonce must
    extend ours by at least one character and be a valid nonce, the salt must be non-empty
    canonical base64, and the iteration count must be decimal digits within
    [min_iterations] (default {!default_min_iterations}) and [max_iterations] (default
    {!default_max_iterations}). *)

val verify_server_signature : expected:string -> string -> (unit, error) result
(** [verify_server_signature ~expected server_final] checks the server-final-message
    against the raw signature [expected]. [v=<signature>] must match in constant time
    (mutual authentication); [e=<error>] is [Server_error]; a message that carries both is
    refused. *)

val verify_server_final : client_final -> string -> (unit, error) result
(** {!verify_server_signature} with the signature from {!client_final}. The connection
    must not be trusted before this returns [Ok ()]. *)

(** {1 Server (SCRAM-SHA-256)} *)

type verifier = {
  iterations : int;
  salt : string;  (** raw bytes *)
  stored_key : string;  (** raw 32 bytes *)
  server_key : string;  (** raw 32 bytes *)
}

val parse_verifier : string -> (verifier, string) result
(** PostgreSQL's stored format:
    [SCRAM-SHA-256$<iterations>:<salt b64>$<StoredKey b64>:<ServerKey b64>]. *)

val verifier_to_string : verifier -> string
(** The format {!parse_verifier} reads. *)

val make_verifier : ?iterations:int -> salt:string -> string -> verifier
(** [make_verifier ~salt password]; 4096 iterations by default. [salt] must come from a
    CSPRNG (16 bytes, as PostgreSQL uses). *)

type server

val server_start :
  verifier:verifier option ->
  mock_secret:string ->
  user:string ->
  server_nonce:string ->
  string ->
  (server * string, error) result
(** [server_start ~verifier ~mock_secret ~user ~server_nonce client_first] is the state
    and the server-first-message. With [verifier = None] (unknown user) a salt and keys
    derived from [mock_secret] and [user] are used and {!server_finish} always fails, so
    the exchange does not reveal whether the user exists. *)

val server_finish : server -> string -> (string, error) result
(** [server_finish t client_final] checks the channel-binding echo, the nonce and the
    proof, and returns the server-final-message ["v=..."]. *)
