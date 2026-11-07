(** SCRAM-SHA-256 (RFC 5802, RFC 7677) as used by PostgreSQL, both sides.

    Channel binding is not offered (mechanism ["SCRAM-SHA-256"] only); a client that
    requests it (gs2 flag ['p']) is rejected. Passwords are used as raw UTF-8 bytes:
    SASLprep normalization is the identity for ASCII passwords, which is what HaltSQL
    supports for proxy users (generate verifiers with [haltsql-proxy scram-verifier]). *)

val mechanism : string
(** ["SCRAM-SHA-256"] *)

val pbkdf2_sha256 : password:string -> salt:string -> iterations:int -> string
(** RFC 5802 [Hi()], 32-byte output. *)

type verifier = {
  iterations : int;
  salt : string;  (** raw bytes *)
  stored_key : string;  (** raw 32 bytes *)
  server_key : string;  (** raw 32 bytes *)
}

val parse_verifier : string -> (verifier, string) result
(** Parses PostgreSQL's stored format
    [SCRAM-SHA-256$<iterations>:<salt b64>$<StoredKey b64>:<ServerKey b64>]. *)

val verifier_to_string : verifier -> string

val make_verifier : ?iterations:int -> ?salt:string -> string -> verifier
(** [make_verifier password]; default 4096 iterations and a random 16-byte salt. *)

(** Server side (the proxy authenticating its clients). *)
module Server : sig
  type t

  val start :
    verifier:verifier option ->
    mock_secret:string ->
    user:string ->
    server_nonce:string ->
    string ->
    (t * string, string) result
  (** [start ~verifier ~mock_secret ~user ~server_nonce client_first] returns the state
      and the server-first-message. With [verifier = None] (unknown user) a deterministic
      fake salt derived from [mock_secret] and [user] is used and authentication always
      fails at {!finish}, so user existence is not revealed. *)

  val finish : t -> string -> (string, string) result
  (** [finish t client_final] verifies the proof (constant time) and returns the
      server-final-message ["v=..."]. *)
end

(** Client side (the proxy authenticating to the upstream server). *)
module Client : sig
  type t

  val first : ?user:string -> nonce:string -> unit -> t * string
  (** [first ~nonce ()] is the state and client-first-message ["n,,n=<user>,r=<nonce>"].
      PostgreSQL ignores the SCRAM user name (default empty) in favour of the startup
      packet's. *)

  val final : t -> password:string -> string -> (t * string, string) result
  (** [final t ~password server_first] checks the server nonce extends ours and returns
      the client-final-message. *)

  val verify_server : t -> string -> (unit, string) result
  (** Checks the server-final-message signature (mutual authentication). *)
end
