(** Per-connection information handed to request handlers. *)

type t = {
  remote : string;  (** peer address, for logs *)
  tls : bool;  (** the connection is TLS *)
  peer : Haltsql_auth.Mtls.peer option;
      (** identity of the client certificate, already verified against
          [server.tls.client_ca] by the TLS layer *)
}

val plain : string -> t
(** A plain-HTTP connection from this address. *)

val string_of_sockaddr : Unix.sockaddr -> string
