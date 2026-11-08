(** Per-connection information handed to request handlers.

    A value of this type is created by the accept loop ({!Server}) for each client
    connection and passed to {!Http.callback} with every request read from it. *)

type t = private {
  remote : string;  (** peer address, for logs *)
  tls : bool;  (** the connection is TLS *)
  peer : Haltsql_auth.Mtls.peer option;
      (** identity of the client certificate, already verified against
          [server.tls.client_ca] by the TLS layer *)
  mutable input_discarded : bool;  (** see {!discard_input} *)
}

val make : remote:string -> tls:bool -> peer:Haltsql_auth.Mtls.peer option -> t
(** A connection from [remote]. *)

val plain : string -> t
(** A plain-HTTP connection from this address. *)

val discard_input : t -> unit
(** Stops reading from the client: every further read on the connection reports end of
    input. Used when a request body is refused (e.g. 413) so the server does not keep
    receiving, then draining, a body it will never use. The connection is closed once the
    current response has been written. *)

val input_discarded : t -> bool
(** Whether {!discard_input} was called. *)

val string_of_sockaddr : Unix.sockaddr -> string
(** ["host:port"] for an Internet address, the path for a Unix socket. *)
