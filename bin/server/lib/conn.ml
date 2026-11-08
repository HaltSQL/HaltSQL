(* Per-connection information handed to request handlers. *)

type t = {
  remote : string;  (** peer address, for logs *)
  tls : bool;  (** the connection is TLS *)
  peer : Haltsql_auth.Mtls.peer option;  (** verified client certificate identity *)
}

let plain remote = { remote; tls = false; peer = None }

let string_of_sockaddr = function
  | Unix.ADDR_INET (a, p) -> Printf.sprintf "%s:%d" (Unix.string_of_inet_addr a) p
  | Unix.ADDR_UNIX s -> s
