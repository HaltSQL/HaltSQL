(** Per-connection information handed to request handlers. *)

type t = {
  remote : string;
  tls : bool;
  peer : Haltsql_auth.Mtls.peer option;
  mutable input_discarded : bool;
}

let make ~remote ~tls ~peer = { remote; tls; peer; input_discarded = false }
let plain remote = make ~remote ~tls:false ~peer:None
let discard_input t = t.input_discarded <- true
let input_discarded t = t.input_discarded

let string_of_sockaddr = function
  | Unix.ADDR_INET (a, p) -> Printf.sprintf "%s:%d" (Unix.string_of_inet_addr a) p
  | Unix.ADDR_UNIX s -> s
