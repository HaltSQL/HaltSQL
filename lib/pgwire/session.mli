(** One client connection: startup, TLS upgrade, client authentication, upstream
    connection and the enforcing message relay. *)

type shared = {
  cfg : Proxy_config.t;
  tls_server : Tls.Config.server option;
  audit : Plog.audit;
  mock_secret : string;  (** per-process secret for SCRAM mock authentication *)
  cancel_table : (int, int * int * int) Hashtbl.t;
      (** proxy pid -> (proxy key, upstream pid, upstream key) *)
}

val handle : shared -> id:string -> Lwt_unix.file_descr -> unit Lwt.t
(** Serves the connection to completion and closes it. Never raises. *)

val sentinel_prefix : string
(** Statements injected upstream in place of denied ones start with this prefix. *)
