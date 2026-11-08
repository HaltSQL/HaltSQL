(** One client connection: startup, TLS upgrade, client authentication, upstream
    connection and the enforcing message relay. *)

type shared = {
  cfg : Proxy_config.t;
      (** the configuration snapshot this session runs under, from accept to close; a
          reload never changes it *)
  generation : int;  (** config generation (1 at start, +1 per successful reload) *)
  tls_server : Tls.Config.server option;
  audit : Paudit.t;  (** process-wide: one chain per sink across every generation *)
  mock_secret : string;  (** per-process secret for SCRAM mock authentication *)
  cancel_table : (int, int * int * int * Proxy_config.upstream) Hashtbl.t;
      (** proxy pid -> (proxy key, upstream pid, upstream key, upstream it runs on);
          shared across generations *)
}

val handle : shared -> id:string -> Lwt_unix.file_descr -> unit Lwt.t
(** Serves the connection to completion and closes it. Never raises. *)

val audit_sqlstate : string
(** ["58030"] ([io_error]): statements refused because their audit record could not be
    written (fail closed). *)

val sentinel_prefix : string
(** Statements injected upstream in place of denied ones start with this prefix. *)
