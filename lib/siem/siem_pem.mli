(** Loading the PEM material of the streaming sinks' configuration. Error messages name
    the file (or "inline PEM") and never contain key material. *)

val read : what:string -> Haltsql_load.Config.pem -> (string, string) result
(** The PEM text: the file's contents or the inline value. *)

val certificates :
  what:string -> Haltsql_load.Config.pem -> (X509.Certificate.t list, string) result
(** At least one certificate. *)

val private_key :
  what:string -> Haltsql_load.Config.pem -> (X509.Private_key.t, string) result
