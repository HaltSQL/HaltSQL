(** Small HTTP client over cohttp-lwt-unix with a hard deadline, a response size cap and
    optional custom CA trust. Error strings never contain request or response bodies. *)

type response = { status : int; headers : (string * string) list; body : string }

type ctx
(** Connection context (TLS trust). *)

val default_ctx : ctx
(** System trust store (ca-certs). *)

val ctx_of_ca_file : string -> (ctx, string) result Lwt.t
(** Trust only the PEM CA certificates in this file (e.g. a private Vault CA). *)

val request :
  ?ctx:ctx ->
  ?timeout:float ->
  ?max_body:int ->
  ?headers:(string * string) list ->
  ?body:string ->
  Cohttp.Code.meth ->
  Uri.t ->
  (response, string) result Lwt.t
(** Defaults: [timeout] 10 s, [max_body] 8 MiB. [Error] on timeout, connection failure or
    an oversized response. Non-2xx statuses are [Ok] responses. *)

val header : response -> string -> string option
(** Case-insensitive response header lookup. *)

val form_encode : (string * string) list -> string
(** [application/x-www-form-urlencoded] body. *)

val pct_encode : ?keep_slash:bool -> string -> string
(** RFC 3986 percent-encoding: unreserved characters ([A-Za-z0-9-_.~]) are kept, and ['/']
    when [keep_slash] (default false). Upper-case hex. *)

val host_header : Uri.t -> string
(** [host] or [host:port] when the port is not the scheme default. *)

val is_loopback_http : string -> bool
(** [http://] URL whose host is [localhost], [127.x.x.x] or [::1]. *)

val check_endpoint : what:string -> string -> (Uri.t, string) result
(** Accepts an [https] URL, or an [http] URL with a loopback host; no credentials, query
    or fragment. *)
