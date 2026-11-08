(** HTTP requests for bundle sources, on top of {!Haltsql_cloud.Http}: redirect following
    that never leaks credentials, plus error classification. *)

val ensure_rng : unit -> unit
(** Initialises the CSPRNG that TLS needs (idempotent). *)

val request :
  ?ctx:Haltsql_cloud.Http.ctx ->
  ?timeout:float ->
  ?max_body:int ->
  ?headers:(string * string) list ->
  ?authorization:string ->
  ?body:string ->
  ?follow:int ->
  Cohttp.Code.meth ->
  Uri.t ->
  (Haltsql_cloud.Http.response, Fetch_error.t) result Lwt.t
(** [authorization] is sent as the [Authorization] header to the origin (scheme, host,
    port) of the first URI only: when a redirect leads to another origin it is dropped.
    [GET] and [HEAD] follow up to [follow] (default 3) redirects (301, 302, 303, 307,
    308); a redirect target must be [https], or [http] on a loopback host, and must not
    carry credentials. Other methods never follow redirects. Transport errors are
    [Unavailable]; a response larger than [max_body] is [Integrity]. *)

val check_url : what:string -> Uri.t -> (unit, string) result
(** [https], or [http] with a loopback host; no userinfo or fragment (a query is allowed).
*)

val check_target_from : what:string -> from:Uri.t -> Uri.t -> (unit, string) result
(** Like {!check_url}, and also forbids [https] to [http] scheme downgrades and redirects
    from a non-loopback host to a loopback host. *)

val basic : username:string -> password:string -> string
(** [Basic <base64(user:password)>] *)
