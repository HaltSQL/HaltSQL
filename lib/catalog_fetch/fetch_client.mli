(** HTTP plumbing shared by the live catalog fetchers: endpoint validation, bearer auth,
    JSON GET/POST, and a bounded cursor-pagination loop.

    Guarantees: the token is sent only as an [Authorization] header to the configured base
    URL's origin, never logged, and never part of an error message; error messages name
    the method, path and HTTP status but never include response bodies. *)

type auth = No_auth | Bearer of string
type t

val create :
  ?ctx:Haltsql_cloud.Http.ctx ->
  ?timeout:float ->
  ?max_pages:int ->
  ?max_body:int ->
  base_url:string ->
  auth ->
  (t, string) result
(** [base_url] must be [https://...], or [http://] on a loopback host
    ({!Haltsql_cloud.Http.check_endpoint}); it may carry a path prefix (e.g.
    [https://datahub.example.com/gms]), which is prepended to every request path. No
    credentials, query or fragment. Defaults: [timeout] 30 s per request, [max_pages]
    1000, [max_body] 32 MiB. *)

val base_url : t -> Uri.t

val get_json :
  t -> ?query:(string * string) list -> string -> (Yojson.Safe.t, string) result Lwt.t
(** [get_json t path]: GET [base_url ^ path] with [Accept: application/json]. Non-2xx
    statuses, non-JSON bodies and transport failures are [Error]s. *)

val post_json :
  t ->
  ?query:(string * string) list ->
  string ->
  Yojson.Safe.t ->
  (Yojson.Safe.t, string) result Lwt.t
(** As {!get_json}, POSTing a JSON body. *)

val paginate :
  t ->
  what:string ->
  (string option -> (Yojson.Safe.t list * string option, string) result Lwt.t) ->
  (Yojson.Safe.t list, string) result Lwt.t
(** [paginate t ~what page] calls [page None], then [page (Some cursor)] with each
    returned cursor until a page returns [None], concatenating the items in order. Fails
    (naming [what]) when a cursor repeats or more than [max_pages] pages are requested, so
    a misbehaving server cannot loop forever. *)

val request_count : t -> int
(** HTTP requests sent so far through this client. *)
