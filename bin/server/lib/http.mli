(** HTTP routing and handlers for haltsql-server.

    Routes: [POST /v1/verify], [GET /v1/policies], [GET|HEAD /healthz], [GET|HEAD /readyz]
    and [GET /metrics] (unless disabled). Every response carries an [x-request-id]: the
    caller's, if short and made of safe characters, otherwise a fresh UUID v4.

    {b Errors} always have the shape [{"error": {"code": "...", "message": "..."}}].
    Unexpected exceptions become [500 INTERNAL] with a generic message; the exception text
    is logged with the request id, never sent to the client. Upstream failures (for
    example an unreachable identity provider) are reported without internal details.

    {b Request bodies} are limited to [server.max_request_bytes]: a larger declared
    [Content-Length] is refused with 413 before authentication and before any of the body
    is read; a chunked body as soon as it passes the cap. A body that a handler does not
    read is discarded up to the same cap; beyond it the connection is closed rather than
    drained.

    {b Readiness}: [/readyz] is 200 when at least one policy is loaded and every audit
    sink is healthy, and 503 otherwise, including while the server drains for shutdown
    ([{"status": "not_ready", "draining": true, ...}]). [/healthz] is 200 while the
    process runs.

    Each request reads one consistent snapshot of the reloadable settings, even if a
    reload completes while it is in flight. *)

val callback :
  ?health_only:bool ->
  State.t ->
  Conn.t * 'conn_id ->
  Cohttp.Request.t ->
  Cohttp_lwt.Body.t ->
  (Cohttp.Response.t * Cohttp_lwt.Body.t) Lwt.t
(** The cohttp request handler. With [~health_only:true] only [/healthz] and [/readyz] are
    served (404 elsewhere), for the plain-HTTP probe listener. Responses carry
    [connection: close] while the server drains or when the request body was refused. *)

val callback_with :
  before_route:(unit -> unit Lwt.t) ->
  ?health_only:bool ->
  State.t ->
  Conn.t * 'conn_id ->
  Cohttp.Request.t ->
  Cohttp_lwt.Body.t ->
  (Cohttp.Response.t * Cohttp_lwt.Body.t) Lwt.t
(** {!callback} with a step run just before routing, inside the handler that turns an
    unexpected exception into a 500. Exists so tests can make a request fail internally
    and check what the client is told; [callback] is
    [callback_with ~before_route:Lwt.return]. *)
