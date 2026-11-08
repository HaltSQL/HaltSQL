(** S3 (and S3-compatible) audit sink: an {!Object_sink} whose uploader PUTs each object
    with SigV4.

    Each PUT carries [Content-MD5], [x-amz-checksum-sha256] (S3 rejects a body that does
    not match either), [x-amz-content-sha256], [If-None-Match: *] (objects are never
    overwritten; a 412 for an object whose name already embeds the body's SHA-256 counts
    as delivered), and, when [object_lock] is configured, [x-amz-object-lock-mode]
    ([GOVERNANCE] / [COMPLIANCE]) and [x-amz-object-lock-retain-until-date] (now +
    [retain_days]).

    URLs: with [endpoint] the request is path-style ([<endpoint>/<bucket>/<key>]);
    otherwise virtual-hosted ([https://<bucket>.s3.<region>.amazonaws.com/<key>]).

    Credential errors ([ExpiredToken], [InvalidToken], [RequestExpired],
    [TokenRefreshRequired]) invalidate the cached credentials and are retried; 429 and 5xx
    are retried; other 4xx are permanent for that attempt. *)

val put_object :
  ?now:(unit -> float) ->
  ?timeout:float ->
  credentials:Aws_creds.t ->
  Haltsql_load.Config.s3_sink ->
  key:string ->
  body:string ->
  (unit, Object_sink.upload_error) result Lwt.t
(** One signed PUT (the uploader used by [create]). *)

val object_url : Haltsql_load.Config.s3_sink -> string -> Uri.t
(** The PUT URL for an object key: virtual-hosted style on AWS, path style
    ([<endpoint>/<bucket>/<key>]) on a custom endpoint. The key is percent-encoded. *)

val create :
  ?env:(string -> string option) ->
  ?now:(unit -> float) ->
  ?host:string ->
  ?run_id:string ->
  ?spool_dir:string ->
  ?max_buffer_records:int ->
  ?max_attempts:int ->
  ?base_backoff:float ->
  ?timeout:float ->
  ?credentials:Aws_creds.t ->
  ?on_event:(string -> unit) ->
  on_error:Haltsql_load.Config.on_error ->
  Haltsql_load.Config.s3_sink ->
  (Object_sink.t, string) result
(** Builds the sink (not started: call {!Object_sink.start}). [credentials] defaults to
    [Aws_creds.create ~region (Aws_creds.source_of_s3 cfg.s3_credentials)]. [spool_dir]
    defaults to [cfg.s3_spool_dir]; see {!Object_sink} for [run_id] and the spool. The
    sink is named ["s3://<bucket>/<prefix>"]. *)
