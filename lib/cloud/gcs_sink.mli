(** Google Cloud Storage audit sink: an {!Object_sink} whose uploader uses the JSON API
    simple upload
    ([POST /upload/storage/v1/b/<bucket>/o?uploadType=media&name=... &ifGenerationMatch=0]).

    [ifGenerationMatch=0] makes objects create-only (a 412 for a name that embeds the
    body's SHA-256 counts as delivered). The [md5Hash] returned by GCS must equal the
    body's MD5, otherwise the upload is treated as failed. A 401 invalidates the cached
    token and is retried; 429/5xx are retried.

    The API base is [https://storage.googleapis.com], or [endpoint], or the
    [STORAGE_EMULATOR_HOST] environment variable. *)

val upload :
  ?timeout:float ->
  ?endpoint:string ->
  auth:Gcp_auth.t ->
  bucket:string ->
  key:string ->
  body:string ->
  unit ->
  (unit, Object_sink.upload_error) result Lwt.t

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
  ?endpoint:string ->
  ?auth:Gcp_auth.t ->
  ?on_event:(string -> unit) ->
  on_error:Haltsql_load.Config.on_error ->
  Haltsql_load.Config.gcs_sink ->
  (Object_sink.t, string) result
(** [auth] defaults to the configured credentials (metadata server or service-account
    file). [spool_dir] defaults to [cfg.gcs_spool_dir]. Named ["gs://<bucket>/<prefix>"].
    Not started. *)
