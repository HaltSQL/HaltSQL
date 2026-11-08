(** Fetching a bundle and its detached signature from HTTPS or S3.

    The bundle lives at the configured URL / object key, its signature next to it with
    [.sig] appended. The bundle request is conditional ([If-None-Match] with the ETag of
    the last accepted bundle); the signature is fetched only when the bundle changed.
    Publishers should therefore upload the new signature {e before} the new bundle. *)

type fetched = {
  bundle : string;
  signature : string;
  etag : string option;  (** of the bundle *)
}

type outcome = Not_modified | Fetched of fetched

val https :
  ?ctx:Haltsql_cloud.Http.ctx ->
  ?timeout:float ->
  ?authorization:string ->
  etag:string option ->
  string ->
  (outcome, Fetch_error.t) result Lwt.t
(** [authorization] is the full [Authorization] header value. *)

val s3_object_url : Haltsql_load.Config.s3_source -> string -> Uri.t
(** Path-style [endpoint/bucket/key] with an endpoint, else
    [https://<bucket>.s3.<region>.amazonaws.com/<key>]. *)

val s3 :
  ?ctx:Haltsql_cloud.Http.ctx ->
  ?timeout:float ->
  ?now:(unit -> float) ->
  credentials:Haltsql_cloud.Aws_creds.t ->
  etag:string option ->
  Haltsql_load.Config.s3_source ->
  (outcome, Fetch_error.t) result Lwt.t
(** SigV4-signed [GET]s (service [s3]). *)
