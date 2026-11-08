(** A minimal OCI Distribution Spec v1.1 client: manifests and blobs, pull and push.

    Authentication follows the registry: a request is first sent with the credentials
    already established for it; on [401] the [WWW-Authenticate] challenge decides:
    - [Bearer realm=...,service=...]: a token is requested from [realm] (which must be
      [https], or [http] on a loopback host) with [service] and the repository scope
      ([repository:<repo>:pull], or [pull,push] for uploads), anonymously or with the
      basic credentials, and cached until shortly before [expires_in];
    - [Basic]: the basic credentials are sent (an error without credentials).

    Every manifest and blob that is read is hashed and compared with its expected digest;
    nothing unverified is returned. Credentials and tokens are never part of an error
    message. *)

type credentials =
  | Anonymous
  | Basic of { username : string; password : string }
  | Bearer of string  (** a pre-issued registry token, sent as is *)

type t

val create :
  ?ctx:Haltsql_cloud.Http.ctx ->
  ?timeout:float ->
  ?plain_http:bool ->
  ?now:(unit -> float) ->
  credentials:credentials ->
  Oci_ref.t ->
  (t, string) result
(** [plain_http] (default false) is refused unless the registry is a loopback address. *)

val reference : t -> Oci_ref.t

val manifest_accept : string list
(** Media types sent in [Accept] for manifests: OCI image manifest, OCI image index,
    Docker schema 2 manifest and list. *)

val max_manifest_bytes : int
(** 4 MiB *)

type manifest = {
  digest : string;  (** verified digest of [body] *)
  media_type : string option;  (** [Content-Type] of the response *)
  body : string;
}

val head_manifest : t -> string -> (string option, Fetch_error.t) result Lwt.t
(** [head_manifest t reference]: the [Docker-Content-Digest] the registry reports for a
    tag or digest, without downloading the manifest. The value is {e not} verified: use it
    only to detect that nothing changed. *)

val get_manifest : t -> string -> (manifest, Fetch_error.t) result Lwt.t
(** Downloads a manifest by tag or digest and verifies it: when [reference] is a digest
    the body must hash to it; when the registry sends [Docker-Content-Digest] the body
    must hash to that as well. The returned digest uses the algorithm of the reference (or
    of the header), sha256 by default. *)

val get_blob : t -> digest:string -> size:int -> (string, Fetch_error.t) result Lwt.t
(** Downloads a blob of exactly [size] bytes whose content must hash to [digest].
    Redirects (e.g. to object storage) are followed without the registry credentials. *)

val blob_exists : t -> string -> (bool, Fetch_error.t) result Lwt.t

val push_blob : t -> string -> (string, Fetch_error.t) result Lwt.t
(** Uploads a blob (monolithic [POST] then [PUT ?digest=]) unless the registry already has
    it, and returns its sha256 digest. *)

val put_manifest :
  t ->
  reference:string ->
  media_type:string ->
  string ->
  (string, Fetch_error.t) result Lwt.t
(** Uploads a manifest under a tag or its digest and returns its sha256 digest (checked
    against the [Docker-Content-Digest] the registry answers with). *)
