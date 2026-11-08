(** The OCI artifact layout of a HaltSQL policy bundle (see docs/policy-bundles.md).

    An OCI image manifest (OCI image spec v1.1 artifact guidance, the layout
    [oras push --artifact-type] produces):

    {v
    { "schemaVersion": 2,
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "artifactType": "application/vnd.haltsql.bundle.v1",
      "config": { "mediaType": "application/vnd.oci.empty.v1+json",
                  "digest": "sha256:44136fa3...", "size": 2, "data": "e30=" },
      "layers": [
        { "mediaType": "application/vnd.haltsql.bundle.v1+json", "digest": ..., "size": ...,
          "annotations": { "org.opencontainers.image.title": "prod.haltsqlbundle" } },
        { "mediaType": "application/vnd.haltsql.bundle.signature.v1+json", ...,
          "annotations": { "org.opencontainers.image.title": "prod.haltsqlbundle.sig" } } ],
      "annotations": { "dev.haltsql.bundle.name": ..., "dev.haltsql.bundle.version": ...,
                       "dev.haltsql.bundle.digest": ... } }
    v}

    Reading accepts the artifact type either in [artifactType] or (older oras) as the
    config media type, requires exactly one bundle layer and one signature layer and
    refuses any other layer, image indexes and Docker manifests. Pushing is deterministic:
    the same bundle and signature always give the same manifest digest (there is no
    timestamp annotation). *)

val artifact_type : string
(** ["application/vnd.haltsql.bundle.v1"] *)

val bundle_media_type : string
(** ["application/vnd.haltsql.bundle.v1+json"] *)

val signature_media_type : string
(** ["application/vnd.haltsql.bundle.signature.v1+json"] *)

val manifest_media_type : string
(** ["application/vnd.oci.image.manifest.v1+json"] *)

val empty_config_media_type : string
(** ["application/vnd.oci.empty.v1+json"]; its content is the 2 bytes [{}] *)

type descriptor = {
  media_type : string;
  digest : string;
  size : int;
  title : string option;  (** [org.opencontainers.image.title] *)
}

type layout = { bundle_layer : descriptor; signature_layer : descriptor }

val parse_manifest :
  ?max_bundle_bytes:int -> content_type:string option -> string -> (layout, string) result
(** Checks the manifest structure and descriptor sizes (bundle at most [max_bundle_bytes],
    default {!Haltsql_bundle.default_max_bytes}; signature at most
    {!Haltsql_bundle.max_signature_bytes}) before anything is downloaded. *)

val build_manifest :
  ?title:string ->
  ?annotations:(string * string) list ->
  bundle:string ->
  signature:string ->
  unit ->
  string
(** The manifest bytes for a bundle and its signature file. [title] (default
    ["bundle.haltsqlbundle"]) names the bundle layer; the signature layer is
    [title ^ ".sig"]. A title that is not a plain file name ([A-Za-z0-9._-], at most 128
    characters) is replaced by the default. *)

val annotations_of_bundle : Haltsql_bundle.t -> (string * string) list
(** [dev.haltsql.bundle.name], [.version] and [.digest]. *)

type pulled = {
  manifest_digest : string;  (** verified *)
  bundle : string;  (** verified against its layer digest and size *)
  signature : string;  (** likewise; the bundle signature itself is NOT checked here *)
  bundle_title : string option;
}

val pull :
  ?max_bundle_bytes:int ->
  ?reference:string ->
  Registry.t ->
  (pulled, Fetch_error.t) result Lwt.t
(** Resolves the manifest ([reference] defaults to {!Oci_ref.reference}), checks the
    layout, and downloads and verifies both layers. *)

val push :
  ?title:string ->
  ?annotations:(string * string) list ->
  Registry.t ->
  bundle:string ->
  signature:string ->
  (string, Fetch_error.t) result Lwt.t
(** Uploads the empty config, the bundle and the signature blobs, then the manifest under
    the reference's tag (or its digest when there is no tag; a pinned digest must then
    equal the manifest digest). Returns the manifest digest. *)
