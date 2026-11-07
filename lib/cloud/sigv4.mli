(** AWS Signature Version 4 (header-based request signing).

    Implements the canonical request / string-to-sign / signing-key derivation of
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html.
    Pure: time is passed explicitly. *)

type credentials = {
  access_key_id : string;
  secret_access_key : string;
  session_token : string option;
}

val sha256_hex : string -> string

val hmac_sha256 : key:string -> string -> string
(** Raw (binary) HMAC-SHA256. *)

val amz_date : float -> string
(** [YYYYMMDDTHHMMSSZ] (UTC). *)

val canonical_uri : s3:bool -> string -> string
(** From the on-the-wire (percent-encoded) path. S3 decodes it and percent-encodes it
    exactly once (every byte outside [A-Za-z0-9-_.~] and ['/']), so the result does not
    depend on how the path was spelled on the wire (e.g. ["="] vs ["%3D"]); other services
    percent-encode each segment once more, as the spec requires. ["" -> "/"]. *)

val canonical_query : (string * string) list -> string
(** Decoded pairs, strictly encoded, sorted by key then value. *)

val canonical_headers : (string * string) list -> string * string
(** [(canonical_headers_block, signed_headers)]: names lower-cased, values trimmed with
    inner whitespace runs collapsed, sorted, duplicates joined with [","]. *)

val canonical_request :
  meth:string ->
  canonical_uri:string ->
  query:(string * string) list ->
  headers:(string * string) list ->
  payload_hash:string ->
  string * string
(** [(canonical_request, signed_headers)]; every header given is signed. *)

val credential_scope : date:string -> region:string -> service:string -> string
val string_to_sign : amz_date:string -> scope:string -> canonical_request:string -> string

val signing_key :
  secret:string -> date:string -> region:string -> service:string -> string
(** Raw (binary) derived key. *)

val signature : signing_key:string -> string -> string
(** Lower-case hex HMAC of the string to sign. *)

val sign :
  ?s3:bool ->
  credentials ->
  service:string ->
  region:string ->
  time:float ->
  meth:string ->
  uri:Uri.t ->
  headers:(string * string) list ->
  payload:string ->
  (string * string) list
(** Returns [headers] plus [host], [x-amz-date], [x-amz-content-sha256] (S3 only),
    [x-amz-security-token] (session credentials) and [authorization]. All returned headers
    except [authorization] are signed. *)

type authorization = {
  credential : string;  (** [AKID/date/region/service/aws4_request] *)
  signed_headers : string list;
  signature_hex : string;
}

val parse_authorization : string -> authorization option
(** Parses an [AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...] value
    (used by verifiers and test fakes). *)
