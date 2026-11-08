(** Google Cloud OAuth2 access tokens, cached and refreshed 60 s before expiry.

    - Metadata server: [GET /computeMetadata/v1/instance/service-accounts/default/token]
      with [Metadata-Flavor: Google] on [http://metadata.google.internal] (or
      [GCE_METADATA_HOST]); the response must carry [Metadata-Flavor: Google].
    - Service-account key file: a JWT ([RS256], signed with the key's RSA private key via
      mirage-crypto-pk) exchanged at the key's [token_uri] with the
      [urn:ietf:params:oauth:grant-type:jwt-bearer] grant. [token_uri] must be https (or
      loopback http, for tests).

    Errors never contain tokens or key material. *)

type t

val default_scope : string
(** [https://www.googleapis.com/auth/cloud-platform]. *)

val metadata :
  ?env:(string -> string option) -> ?now:(unit -> float) -> ?timeout:float -> unit -> t
(** Tokens from the GCE metadata server ([GCE_METADATA_HOST] or
    [metadata.google.internal]); responses must carry [Metadata-Flavor: Google]. *)

val service_account :
  ?now:(unit -> float) -> ?timeout:float -> ?scope:string -> string -> (t, string) result
(** From the JSON text of a service-account key. *)

val service_account_file :
  ?now:(unit -> float) -> ?timeout:float -> ?scope:string -> string -> (t, string) result
(** {!service_account} from a key file of at most 64 KiB. *)

val default :
  ?env:(string -> string option) ->
  ?now:(unit -> float) ->
  ?timeout:float ->
  unit ->
  (t, string) result
(** [GOOGLE_APPLICATION_CREDENTIALS] when set, else the metadata server. *)

val token : t -> (string, string) result Lwt.t
(** A cached access token, refreshed (once, under a lock) within 60 s of its expiry.
    Errors never contain tokens or key material. *)

val invalidate : t -> unit
(** Drops the cached token (e.g. after a 401). *)

val jwt_assertion :
  key:Mirage_crypto_pk.Rsa.priv ->
  key_id:string option ->
  email:string ->
  scope:string ->
  aud:string ->
  now:float ->
  string
(** The signed JWT bearer assertion (exposed for tests). *)
