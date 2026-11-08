(** AWS credential providers with caching and refresh before expiry.

    Sources:
    - [Env]: [AWS_ACCESS_KEY_ID], [AWS_SECRET_ACCESS_KEY], optional [AWS_SESSION_TOKEN];
    - [Static]: fixed keys (from the config);
    - [Web_identity]: [AWS_WEB_IDENTITY_TOKEN_FILE] + [AWS_ROLE_ARN] (+ optional
      [AWS_ROLE_SESSION_NAME]) exchanged through STS [AssumeRoleWithWebIdentity] (POST,
      form-encoded, so the token never appears in a URL). The STS endpoint is
      [AWS_ENDPOINT_URL_STS] when set, else [https://sts.<region>.amazonaws.com];
    - [Container]: ECS / EKS Pod Identity container credentials via
      [AWS_CONTAINER_CREDENTIALS_RELATIVE_URI] or [AWS_CONTAINER_CREDENTIALS_FULL_URI],
      with optional [AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE] or
      [AWS_CONTAINER_AUTHORIZATION_TOKEN];
    - [Instance]: EC2 IMDSv2 (session token via [PUT /latest/api/token], then the role's
      credentials). The endpoint is [AWS_EC2_METADATA_SERVICE_ENDPOINT] when set, else
      [http://169.254.169.254]; [AWS_EC2_METADATA_DISABLED=true] disables it;
    - [Chain]: the first source that yields credentials.

    Temporary credentials are cached and refreshed [refresh_margin] seconds (default 300)
    before they expire; if a refresh fails while the cached credentials are still valid,
    those are used. Concurrent callers share a single refresh. Error strings never contain
    key material or tokens. *)

type source =
  | Env
  | Static of Sigv4.credentials
  | Web_identity
  | Container
  | Instance
  | Chain of source list

val default_chain : source
(** [Chain [Env; Web_identity; Container; Instance]]. *)

val source_of_s3 : Haltsql_load.Config.s3_credentials -> source
(** [S3_env] maps to [Env], [S3_static] to [Static], etc. *)

type t

val create :
  ?env:(string -> string option) ->
  ?now:(unit -> float) ->
  ?refresh_margin:float ->
  ?timeout:float ->
  ?region:string ->
  source ->
  t
(** [region] selects the regional STS endpoint (default: [AWS_REGION], else [us-east-1]).
    [timeout] bounds each HTTP call (default 5 s). *)

val get : t -> (Sigv4.credentials, string) result Lwt.t

val invalidate : t -> unit
(** Forgets cached credentials (e.g. after an [ExpiredToken] response). *)

val fetch_count : t -> int
(** Number of successful fetches from the underlying source (for tests and metrics). *)
