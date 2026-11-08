(** OCI artifact references: [registry[:port]/repository(:tag|@digest|:tag@digest)].

    The rules match the [bundle_source.oci] config key (see docs/config-reference.md): the
    registry host is mandatory (there is no implicit Docker Hub), so the first component
    must contain a [.] or a [:] or be [localhost]. Repository components are lower-case
    letters, digits, [.], [_] and [-]. A digest is [sha256:<64 hex>] or [sha512:<128 hex>]
    (lower case). *)

type t = {
  registry : string;  (** [host[:port]] as written, e.g. [ghcr.io] or [127.0.0.1:5000] *)
  host : string;  (** lower-cased host without port or brackets *)
  repository : string;
  tag : string option;
  digest : string option;
}

val parse : string -> (t, string) result

val of_config : Haltsql_load.Config.oci_source -> (t, string) result
(** Re-parses [oci_reference] (defence in depth) and checks it agrees with the decoded
    fields. *)

val to_string : t -> string

val reference : t -> string
(** What to ask the registry for: the digest when pinned (a digest wins over a tag), else
    the tag. *)

val is_loopback : t -> bool
(** {!Haltsql_core.Loopback.is_host} of the registry host: [localhost], a literal
    127.0.0.0/8 IPv4 address or [::1]. *)

val base_url : plain_http:bool -> t -> (string, string) result
(** [https://registry], or [http://registry] when [plain_http] (refused unless
    {!is_loopback}). *)

val valid_digest : string -> bool
val valid_tag : string -> bool
