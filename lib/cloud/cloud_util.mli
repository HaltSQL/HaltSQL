(** Internal helpers shared by the cloud modules. *)

val xml_tag : string -> string -> string option
(** [xml_tag body name]: text of the first [<name>...</name>] element (no entity decoding
    beyond the five predefined XML entities). *)

val parse_rfc3339 : string -> float option
(** [2024-01-02T03:04:05Z] (fractional seconds and offsets accepted) to Unix time. *)

val rfc3339 : float -> string
(** [YYYY-MM-DDTHH:MM:SSZ] (UTC). *)

val json_string_field : Yojson.Safe.t -> string -> string option
(** String member of a JSON object. *)

val scalar_to_string : Yojson.Safe.t -> string option
(** Strings as is; ints, floats and bools in their JSON spelling; [None] otherwise. *)

val json_key : what:string -> key:string -> string -> (string, string) result
(** Parses a secret value as a JSON object and returns the scalar under [key]. The error
    never contains the secret value. *)

val read_file : ?limit:int -> string -> (string, string) result
(** Whole file (default limit 1 MiB). *)

val crc32c : string -> int32
(** CRC-32C (Castagnoli), as used by Google Cloud integrity checks. *)

val base64 : string -> string
val base64url_nopad : string -> string
val base64_decode : string -> (string, string) result
