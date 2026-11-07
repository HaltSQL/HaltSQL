(** Strict unpadded base64url (RFC 4648 section 5), as used by JOSE (RFC 7515). *)

val encode : string -> string
(** [encode s] is the unpadded base64url encoding of [s]. *)

val decode : string -> (string, string) result
(** [decode s] decodes unpadded base64url. It rejects padding ([=]), characters outside
    the base64url alphabet, impossible lengths ([length mod 4 = 1]) and non-canonical
    trailing bits, so every byte string has exactly one accepted encoding. *)
