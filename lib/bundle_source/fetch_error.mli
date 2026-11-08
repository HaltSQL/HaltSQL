(** Why fetching from a remote source failed. Messages never contain credentials, tokens
    or response bodies. *)

type t =
  | Unavailable of string  (** connection failure, timeout, HTTP 429 or 5xx *)
  | Denied of string  (** HTTP 401/403 after authenticating (or with no credentials) *)
  | Not_found of string  (** HTTP 404: no such object, tag or blob *)
  | Integrity of string
      (** digest or size mismatch, unexpected media type, malformed manifest *)
  | Protocol of string  (** any other unexpected response *)

val to_string : t -> string

val of_status : what:string -> int -> t
(** Classifies an unexpected HTTP status. *)
