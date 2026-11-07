(** PostgreSQL frontend/backend protocol v3 message codecs (pure, no I/O).

    Every decoder is strict: it consumes the whole payload and raises {!Malformed} on any
    truncation, missing NUL terminator, negative length or trailing bytes. The proxy
    treats {!Malformed} as a protocol violation and closes the connection (fail closed).
*)

exception Malformed of string

(** {1 Framing} *)

val frame : char -> string -> string
(** [frame tag payload] is [tag] followed by the big-endian int32 length (payload + 4) and
    the payload. *)

val frame_untagged : string -> string
(** Length-prefixed body without a tag (startup-phase packets). *)

(** {1 Payload builder and cursor} *)

val add_int32 : Buffer.t -> int -> unit
val add_int16 : Buffer.t -> int -> unit
val add_cstring : Buffer.t -> string -> unit

type cursor

val cursor : string -> cursor

val get_int32 : cursor -> int
(** Signed 32-bit. *)

val get_int16 : cursor -> int
(** Signed 16-bit. *)

val get_cstring : cursor -> string
val get_bytes : cursor -> int -> string
val get_rest : cursor -> string
val at_end : cursor -> bool
val expect_end : cursor -> unit

(** {1 Startup phase (untagged packets)} *)

val ssl_request_code : int
val gssenc_request_code : int
val cancel_request_code : int
val protocol_3_0 : int

type startup =
  | Ssl_request
  | Gssenc_request
  | Cancel_request of { pid : int; key : int }
  | Startup of { major : int; minor : int; params : (string * string) list }

val decode_startup : string -> startup
(** [decode_startup body] where [body] excludes the 4-byte length. Unknown request codes
    and protocol majors other than 3 raise {!Malformed}. Duplicate parameter names raise.
*)

val encode_startup : (string * string) list -> string
(** Full packet (with length) for protocol 3.0. *)

val encode_cancel : pid:int -> key:int -> string
val encode_ssl_request : string

(** {1 Frontend messages} *)

type parse = { stmt : string; query : string; param_types : int list }

type bind = {
  portal : string;
  bstmt : string;
  param_formats : int list;
  params : string option list;  (** [None] is SQL NULL *)
  result_formats : int list;
}

val decode_query : string -> string
val decode_parse : string -> parse

val encode_parse : parse -> string
(** Framed ['P'] message. *)

val decode_bind : string -> bind

val encode_bind : bind -> string
(** Framed ['B'] message. *)

val param_format : bind -> int -> int
(** [param_format b i] is the format code (0 text, 1 binary) of 0-based parameter [i],
    following the protocol's 0 / 1 / n format-code rule. Raises {!Malformed} if the
    format-code count is neither 0, 1 nor the parameter count. *)

val decode_describe_or_close : string -> char * string
(** [('S' | 'P', name)]. *)

val decode_execute : string -> string * int

val decode_sasl_initial : string -> string * string option
(** [(mechanism, initial response)]; a length of -1 means no initial response. *)

(** {1 Backend messages} *)

val auth_ok : string
val auth_sasl : string list -> string
val auth_sasl_continue : string -> string
val auth_sasl_final : string -> string
val backend_key_data : pid:int -> key:int -> string
val ready_for_query : char -> string
val parameter_status : string -> string -> string
val negotiate_protocol_version : minor:int -> string list -> string

val error_response : (char * string) list -> string
(** Framed ['E'] message from fields such as [('S', "ERROR"); ('C', "42501")]. *)

val decode_fields : string -> (char * string) list
(** Fields of an ErrorResponse/NoticeResponse payload. *)

type auth_request =
  | Auth_ok
  | Auth_cleartext
  | Auth_md5 of string  (** 4-byte salt *)
  | Auth_sasl of string list
  | Auth_sasl_continue of string
  | Auth_sasl_final of string
  | Auth_other of int

val decode_auth : string -> auth_request

val sasl_initial_response : mechanism:string -> string -> string
(** Framed ['p'] SASLInitialResponse. *)

val sasl_response : string -> string
(** Framed ['p'] SASLResponse. *)

val password_message : string -> string
(** Framed ['p'] PasswordMessage (NUL-terminated). *)
