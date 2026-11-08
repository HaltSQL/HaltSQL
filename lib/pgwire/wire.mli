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
(** Appends the low 32 bits of the integer, big-endian. *)

val add_int16 : Buffer.t -> int -> unit
(** Appends the low 16 bits of the integer, big-endian. *)

val add_cstring : Buffer.t -> string -> unit
(** Appends the string and a NUL terminator. Raises {!Malformed} if the string contains a
    NUL byte (it could not be decoded back). *)

type cursor

val cursor : string -> cursor
(** A read cursor at the start of a payload. Every [get_*] below raises {!Malformed}
    instead of reading past the end. *)

val get_int32 : cursor -> int
(** Signed 32-bit. *)

val get_int16 : cursor -> int
(** Signed 16-bit. *)

val get_cstring : cursor -> string
(** Bytes up to the next NUL (consumed, not returned). *)

val get_bytes : cursor -> int -> string
(** [get_bytes c n] is the next [n] bytes; a negative [n] or a truncated payload raises
    {!Malformed} before anything is allocated. *)

val get_rest : cursor -> string
(** All remaining bytes. *)

val at_end : cursor -> bool
(** [true] when every byte was consumed. *)

val expect_end : cursor -> unit
(** Raises {!Malformed} if bytes remain (strict decoding). *)

(** {1 Startup phase (untagged packets)} *)

val ssl_request_code : int
(** 80877103, the SSLRequest code. *)

val gssenc_request_code : int
(** 80877104, the GSSENCRequest code (always refused by the proxy). *)

val cancel_request_code : int
(** 80877102, the CancelRequest code. *)

val protocol_3_0 : int
(** 196608, protocol version 3.0 as sent in the startup packet. *)

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
(** Full CancelRequest packet (with length). *)

val encode_ssl_request : string
(** Full SSLRequest packet (with length). *)

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
(** SQL text of a Query (['Q']) payload. *)

val decode_parse : string -> parse
(** Parse (['P']) payload; a negative parameter-type count raises {!Malformed}. *)

val encode_parse : parse -> string
(** Framed ['P'] message. *)

val decode_bind : string -> bind
(** Bind (['B']) payload. Format codes other than 0/1, negative counts, parameter lengths
    below -1 and an inconsistent format-code count raise {!Malformed}. *)

val encode_bind : bind -> string
(** Framed ['B'] message. *)

val param_format : bind -> int -> int
(** [param_format b i] is the format code (0 text, 1 binary) of 0-based parameter [i],
    following the protocol's 0 / 1 / n format-code rule. Raises {!Malformed} if the
    format-code count is neither 0, 1 nor the parameter count. *)

val decode_describe_or_close : string -> char * string
(** [('S' | 'P', name)]. *)

val decode_execute : string -> string * int
(** [(portal, max_rows)] of an Execute (['E']) payload. *)

val decode_sasl_initial : string -> string * string option
(** [(mechanism, initial response)]; a length of -1 means no initial response. *)

(** {1 Backend messages} *)

val auth_ok : string
(** Framed AuthenticationOk. *)

val auth_sasl : string list -> string
(** Framed AuthenticationSASL advertising the mechanisms. *)

val auth_sasl_continue : string -> string
(** Framed AuthenticationSASLContinue carrying server data. *)

val auth_sasl_final : string -> string
(** Framed AuthenticationSASLFinal carrying server data. *)

val backend_key_data : pid:int -> key:int -> string
(** Framed BackendKeyData (cancellation key). *)

val ready_for_query : char -> string
(** Framed ReadyForQuery with the transaction status (['I'], ['T'] or ['E']). *)

val parameter_status : string -> string -> string
(** Framed ParameterStatus [name value]. *)

val negotiate_protocol_version : minor:int -> string list -> string
(** Framed NegotiateProtocolVersion: the newest supported minor version and the
    unrecognised [_pq_.] options. *)

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
(** Authentication (['R']) payload from the upstream server. *)

val sasl_initial_response : mechanism:string -> string -> string
(** Framed ['p'] SASLInitialResponse. *)

val sasl_response : string -> string
(** Framed ['p'] SASLResponse. *)

val password_message : string -> string
(** Framed ['p'] PasswordMessage (NUL-terminated). *)
