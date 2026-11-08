(** W3C Trace Context [traceparent] header (https://www.w3.org/TR/trace-context/).

    [00-<32 hex trace-id>-<16 hex parent-id>-<2 hex flags>]. Parsing follows the spec:
    lower-case hex only, all-zero ids and version [ff] are invalid, and versions above
    [00] may carry extra [-]-separated fields, which are ignored. *)

type t = {
  trace_id : string;  (** 32 lower-case hex characters, not all zeros *)
  parent_id : string;  (** 16 lower-case hex characters, not all zeros *)
  flags : int;  (** trace-flags byte; bit 0 is "sampled" *)
}

val parse : string -> t option
(** [None] for any malformed header (the caller then starts a new trace). Surrounding
    spaces and tabs are ignored. *)

val to_string : t -> string
(** Always version [00]. *)

val sampled : t -> bool
(** The sampled bit of the trace flags. *)

val is_hex_id : len:int -> string -> bool
(** [len] lower-case hex characters, not all zeros. *)
