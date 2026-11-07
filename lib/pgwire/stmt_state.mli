(** Prepared-statement bookkeeping that stays consistent with the upstream server.

    The proxy must know the verdict of the statement a Bind refers to. Because clients
    pipeline, and the server silently ignores messages after an error until Sync, a Parse
    only takes effect upstream when the server answers ParseComplete. This module keeps:

    - a {e committed} map (statements the server confirmed),
    - an ordered queue of {e pending} Parse/Close operations, each tagged with the Sync
      segment it was sent in,
    - the queue of open segments (one per Sync / simple Query / FunctionCall sent), each
      possibly carrying a denial the proxy injected.

    Server responses are applied in order: ParseComplete commits the oldest pending Parse,
    CloseComplete applies the oldest pending Close, ErrorResponse discards the pending
    operations of the segment being processed, ReadyForQuery retires that segment.

    A Bind in the {e same} segment as a pending Parse may use the pending verdict (if the
    Parse fails, the server ignores the Bind too). A Bind whose statement has pending
    operations in an {e earlier} segment must wait ({!Wait}) until they are resolved.
    Missing entries always lead to denial, so staleness can only deny, never allow. *)

type t

val create : ?max_pending:int -> unit -> t
(** [max_pending] (default 10000) bounds queued operations and segments. *)

exception Overflow

type lookup = Found of Haltsql.Verdict.t | Missing | Wait

val lookup : t -> string -> lookup

(** {1 Client side (called as messages are forwarded)} *)

val note_parse : t -> string -> Haltsql.Verdict.t -> unit
(** Raises {!Overflow}. For the unnamed statement the committed entry is dropped at once
    (the server replaces it). *)

val note_close_statement : t -> string -> unit
val note_close_portal : t -> unit

val drop_unnamed : t -> unit
(** A simple Query destroys the unnamed statement. *)

val set_deny : t -> token:string -> (char * string) list -> unit
(** Attach an injected denial (sentinel token, error fields) to the open segment. *)

val end_segment : t -> unit
(** Sync, simple Query or FunctionCall was forwarded. Opens the segment first if needed.
*)

val touch : t -> unit
(** Opens a segment if none is open (any extended-protocol message). *)

val in_flight : t -> int
(** Segments awaiting ReadyForQuery. *)

(** {1 Server side (called as responses arrive)} *)

val on_parse_complete : t -> (unit, string) result
val on_close_complete : t -> (unit, string) result

val on_error : t -> (string * (char * string) list) option
(** Discards pending operations of the head segment and returns (and clears) its injected
    denial, if any. *)

val on_ready : t -> unit
