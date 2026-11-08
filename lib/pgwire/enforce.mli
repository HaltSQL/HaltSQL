(** Pure enforcement decisions for the proxy: what to do with a simple Query, a Parse and
    a Bind, given the session's policy and context. No I/O. *)

open Haltsql

type deny = {
  sqlstate : string;
  message : string;
  detail : string option;
  hint : string option;
  codes : string list;  (** HaltSQL reason codes, e.g. [["E_TABLE_DENIED"]] *)
}

val deny_fields : deny -> (char * string) list
(** ErrorResponse fields: [S]/[V] = ERROR, [C], [M], optional [D] and [H]. *)

val of_verdict : sqlstate:string -> Verdict.t -> deny
(** Denial for a verdict with [allowed = false]. [D] lists the reason codes
    (["HaltSQL reasons: E_A, E_B"]). *)

val transaction_control : string -> bool
(** [true] iff the statement is exactly plain transaction control:
    [BEGIN]/[START TRANSACTION] with optional isolation level / READ ONLY|WRITE / [NOT]
    DEFERRABLE modes, or [COMMIT]/[END]/[ROLLBACK]/[ABORT] with optional WORK/TRANSACTION
    (case-insensitive, optional trailing semicolon). Comments, quotes, savepoints,
    [AND CHAIN] and anything else return [false]. *)

val simple :
  sqlstate:string ->
  ?allow_tx:bool ->
  Proxy_config.binding ->
  string ->
  Verdict.t * (unit, deny) result
(** Simple Query protocol. With [allow_tx] (default false), {!transaction_control}
    statements are allowed without consulting the policy. Denied if the verdict denies, or
    if it needs bound tenancy parameters (they cannot be bound in the simple protocol). *)

val parse :
  sqlstate:string ->
  ?allow_tx:bool ->
  Proxy_config.binding ->
  string ->
  Verdict.t * (unit, deny) result
(** Extended protocol Parse: denied iff the verdict denies ([allow_tx] as in {!simple}).
*)

val context_text : Context.value -> string
(** Text-format parameter value: [One v] is [v]; [Many vs] is a PostgreSQL array literal
    with every element double-quoted and escaped, e.g. [{"a","b\"c"}]. *)

val bind : sqlstate:string -> Verdict.t -> Wire.bind -> (Wire.bind, deny) result
(** Enforces bound tenancy: every [$n] in [verdict.bind_params] is overwritten with the
    session's context value (text format), whatever the client sent. Fails if a tenancy
    parameter is missing from the Bind or uses binary format. *)

val reset_tenancy_param_types : Verdict.t -> Wire.parse -> Wire.parse
(** Clears (sets to [0], "unspecified") the client-declared Parse type of every tenancy
    parameter in [verdict.bind_params], so PostgreSQL infers it from the tenant predicate
    instead of decoding the injected context value as a client-chosen type (e.g. [float8]
    would round 64-bit IDs; [name] or ["char"] would truncate them). Other parameters'
    declared types are kept. Returns [p] physically unchanged when nothing needs clearing.
*)

val local_deny : sqlstate:string -> ?hint:string -> code:string -> string -> deny
(** A denial raised by the proxy itself (e.g. unknown statement, binary tenancy param).
    [code] is a pseudo reason code recorded in [D] and in the audit log. *)
