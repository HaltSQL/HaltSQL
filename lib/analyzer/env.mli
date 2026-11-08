(** Per-call analysis accumulator.

    [Analyzer.analyze] creates one {!t} for a single statement and discards it afterwards.
    It is never shared between calls or domains, so its mutable fields are local state of
    one call that is pure from the outside: the analyzer has no global mutable state and
    is safe to run on many domains at once.

    Rules never stop at the first problem: they {!emit} every violation they find and the
    walk continues, so a verdict lists all reasons. *)

open Haltsql_core

type binding = {
  b_param : int;  (** the [n] of [$n] *)
  b_value : Context.value;  (** value the caller must bind *)
  b_loc : int;  (** location reported if the bindings of [$n] conflict *)
  b_ploc : int;
      (** location of the [$n] node that the proof uses; any other occurrence of a tenant
          placeholder is denied (it could change the parameter's inferred type) *)
}
(** A bound-mode tenant proof: placeholder [$b_param] must be bound to [b_value]. *)

type t = {
  policy : Policy.t;
  ctx : Context.t;
  mutable reasons : Reason.t list;  (** newest first *)
  mutable tables : string list;  (** qualified relations touched (unsorted, duplicates) *)
  mutable columns : string list;
      (** ["schema.table.column"] read (unsorted, duplicates) *)
  mutable params : (int * int) list;  (** every [$n] seen: [(n, loc)], newest first *)
  mutable bindings : binding list;  (** bound-mode tenant proofs, newest first *)
  mutable joins : int;  (** joins counted so far, for the join budget *)
  mutable next_id : int;  (** see {!fresh_id} *)
  mutable missing_keys : string list;
      (** tenancy keys already reported as [E_CONTEXT_MISSING] (reported once each) *)
}

val create : Policy.t -> Context.t -> t
(** A fresh accumulator with nothing recorded. *)

val emit : t -> ?loc:int -> ?hint:string -> rule:string -> Reason.code -> string -> unit
(** [emit env ?loc ?hint ~rule code message] records a violation (see
    {!Haltsql_core.Reason.make}). *)

val add_table : t -> string -> unit
val add_column : t -> string -> unit

val add_param : t -> int -> int -> unit
(** [add_param env n loc] records an occurrence of [$n] at [loc]. *)

val add_binding : t -> int -> Context.value -> ploc:int -> int -> unit
(** [add_binding env n v ~ploc loc] records that [$n] (the node at [ploc]) proves a tenant
    predicate and must be bound to [v]; [loc] locates conflict reports. *)

val add_joins : t -> int -> unit

val fresh_id : t -> int
(** A new id, unique within this analysis; identifies one occurrence of a FROM item. *)
