(* Per-call analysis accumulator; see env.mli. *)

open Haltsql_core

type binding = {
  b_param : int;
  b_value : Context.value;
  b_loc : int;
  b_ploc : int;  (** location of the [$n] node that the proof uses *)
}

type t = {
  policy : Policy.t;
  ctx : Context.t;
  mutable reasons : Reason.t list;  (** reversed emission order *)
  mutable tables : string list;
  mutable columns : string list;
  mutable params : (int * int) list;  (** every [$n] seen: [(n, loc)] *)
  mutable bindings : binding list;  (** bound-mode tenant proofs *)
  mutable joins : int;
  mutable next_id : int;
  mutable missing_keys : string list;  (** tenancy keys already reported *)
}

let create policy ctx =
  {
    policy;
    ctx;
    reasons = [];
    tables = [];
    columns = [];
    params = [];
    bindings = [];
    joins = 0;
    next_id = 0;
    missing_keys = [];
  }

let emit env ?loc ?hint ~rule code message =
  env.reasons <- Reason.make ?loc ?hint ~rule code message :: env.reasons

let add_table env s = env.tables <- s :: env.tables
let add_column env s = env.columns <- s :: env.columns
let add_param env n loc = env.params <- (n, loc) :: env.params

let add_binding env n v ~ploc loc =
  env.bindings <- { b_param = n; b_value = v; b_loc = loc; b_ploc = ploc } :: env.bindings

let add_joins env n = env.joins <- env.joins + n

let fresh_id env =
  let id = env.next_id in
  env.next_id <- id + 1;
  id
