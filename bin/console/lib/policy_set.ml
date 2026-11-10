(* See policy_set.mli. *)

let key : (string * Haltsql.Policy.t) list Ctx.Key.t = Ctx.Key.create "policies"
let get ctx = Option.value (Ctx.get ctx key) ~default:[]
let find ctx name = List.assoc_opt name (get ctx)
let set ctx v = Ctx.set ctx key v
