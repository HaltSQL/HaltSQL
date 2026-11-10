(* Playground checks against live, shadow and draft policies. Owner: PR console/05-build.
   See docs/console/api.md. This stub registers no routes yet. *)

let routes : Router.route list = []

(** Background loop, started once at startup; must not return while the console runs (or
    return immediately when the feature has nothing to do in the background). *)
let start (_ : Ctx.t) : unit Lwt.t = Lwt.return_unit
