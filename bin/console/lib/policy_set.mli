(** The compiled policies the console has loaded, by name.

    Written only by {!Policies} (on every successful reload); read by Data, Records,
    Evidence, Signals and the rest. It lives in its own module rather than in Policies
    because Policies itself reads Data's classification ([Data.columns_doc]), and Data
    needs the policies: a key private to either module would make the two depend on each
    other. *)

val get : Ctx.t -> (string * Haltsql.Policy.t) list
(** The loaded policies; [[]] before the first successful load. *)

val find : Ctx.t -> string -> Haltsql.Policy.t option
(** [List.assoc_opt name (get ctx)]. *)

val set : Ctx.t -> (string * Haltsql.Policy.t) list -> unit
(** Replaces the loaded set. Only {!Policies} calls this. *)
