(* The shared runtime context every handler and background loop receives.

   [Ctx.t] holds only what every feature shares (config, store, index, start time). It
   has no per-feature fields: feature state lives in a typed registry. Each feature
   declares its own key privately and exposes read accessors, e.g. in fleet.ml

     let state : Fleet_state.t Ctx.Key.t = Ctx.Key.create "fleet"
     let snapshot ctx = Ctx.get ctx state

   Because the key is not exported, only the owning module can [Ctx.set] its state:
   ownership is enforced by module scope, and adding a feature never edits this file. *)

type principal = {
  id : string;  (** stable user or token id, e.g. an email *)
  name : string;
  auth : string;  (** "oidc:<provider>", "proxy:<label>", "token:<name>", "dev" *)
  groups : string list;
  roles : Rbac.role list;
      (** every role the principal's groups map to (non-empty); permissions are the union
          of these roles' grants *)
  role : Rbac.role;  (** the primary role for display: the highest-precedence of [roles] *)
}

(* The per-feature state registry: a heterogeneous table keyed by typed keys, built on
   [Type.Id]. The table is abstract, so the only way to read or write an entry is to
   hold its key. *)
module Registry : sig
  type t

  module Key : sig
    type 'a t

    val create : string -> 'a t
    (** A fresh key. Two keys never alias, even with the same name (the name is for
        debugging only). *)

    val name : 'a t -> string
  end

  val create : unit -> t
  val get : t -> 'a Key.t -> 'a option
  val set : t -> 'a Key.t -> 'a -> unit
end = struct
  module Key = struct
    type 'a t = { name : string; id : 'a Type.Id.t }

    let create name = { name; id = Type.Id.make () }
    let name k = k.name
  end

  type binding = B : 'a Type.Id.t * 'a -> binding
  type t = (int, binding) Hashtbl.t

  let create () = Hashtbl.create 16

  let get (type a) (t : t) (key : a Key.t) : a option =
    match Hashtbl.find_opt t (Type.Id.uid key.id) with
    | None -> None
    | Some (B (id', v)) -> (
        match Type.Id.provably_equal key.id id' with
        | Some Type.Equal -> Some v
        | None -> None)

  let set (t : t) (key : 'a Key.t) v =
    Hashtbl.replace t (Type.Id.uid key.id) (B (key.id, v))
end

module Key = Registry.Key

type t = {
  config : Console_config.t;
  store : Store.t;
  index : Index.t;
  started : float;
  state : Registry.t;  (** per-feature state; read and written only through a [Key.t] *)
}

let create ~config ~store ~index =
  { config; store; index; started = Unix.gettimeofday (); state = Registry.create () }

(** The state stored under [key], or [None] before its owner first sets it. *)
let get (t : t) key = Registry.get t.state key

(** Replaces the state stored under [key]. *)
let set (t : t) key v = Registry.set t.state key v

let now () = Unix.gettimeofday ()

(* ---- permission checks ---- *)

(** The reason from the [x-haltsql-reason] header or the body's [reason] field. *)
let reason_of ?body (req : Cohttp.Request.t) =
  let from_body =
    match body with
    | Some b -> (
        match Api.member "reason" b with
        | Some (`String s) when String.trim s <> "" -> Some s
        | _ -> None)
    | None -> None
  in
  match from_body with
  | Some _ as r -> r
  | None -> (
      match Cohttp.Header.get (Cohttp.Request.headers req) "x-haltsql-reason" with
      | Some s when String.trim s <> "" -> Some s
      | _ -> None)

(** Raises [Api.Error] unless [p] may use [perm]; returns the reason when the grant is
    "with a reason" (and [None] for a plain yes). The grant is the union over all of
    [p.roles] ([Rbac.grant_union]), not just the display role. *)
let require ?body (p : principal) req perm =
  match Rbac.grant_union p.roles perm with
  | Rbac.Yes -> None
  | Rbac.No ->
      Api.forbidden "role %s lacks permission %s"
        (String.concat "+" (List.map Rbac.role_to_string p.roles))
        (Rbac.permission_id perm)
  | Rbac.With_reason -> (
      match reason_of ?body req with
      | Some r -> Some r
      | None ->
          Api.fail `Forbidden "REASON_REQUIRED"
            "%s needs a reason (x-haltsql-reason header or reason field)"
            (Rbac.permission_id perm))
