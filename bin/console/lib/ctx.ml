(* The shared runtime context every handler and background loop receives.

   Feature-owned state lives in the mutable fields below so features do not need to
   change this record: each owns exactly one field and is the only writer. *)

type principal = {
  id : string;  (** stable user or token id, e.g. an email *)
  name : string;
  auth : string;  (** "oidc:<provider>", "proxy:<label>", "token:<name>", "dev" *)
  groups : string list;
  role : Rbac.role;
}

type t = {
  config : Console_config.t;
  store : Store.t;
  index : Index.t;
  started : float;
  mutable fleet : Yojson.Safe.t option;
      (** last fleet snapshot ([GET /api/v1/fleet] shape), written by [Fleet] *)
  mutable policies : (string * Haltsql.Policy.t) list;
      (** loaded policies by name, written by [Policies] *)
  mutable catalog_columns : Yojson.Safe.t option;
      (** merged catalog tags ([GET /api/v1/data/columns] shape), written by [Data] *)
  mutable ingest_status : Yojson.Safe.t;
      (** per-source ingestion state, written by [Ingest] *)
  mutable chain_status : Yojson.Safe.t;
      (** last audit-chain verification, written by [Records] *)
}

let create ~config ~store ~index =
  {
    config;
    store;
    index;
    started = Unix.gettimeofday ();
    fleet = None;
    policies = [];
    catalog_columns = None;
    ingest_status = `List [];
    chain_status = `Null;
  }

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
    "with a reason" (and [None] for a plain yes). *)
let require ?body (p : principal) req perm =
  match Rbac.grant p.role perm with
  | Rbac.Yes -> None
  | Rbac.No ->
      Api.forbidden "role %s lacks permission %s" (Rbac.role_to_string p.role)
        (Rbac.permission_id perm)
  | Rbac.With_reason -> (
      match reason_of ?body req with
      | Some r -> Some r
      | None ->
          Api.fail `Forbidden "REASON_REQUIRED"
            "%s needs a reason (x-haltsql-reason header or reason field)"
            (Rbac.permission_id perm))
