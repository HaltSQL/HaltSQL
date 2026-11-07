(* Prepared-statement bookkeeping; see stmt_state.mli. *)

type op_kind =
  | Op_parse of string * Haltsql.Verdict.t
  | Op_close_stmt of string
  | Op_close_portal

type op = { seg : int; kind : op_kind }
type seg = { id : int; mutable deny : (string * (char * string) list) option }

type t = {
  committed : (string, Haltsql.Verdict.t) Hashtbl.t;
  ops : op Queue.t;
  segs : seg Queue.t;
  mutable open_seg : seg option;
  mutable next_id : int;
  max_pending : int;
}

exception Overflow

type lookup = Found of Haltsql.Verdict.t | Missing | Wait

let create ?(max_pending = 10_000) () =
  {
    committed = Hashtbl.create 16;
    ops = Queue.create ();
    segs = Queue.create ();
    open_seg = None;
    next_id = 0;
    max_pending;
  }

let touch t =
  match t.open_seg with
  | Some _ -> ()
  | None ->
      if Queue.length t.segs >= t.max_pending then raise Overflow;
      let s = { id = t.next_id; deny = None } in
      t.next_id <- t.next_id + 1;
      Queue.push s t.segs;
      t.open_seg <- Some s

let current t =
  touch t;
  match t.open_seg with Some s -> s | None -> assert false

let names = function
  | Op_parse (n, _) | Op_close_stmt n -> Some n
  | Op_close_portal -> None

let lookup t name =
  let cur = match t.open_seg with Some s -> s.id | None -> -1 in
  let in_current = ref None and earlier = ref false in
  Queue.iter
    (fun op ->
      if names op.kind = Some name then
        if op.seg = cur then in_current := Some op.kind else earlier := true)
    t.ops;
  match !in_current with
  | Some (Op_parse (_, v)) -> Found v
  | Some _ -> Missing
  | None -> (
      if !earlier then Wait
      else
        match Hashtbl.find_opt t.committed name with Some v -> Found v | None -> Missing)

let push t kind =
  let s = current t in
  if Queue.length t.ops >= t.max_pending then raise Overflow;
  Queue.push { seg = s.id; kind } t.ops

let note_parse t name v =
  if name = "" then Hashtbl.remove t.committed "";
  push t (Op_parse (name, v))

let note_close_statement t name =
  (* Removing early is safe: a missing entry can only cause a denial. *)
  Hashtbl.remove t.committed name;
  push t (Op_close_stmt name)

let note_close_portal t = push t Op_close_portal
let drop_unnamed t = Hashtbl.remove t.committed ""
let set_deny t ~token fields = (current t).deny <- Some (token, fields)

let end_segment t =
  touch t;
  t.open_seg <- None

let in_flight t = Queue.length t.segs
let head_id t = match Queue.peek_opt t.segs with Some s -> Some s.id | None -> None

let pop_op t =
  match (Queue.peek_opt t.ops, head_id t) with
  | Some op, Some h when op.seg = h -> Some (Queue.pop t.ops)
  | _ -> None

let on_parse_complete t =
  match pop_op t with
  | Some { kind = Op_parse (name, v); _ } ->
      Hashtbl.replace t.committed name v;
      Ok ()
  | _ -> Error "unexpected ParseComplete from upstream"

let on_close_complete t =
  match pop_op t with
  | Some { kind = Op_close_stmt name; _ } ->
      Hashtbl.remove t.committed name;
      Ok ()
  | Some { kind = Op_close_portal; _ } -> Ok ()
  | _ -> Error "unexpected CloseComplete from upstream"

let drop_head_ops t =
  match head_id t with
  | None -> ()
  | Some h ->
      let keep = Queue.create () in
      Queue.iter (fun op -> if op.seg <> h then Queue.push op keep) t.ops;
      Queue.clear t.ops;
      Queue.transfer keep t.ops

let on_error t =
  drop_head_ops t;
  match Queue.peek_opt t.segs with
  | Some s ->
      let d = s.deny in
      s.deny <- None;
      d
  | None -> None

let on_ready t =
  drop_head_ops t;
  match Queue.take_opt t.segs with
  | Some s -> (
      match t.open_seg with Some o when o.id = s.id -> t.open_seg <- None | _ -> ())
  | None -> ()
