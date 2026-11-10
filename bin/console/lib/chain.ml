(* Chain of custody: local verification of each verifier's audit hash chain over the
   records in the index ({!Haltsql_cloud.Audit_chain}), neighbours, and the command that
   re-verifies the original records independently.

   A verifier's records are walked in [seq] order and grouped into segments by following
   hash links: a record whose [prev_hash] is the last [hash] of an open segment continues
   that segment, so independent chains that share a verifier name (several hosts under
   one prefix, files with the same basename) are checked separately. A record that links
   to no open segment starts a new one when its [prev_hash] is the genesis hash (a new
   chain, e.g. a restart without a spool), when it is the first record read from its
   origin (file path, or object-sink host: its predecessor may have left the retention
   window), or when ingestion reported a gap right before it (rotation or truncation
   that skipped records; the segment is then flagged [gap], not broken). Otherwise the
   link is broken. Every record's own hash is checked. Records without a [hash] are not
   chained ("unknown").

   Index entries never change once added, so the check is incremental: each call catches
   up with the records added since the last one ({!Index.verifier_range}) and trims
   segments whose records were evicted; only an out-of-order arrival forces a full walk.
   [POST /records/{id}/verify-chain] re-walks the whole stream ({!reverify}), yielding to
   the event loop every [chunk] records; concurrent calls share one walk, and a walk is
   not repeated within [min_reverify_interval] seconds. The per-verifier state lives in
   the context ([state_key]), and verifiers that leave the index are dropped by
   {!check_all}. *)

open Lwt.Syntax
module Audit_chain = Haltsql_cloud.Audit_chain

type segment = {
  mutable origins : string list;
  first_seq : int;
  mutable trimmed_to : int;  (** lowest live seq, once older records were evicted *)
  mutable last_seq : int;
  mutable count : int;
  mutable break : (Index.entry * string) option;  (** the first record that fails *)
  gap : bool;  (** starts right after an ingestion gap *)
}

type result = {
  verifier : string;
  mutable version : int;
  mutable layout : int;
  mutable upto : int;  (** highest seq consumed *)
  mutable segments : segment list;  (** newest first *)
  tails : (string, segment) Hashtbl.t;  (** last hash of an open segment -> segment *)
  origins : (string, int * segment) Hashtbl.t;  (** origin -> (last seq, last segment) *)
  mutable checked_at : float;
  mutable full_at : float;  (** end of the last full walk *)
  mutable running : unit Lwt.t option;  (** a full walk in progress *)
}

let chunk = 10_000
let min_reverify_interval = 30.
let records r = List.fold_left (fun n s -> n + s.count) 0 r.segments

let state_of r =
  if List.exists (fun s -> s.break <> None) r.segments then "broken"
  else if records r = 0 then "unknown"
  else if List.exists (fun s -> s.gap) r.segments then "gap"
  else "intact"

(* The oldest break ([segments] is newest first). *)
let first_break r =
  List.fold_left
    (fun acc s -> match s.break with Some b -> Some b | None -> acc)
    None r.segments

let strip_line loc =
  match String.rindex_opt loc '#' with Some i -> String.sub loc 0 i | None -> loc

(** Where a record was written: the object-sink host for objects, else the path. *)
let origin_of (e : Index.entry) =
  let path = strip_line e.location in
  if String.starts_with ~prefix:"s3://" path || String.starts_with ~prefix:"gs://" path
  then
    match Ingest.host_of_object_name path with
    | Some h -> "host:" ^ h
    | None -> Filename.dirname path
  else path

let fresh verifier =
  {
    verifier;
    version = -1;
    layout = -1;
    upto = min_int;
    segments = [];
    tails = Hashtbl.create 8;
    origins = Hashtbl.create 8;
    checked_at = 0.;
    full_at = 0.;
    running = None;
  }

let clear r =
  r.version <- -1;
  r.layout <- -1;
  r.upto <- min_int;
  r.segments <- [];
  Hashtbl.reset r.tails;
  Hashtbl.reset r.origins

let hash_problem (e : Index.entry) =
  match Audit_chain.verify_lines ~initial_prev:None [ Yojson.Safe.to_string e.raw ] with
  | Ok _ -> None
  | Error (_, msg) -> Some msg

(* Adds one record (in seq order). *)
let consume ~is_gap r (e : Index.entry) =
  r.upto <- max r.upto e.seq;
  if e.hash <> None then begin
    let origin = origin_of e in
    let start ~gap =
      let s =
        {
          origins = [ origin ];
          first_seq = e.seq;
          trimmed_to = e.seq;
          last_seq = e.seq;
          count = 0;
          break = None;
          gap;
        }
      in
      r.segments <- s :: r.segments;
      s
    in
    let linked =
      match e.prev_hash with Some p -> Hashtbl.find_opt r.tails p | None -> None
    in
    let seg, link_problem =
      match linked with
      | Some s -> (s, None)
      | None -> (
          if e.prev_hash = Some Audit_chain.genesis then (start ~gap:false, None)
          else if is_gap e.seq then (start ~gap:true, None)
          else
            match Hashtbl.find_opt r.origins origin with
            | None -> (start ~gap:false, None)
            | Some (_, s) ->
                (s, Some "prev_hash does not match the previous record's hash"))
    in
    let problem = match link_problem with Some _ as p -> p | None -> hash_problem e in
    (match (seg.break, problem) with
    | None, Some msg -> seg.break <- Some (e, msg)
    | _ -> ());
    if not (List.mem origin seg.origins) then seg.origins <- seg.origins @ [ origin ];
    seg.count <- seg.count + 1;
    seg.last_seq <- e.seq;
    (* the segment's previous tail is no longer open *)
    Hashtbl.filter_map_inplace (fun _ s -> if s == seg then None else Some s) r.tails;
    Option.iter (fun h -> Hashtbl.replace r.tails h seg) e.hash;
    Hashtbl.replace r.origins origin (e.seq, seg)
  end

(* Drops what was evicted from the index: segments wholly before [first] (the lowest live
   seq), and the part of a segment before it. A partly evicted segment's [count] is
   reduced by the seq distance, so it is approximate when chains interleave; the next
   full walk ({!reverify}) recounts it exactly. *)
let trim r first =
  let dead (s : segment) = s.last_seq < first in
  if List.exists (fun s -> s.trimmed_to < first) r.segments then begin
    r.segments <-
      List.filter_map
        (fun s ->
          if dead s then None
          else begin
            if s.trimmed_to < first then begin
              s.count <- max 1 (s.count - (first - s.trimmed_to));
              s.trimmed_to <- first;
              match s.break with
              | Some (b, _) when b.Index.seq < first -> s.break <- None
              | _ -> ()
            end;
            Some s
          end)
        r.segments;
    Hashtbl.filter_map_inplace (fun _ s -> if dead s then None else Some s) r.tails;
    Hashtbl.filter_map_inplace
      (fun _ ((last, _) as v) -> if last < first then None else Some v)
      r.origins
  end

(* ---- per-context state ---- *)

let state_key : (string, result) Hashtbl.t Ctx.Key.t = Ctx.Key.create "chain.state"

let states (ctx : Ctx.t) =
  match Ctx.get ctx state_key with
  | Some h -> h
  | None ->
      let h = Hashtbl.create 8 in
      Ctx.set ctx state_key h;
      h

let state_for ctx verifier =
  let h = states ctx in
  match Hashtbl.find_opt h verifier with
  | Some r -> r
  | None ->
      let r = fresh verifier in
      Hashtbl.replace h verifier r;
      r

(* Catches up with the index. *)
let refresh (ctx : Ctx.t) r =
  let index = ctx.index in
  let is_gap = Ingest.is_gap ctx r.verifier in
  (match Index.stream_version index r.verifier with
  | None -> clear r
  | Some (v, _) when v = r.version -> ()
  | Some (v, l) ->
      if l <> r.layout then clear r;
      List.iter (consume ~is_gap r)
        (Index.verifier_range index r.verifier ~after:r.upto ~limit:max_int);
      (match Index.verifier_range index r.verifier ~after:min_int ~limit:1 with
      | e :: _ -> trim r e.Index.seq
      | [] -> ());
      r.version <- v;
      r.layout <- l);
  r.checked_at <- Ctx.now ()

(** The verifier's chain state, brought up to date with the index (incremental). *)
let get (ctx : Ctx.t) verifier =
  let r = state_for ctx verifier in
  refresh ctx r;
  r

(* A full walk from scratch, yielding every [chunk] records. *)
let walk (ctx : Ctx.t) r =
  let index = ctx.index in
  let is_gap = Ingest.is_gap ctx r.verifier in
  let fresh_r = fresh r.verifier in
  let layout = Option.map snd (Index.stream_version index r.verifier) in
  let rec go after =
    match Index.verifier_range index r.verifier ~after ~limit:chunk with
    | [] -> Lwt.return_unit
    | es ->
        List.iter (consume ~is_gap fresh_r) es;
        let* () = Lwt.pause () in
        go fresh_r.upto
  in
  let* () = go min_int in
  clear r;
  r.upto <- fresh_r.upto;
  r.segments <- fresh_r.segments;
  Hashtbl.iter (Hashtbl.replace r.tails) fresh_r.tails;
  Hashtbl.iter (Hashtbl.replace r.origins) fresh_r.origins;
  (* Removals during the walk are trimmed by the next [refresh]; an out-of-order arrival
     changes the layout and forces another walk. *)
  r.version <- -2;
  r.layout <- Option.value layout ~default:(-1);
  r.full_at <- Ctx.now ();
  refresh ctx r;
  Lwt.return_unit

(** Re-walks the verifier's whole stream. Concurrent calls share one walk, and within
    [min_reverify_interval] seconds of the last walk this is the incremental {!get}. *)
let reverify (ctx : Ctx.t) verifier =
  let r = state_for ctx verifier in
  let* () =
    match r.running with
    | Some p -> p
    | None when Ctx.now () -. r.full_at < min_reverify_interval ->
        refresh ctx r;
        Lwt.return_unit
    | None ->
        let p =
          Lwt.finalize
            (fun () -> walk ctx r)
            (fun () ->
              r.running <- None;
              Lwt.return_unit)
        in
        if Lwt.is_sleeping p then r.running <- Some p;
        p
  in
  Lwt.return r

let break_to_json = function
  | None -> `Null
  | Some ((e : Index.entry), msg) ->
      `Assoc
        [
          ("seq", `Int e.seq);
          ("request_id", `String e.request_id);
          ("location", `String e.location);
          ("message", `String msg);
        ]

let chain_json r : Yojson.Safe.t =
  `Assoc
    [
      ("verifier", `String r.verifier);
      ("state", `String (state_of r));
      ("records", `Int (records r));
      ("segments", `Int (List.length r.segments));
      ("gaps", `Int (List.length (List.filter (fun s -> s.gap) r.segments)));
      ("first_break", break_to_json (first_break r));
      ("checked_at", `String (Api.iso8601 r.checked_at));
    ]

(* The last published verification ([{checked_at, chains}]); private, read through
   [status]. *)
let status_key : Yojson.Safe.t Ctx.Key.t = Ctx.Key.create "chain.status"

(** The last audit-chain verification of every verifier ([{checked_at, chains: [...]}]),
    [`Null] before the first check. *)
let status (ctx : Ctx.t) = Option.value (Ctx.get ctx status_key) ~default:`Null

(** For tests only: replaces the published status without checking chains. *)
module Testing = struct
  let set_status (ctx : Ctx.t) j = Ctx.set ctx status_key j
end

(** Replaces (or adds) these verifiers' entries in [status]. With [~all:true], entries for
    verifiers not in [results] are dropped. *)
let publish ?(all = false) (ctx : Ctx.t) results =
  let old =
    if all then []
    else match Api.member "chains" (status ctx) with Some (`List l) -> l | _ -> []
  in
  let names = List.map (fun r -> r.verifier) results in
  let kept =
    List.filter
      (fun j ->
        match Api.member "verifier" j with
        | Some (`String v) -> not (List.mem v names)
        | _ -> false)
      old
  in
  let chains =
    List.sort
      (fun a b -> compare (Api.member "verifier" a) (Api.member "verifier" b))
      (kept @ List.map chain_json results)
  in
  Ctx.set ctx status_key
    (`Assoc
       [ ("checked_at", `String (Api.iso8601 (Ctx.now ()))); ("chains", `List chains) ])

(** Brings every verifier's chain state up to date (incrementally), drops the state of
    verifiers no longer in the index and publishes [status]. *)
let check_all (ctx : Ctx.t) =
  let live = Index.verifiers ctx.index in
  let h = states ctx in
  Hashtbl.filter_map_inplace
    (fun v r -> if List.mem v live || r.running <> None then Some r else None)
    h;
  let results = List.map (get ctx) live in
  publish ~all:true ctx results

(* ---- verify command ---- *)

let quote s =
  if
    s <> ""
    && String.for_all
         (function
           | 'a' .. 'z'
           | 'A' .. 'Z'
           | '0' .. '9'
           | '/' | '.' | '_' | '-' | ':' | '=' | '@' ->
               true
           | _ -> false)
         s
  then s
  else "'" ^ String.concat "'\\''" (String.split_on_char '\'' s) ^ "'"

(** [haltsql audit verify ...] for the original records of [e]. *)
let verify_command (cfg : Console_config.t) (e : Index.entry) =
  let path = strip_line e.location in
  let object_source scheme =
    List.find_map
      (fun (_, src) ->
        match src with
        | Console_config.Src_s3 { uri; region; endpoint }
          when scheme = "s3://" && String.starts_with ~prefix:uri path ->
            Some (uri, region, endpoint)
        | Console_config.Src_gcs { uri }
          when scheme = "gs://" && String.starts_with ~prefix:uri path ->
            Some (uri, None, None)
        | _ -> None)
      cfg.audit.sources
  in
  let host =
    match Ingest.host_of_object_name path with Some h -> h | None -> e.verifier
  in
  if String.starts_with ~prefix:"s3://" path then
    let uri, region, endpoint =
      match object_source "s3://" with
      | Some x -> x
      | None -> (Filename.dirname path ^ "/", None, None)
    in
    String.concat " "
      ([ "haltsql audit verify"; quote uri; "--host"; quote host ]
      @ (match region with Some r -> [ "--region"; quote r ] | None -> [])
      @ match endpoint with Some ep -> [ "--endpoint"; quote ep ] | None -> [])
  else if String.starts_with ~prefix:"gs://" path then
    let uri =
      match object_source "gs://" with
      | Some (u, _, _) -> u
      | None -> Filename.dirname path ^ "/"
    in
    (* The CLI reads s3:// directly; GCS objects are verified from a local copy. *)
    Printf.sprintf
      "gcloud storage cp -r %s ./haltsql-audit && haltsql audit verify ./haltsql-audit \
       --host %s"
      (quote uri) (quote host)
  else "haltsql audit verify " ^ quote path

(* ---- custody ---- *)

(* The segment holding [e]: the newest one that came from [e]'s origin and spans its
   seq. *)
let segment_of r (e : Index.entry) =
  let origin = origin_of e in
  List.find_opt
    (fun (s : segment) ->
      List.mem origin s.origins && s.trimmed_to <= e.seq && e.seq <= s.last_seq)
    r.segments

let custody_json (ctx : Ctx.t) r (e : Index.entry) : Yojson.Safe.t =
  let neighbours =
    Index.verifier_range ctx.index e.verifier ~after:(e.seq - 3) ~limit:5
    |> List.filter (fun (n : Index.entry) -> n.seq <> e.seq && abs (n.seq - e.seq) <= 2)
  in
  let seg = if e.hash = None then None else segment_of r e in
  let state =
    match seg with
    | None -> "unknown"
    | Some { break = Some _; _ } -> "broken"
    | Some { gap = true; _ } -> "gap"
    | Some _ -> "intact"
  in
  let seg_break = Option.bind seg (fun s -> s.break) in
  `Assoc
    [
      ("verifier", `String e.verifier);
      ("seq", `Int e.seq);
      ("hash", Api.opt_string e.hash);
      ("prev_hash", Api.opt_string e.prev_hash);
      ( "neighbours",
        `List
          (List.map
             (fun (n : Index.entry) ->
               `Assoc
                 [
                   ("seq", `Int n.seq);
                   ("request_id", `String n.request_id);
                   ("hash", Api.opt_string n.hash);
                   ("prev_hash", Api.opt_string n.prev_hash);
                   ( "outcome",
                     `String (Haltsql_report.Record.outcome_to_string n.record.outcome) );
                 ])
             neighbours) );
      ("location", `String e.location);
      ("chain_state", `String state);
      ("first_break", break_to_json seg_break);
      ("last_verified", `String (Api.iso8601 r.checked_at));
      ("verify_command", `String (verify_command ctx.config e));
    ]

(** Custody of [e] from the incrementally maintained chain state. *)
let custody (ctx : Ctx.t) (e : Index.entry) = custody_json ctx (get ctx e.verifier) e
