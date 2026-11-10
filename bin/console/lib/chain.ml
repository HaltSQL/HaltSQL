(* Chain of custody: local verification of each verifier's audit hash chain over the
   records in the index ({!Haltsql_cloud.Audit_chain}), neighbours, and the command that
   re-verifies the original records independently.

   A verifier's stream (in [seq] order) is split into segments at every record whose
   [prev_hash] is the genesis hash (a new chain, e.g. a restart without a spool), the same
   tolerance as [haltsql audit verify] without [--strict]. The first record of a segment
   may link to a record that is no longer in the index (retention), so it is accepted as
   is; every later link and every hash is checked. Records without a [hash] are not
   chained ("unknown"). *)

module Audit_chain = Haltsql_cloud.Audit_chain

type segment = {
  first_seq : int;
  last_seq : int;
  count : int;
  break : (Index.entry * string) option;  (** the first record that fails, and why *)
}

type result = {
  verifier : string;
  checked_at : float;
  segments : segment list;
  records : int;  (** chained records checked *)
  stamp : int * int;  (** (stream length, last seq) when checked *)
}

let state_of r =
  if List.exists (fun s -> s.break <> None) r.segments then "broken"
  else if r.records = 0 then "unknown"
  else "intact"

let first_break r = List.find_map (fun s -> s.break) r.segments

let verify_segment (entries : Index.entry list) =
  let arr = Array.of_list entries in
  let lines =
    Array.to_list (Array.map (fun (e : Index.entry) -> Yojson.Safe.to_string e.raw) arr)
  in
  let break =
    match Audit_chain.verify_lines ~initial_prev:None lines with
    | Ok _ -> None
    | Error (n, msg) ->
        let i = max 0 (min (Array.length arr - 1) (n - 1)) in
        Some (arr.(i), msg)
  in
  {
    first_seq = arr.(0).seq;
    last_seq = arr.(Array.length arr - 1).seq;
    count = Array.length arr;
    break;
  }

let stamp_of (stream : Index.entry list) =
  (List.length stream, match List.rev stream with e :: _ -> e.seq | [] -> -1)

let check (index : Index.t) verifier =
  let stream = Index.verifier_stream index verifier in
  let chained = List.filter (fun (e : Index.entry) -> e.hash <> None) stream in
  let segs =
    List.fold_left
      (fun acc (e : Index.entry) ->
        match acc with
        | cur :: rest when e.prev_hash <> Some Audit_chain.genesis -> (e :: cur) :: rest
        | _ -> [ e ] :: acc)
      [] chained
    |> List.rev_map List.rev
  in
  {
    verifier;
    checked_at = Unix.gettimeofday ();
    segments = List.map verify_segment segs;
    records = List.length chained;
    stamp = stamp_of stream;
  }

(* Last result per verifier, for one index (several consoles can share a process in
   tests). *)
let cache : (Index.t * (string, result) Hashtbl.t) option ref = ref None

let cache_for index =
  match !cache with
  | Some (i, h) when i == index -> h
  | _ ->
      let h = Hashtbl.create 8 in
      cache := Some (index, h);
      h

(** The cached result when the verifier's stream has not changed, else a fresh check
    (always fresh with [~force:true]). *)
let get ?(force = false) (index : Index.t) verifier =
  let cache = cache_for index in
  match Hashtbl.find_opt cache verifier with
  | Some r when (not force) && r.stamp = stamp_of (Index.verifier_stream index verifier)
    ->
      r
  | _ ->
      let r = check index verifier in
      Hashtbl.replace cache verifier r;
      r

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
      ("records", `Int r.records);
      ("segments", `Int (List.length r.segments));
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

let check_all (ctx : Ctx.t) =
  let results = List.map (get ~force:true ctx.index) (Index.verifiers ctx.index) in
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

let strip_line loc =
  match String.rindex_opt loc '#' with Some i -> String.sub loc 0 i | None -> loc

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

let custody (ctx : Ctx.t) ?(force = false) (e : Index.entry) : Yojson.Safe.t =
  let r = get ~force ctx.index e.verifier in
  let stream = Index.verifier_stream ctx.index e.verifier in
  let neighbours =
    List.filter
      (fun (n : Index.entry) -> n.seq <> e.seq && abs (n.seq - e.seq) <= 2)
      stream
  in
  let state =
    if e.hash = None then "unknown"
    else
      match
        List.find_opt (fun s -> s.first_seq <= e.seq && e.seq <= s.last_seq) r.segments
      with
      | None -> "unknown"
      | Some { break = Some _; _ } -> "broken"
      | Some { break = None; _ } -> "intact"
  in
  let seg_break =
    List.find_map
      (fun s -> if s.first_seq <= e.seq && e.seq <= s.last_seq then s.break else None)
      r.segments
  in
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
