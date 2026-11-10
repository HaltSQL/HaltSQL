module Record = Haltsql_report.Record

type entry = {
  record : Record.t;
  request_id : string;
  ts : float;
  verifier : string;
  hash : string option;
  prev_hash : string option;
  elapsed_us : int option;
  location : string;
  seq : int;
  raw : Yojson.Safe.t;
}

(* ---- layout ----

   Every entry is wrapped once in a [node]; all secondary structures hold references to
   that node, never copies of the entry. Removal (eviction, expiry) marks the node dead
   and bumps a [dead] counter on the structures that reference it; each structure
   compacts itself once more than half of its slots are dead, so removal is O(1)
   amortised and memory stays within a constant factor of the live set.

   - [items]: insertion order, with a moving start offset (eviction from the front,
     [iter]/[fold]).
   - [buckets]: minute bucket -> nodes in insertion order, in an ordered map, so time
     ranges touch only the overlapping buckets.
   - [streams]: verifier -> nodes, kept sorted by [seq] (re-sorted lazily if an entry
     arrives out of order); the live count doubles as the per-verifier aggregate.
   - [oldest]/[newest]: cached, updated on add, invalidated only when the removed entry
     carries the cached value, then recomputed from the first/last bucket. *)

type node = { e : entry; mutable live : bool }

(* A growable array of nodes with a count of dead ones still in it. Unused slots hold a
   live node of the same vector (never a dead one), so they keep no evicted entry alive. *)
type vec = { mutable a : node array; mutable len : int; mutable dead : int }

let vec_make n = { a = Array.make 4 n; len = 1; dead = 0 }

let vec_push v n =
  if v.len >= Array.length v.a then begin
    let b = Array.make (2 * Array.length v.a) n in
    Array.blit v.a 0 b 0 v.len;
    v.a <- b
  end;
  v.a.(v.len) <- n;
  v.len <- v.len + 1

let vec_live v = v.len - v.dead

(* Drops dead nodes, keeping order. *)
let vec_compact v =
  let j = ref 0 in
  for i = 0 to v.len - 1 do
    let n = v.a.(i) in
    if n.live then begin
      v.a.(!j) <- n;
      incr j
    end
  done;
  if !j > 0 then Array.fill v.a !j (v.len - !j) v.a.(0);
  v.len <- !j;
  v.dead <- 0;
  if Array.length v.a > 64 && 4 * v.len < Array.length v.a then
    v.a <- Array.sub v.a 0 (max 4 (2 * v.len))

let vec_kill v =
  v.dead <- v.dead + 1;
  if v.dead < v.len && v.len >= 16 && 2 * v.dead > v.len then vec_compact v

module IntMap = Map.Make (Int)

let bucket_seconds = 60.

let bucket_of ts =
  if Float.is_nan ts then 0
  else
    let b = Float.floor (ts /. bucket_seconds) in
    if b <= -4e18 then min_int + 1 else if b >= 4e18 then max_int - 1 else int_of_float b

type stream = {
  nodes : vec;
  mutable sorted : bool;
  mutable version : int;  (** [t.gen] at the last add or removal *)
  mutable layout : int;  (** [t.gen] at creation or the last out-of-order add *)
}

type t = {
  mutable items : node array;
  mutable start : int;
  mutable stop : int;
  mutable count : int;
  by_id : (string, node) Hashtbl.t;
  mutable buckets : vec IntMap.t;
  streams : (string, stream) Hashtbl.t;
  mutable oldest_c : float option;
  mutable oldest_ok : bool;
  mutable newest_c : float option;
  mutable newest_ok : bool;
  max_records : int;
  retention : float;
  mutable gen : int;  (** bumped on every stream change; never repeats *)
}

let create ?(max_records = 2_000_000) ?(retention_seconds = 7. *. 86400.) () =
  {
    items = [||];
    start = 0;
    stop = 0;
    count = 0;
    by_id = Hashtbl.create 4096;
    buckets = IntMap.empty;
    streams = Hashtbl.create 16;
    oldest_c = None;
    oldest_ok = true;
    newest_c = None;
    newest_ok = true;
    max_records = max 1 max_records;
    retention = retention_seconds;
    gen = 0;
  }

let size t = t.count

(* Rebuilds [items] with only live nodes, with room for [extra] more. [filler] is a live
   node used for unused slots. *)
let compact_items t ~filler =
  let cap = max 1024 ((2 * t.count) + 1) in
  let a = Array.make cap filler in
  let j = ref 0 in
  for i = t.start to t.stop - 1 do
    let n = t.items.(i) in
    if n.live then begin
      a.(!j) <- n;
      incr j
    end
  done;
  t.items <- a;
  t.start <- 0;
  t.stop <- !j

let kill t n =
  let e = n.e in
  n.live <- false;
  t.count <- t.count - 1;
  (match Hashtbl.find_opt t.by_id e.request_id with
  | Some n' when n' == n -> Hashtbl.remove t.by_id e.request_id
  | _ -> ());
  let k = bucket_of e.ts in
  (match IntMap.find_opt k t.buckets with
  | Some v ->
      if vec_live v <= 1 then t.buckets <- IntMap.remove k t.buckets else vec_kill v
  | None -> ());
  (match Hashtbl.find_opt t.streams e.verifier with
  | Some s ->
      if vec_live s.nodes <= 1 then Hashtbl.remove t.streams e.verifier
      else begin
        vec_kill s.nodes;
        t.gen <- t.gen + 1;
        s.version <- t.gen
      end
  | None -> ());
  (match t.oldest_c with
  | Some x when t.oldest_ok && not (x < e.ts) -> t.oldest_ok <- false
  | _ -> ());
  match t.newest_c with
  | Some x when t.newest_ok && not (x > e.ts) -> t.newest_ok <- false
  | _ -> ()

(* Drops dead nodes, then the first live one, from the front of [items]. *)
let evict_front t =
  let continue = ref true in
  while !continue && t.start < t.stop do
    let n = t.items.(t.start) in
    if n.live then begin
      kill t n;
      continue := false
    end;
    (* Overwrite the slot with the newest node so it no longer references [n]. *)
    t.items.(t.start) <- t.items.(t.stop - 1);
    t.start <- t.start + 1
  done

let push_item t n =
  if t.stop >= Array.length t.items then compact_items t ~filler:n;
  t.items.(t.stop) <- n;
  t.stop <- t.stop + 1

(* [true] when the entry was added (not a duplicate). *)
let add_entry t e =
  let dup =
    match Hashtbl.find_opt t.by_id e.request_id with
    | Some n' -> n'.e.verifier = e.verifier && n'.e.location = e.location
    | None -> false
  in
  if not dup then begin
    let n = { e; live = true } in
    push_item t n;
    t.count <- t.count + 1;
    Hashtbl.replace t.by_id e.request_id n;
    let k = bucket_of e.ts in
    (match IntMap.find_opt k t.buckets with
    | Some v -> vec_push v n
    | None -> t.buckets <- IntMap.add k (vec_make n) t.buckets);
    t.gen <- t.gen + 1;
    (match Hashtbl.find_opt t.streams e.verifier with
    | Some s ->
        let v = s.nodes in
        if v.len > 0 && v.a.(v.len - 1).e.seq >= e.seq then begin
          s.sorted <- false;
          s.layout <- t.gen
        end;
        s.version <- t.gen;
        vec_push v n
    | None ->
        Hashtbl.replace t.streams e.verifier
          { nodes = vec_make n; sorted = true; version = t.gen; layout = t.gen });
    if t.oldest_ok then
      t.oldest_c <-
        (match t.oldest_c with Some x when x <= e.ts -> Some x | _ -> Some e.ts);
    if t.newest_ok then
      t.newest_c <-
        (match t.newest_c with Some x when x >= e.ts -> Some x | _ -> Some e.ts);
    while t.count > t.max_records do
      evict_front t
    done
  end;
  not dup

let add t e = ignore (add_entry t e)

let iter t f =
  for i = t.start to t.stop - 1 do
    let n = t.items.(i) in
    if n.live then f n.e
  done

let fold t ~init ~f =
  let acc = ref init in
  iter t (fun e -> acc := f !acc e);
  !acc

let vec_iter v f =
  for i = 0 to v.len - 1 do
    let n = v.a.(i) in
    if n.live then f n.e
  done

(* Buckets with [lo <= key <= hi], ascending. *)
let iter_buckets_asc t ~lo ~hi f =
  let rec go s =
    match s () with
    | Seq.Cons ((k, v), rest) when k <= hi ->
        f v;
        go rest
    | _ -> ()
  in
  go (IntMap.to_seq_from lo t.buckets)

(* Buckets with [lo <= key <= hi], descending, while [f] returns [true]. *)
let iter_buckets_desc t ~lo ~hi f =
  let rec go hi =
    match IntMap.find_last_opt (fun k -> k <= hi) t.buckets with
    | Some (k, v) when k >= lo -> if f v && k > min_int then go (k - 1)
    | _ -> ()
  in
  go hi

let expire t ~now =
  let cutoff = now -. t.retention in
  let doomed = ref [] in
  iter_buckets_asc t ~lo:min_int ~hi:(bucket_of cutoff) (fun v ->
      for i = 0 to v.len - 1 do
        let n = v.a.(i) in
        if n.live && n.e.ts < cutoff then doomed := n :: !doomed
      done);
  List.iter (fun n -> if n.live then kill t n) !doomed;
  while t.start < t.stop && not t.items.(t.start).live do
    t.items.(t.start) <- t.items.(t.stop - 1);
    t.start <- t.start + 1
  done;
  if t.start >= t.stop then begin
    t.items <- [||];
    t.start <- 0;
    t.stop <- 0
  end
  else if t.start > Array.length t.items / 2 || 2 * t.count < t.stop - t.start then
    compact_items t ~filler:t.items.(t.stop - 1)

let bucket_extreme v ~better =
  let r = ref None in
  vec_iter v (fun e ->
      match !r with Some x when not (better e.ts x) -> () | _ -> r := Some e.ts);
  !r

let oldest t =
  if not t.oldest_ok then begin
    t.oldest_c <-
      (match IntMap.min_binding_opt t.buckets with
      | Some (_, v) -> bucket_extreme v ~better:( < )
      | None -> None);
    t.oldest_ok <- true
  end;
  t.oldest_c

let newest t =
  if not t.newest_ok then begin
    t.newest_c <-
      (match IntMap.max_binding_opt t.buckets with
      | Some (_, v) -> bucket_extreme v ~better:( > )
      | None -> None);
    t.newest_ok <- true
  end;
  t.newest_c

let find t id = Option.map (fun n -> n.e) (Hashtbl.find_opt t.by_id id)
let by_ts a b = compare a.ts b.ts

let between t ~since ~until =
  if not (since < until) then []
  else begin
    let acc = ref [] in
    iter_buckets_asc t ~lo:(bucket_of since) ~hi:(bucket_of until) (fun v ->
        (* Collected newest-inserted first, then reversed: insertion order within a
           bucket, as the stable sort below expects for equal timestamps. *)
        let part = ref [] in
        vec_iter v (fun e -> if e.ts >= since && e.ts < until then part := e :: !part);
        acc := List.rev_append (List.stable_sort by_ts (List.rev !part)) !acc);
    List.rev !acc
  end

let ensure_sorted s =
  let vec = s.nodes in
  if not s.sorted then begin
    vec_compact vec;
    let a = Array.sub vec.a 0 vec.len in
    Array.stable_sort (fun x y -> compare x.e.seq y.e.seq) a;
    Array.blit a 0 vec.a 0 vec.len;
    s.sorted <- true
  end

let verifier_stream t v =
  match Hashtbl.find_opt t.streams v with
  | None -> []
  | Some s ->
      ensure_sorted s;
      let vec = s.nodes in
      let acc = ref [] in
      for i = vec.len - 1 downto 0 do
        let n = vec.a.(i) in
        if n.live then acc := n.e :: !acc
      done;
      !acc

let stream_version t v =
  Option.map (fun s -> (s.version, s.layout)) (Hashtbl.find_opt t.streams v)

let verifier_range t v ~after ~limit =
  match Hashtbl.find_opt t.streams v with
  | None -> []
  | Some s ->
      ensure_sorted s;
      let vec = s.nodes in
      (* first slot with seq > after (dead slots keep their place in seq order) *)
      let lo = ref 0 and hi = ref vec.len in
      while !lo < !hi do
        let mid = (!lo + !hi) / 2 in
        if vec.a.(mid).e.seq > after then hi := mid else lo := mid + 1
      done;
      let acc = ref [] and k = ref 0 and i = ref !lo in
      while !k < limit && !i < vec.len do
        let n = vec.a.(!i) in
        if n.live then begin
          acc := n.e :: !acc;
          incr k
        end;
        incr i
      done;
      List.rev !acc

let verifier_counts t =
  Hashtbl.fold (fun k s acc -> (k, vec_live s.nodes) :: acc) t.streams []
  |> List.sort (fun (a, _) (b, _) -> compare a b)

let verifiers t = List.map fst (verifier_counts t)
(* ---- building entries ---- *)

let str_member name = function
  | `Assoc l -> (
      match List.assoc_opt name l with Some (`String s) -> Some s | _ -> None)
  | _ -> None

let int_member name = function
  | `Assoc l -> (
      match List.assoc_opt name l with
      | Some (`Int i) -> Some i
      | Some (`Float f) -> Some (int_of_float f)
      | _ -> None)
  | _ -> None

let entry_of_json ~verifier ~location ~seq ~now (j : Yojson.Safe.t) =
  match Record.of_json j with
  | Error _ -> None
  | Ok record ->
      let request_id =
        match str_member "request_id" j with
        | Some id -> id
        | None -> (
            (* Proxy records have no request id: derive a stable one from the location. *)
            match str_member "session" j with
            | Some s -> Printf.sprintf "%s-%d" s seq
            | None ->
                Printf.sprintf "%s-%d"
                  (Haltsql.sha256_hex location |> fun h -> String.sub h 0 12)
                  seq)
      in
      Some
        {
          record;
          request_id;
          ts = Option.value record.ts ~default:now;
          verifier;
          hash = str_member "hash" j;
          prev_hash = str_member "prev_hash" j;
          elapsed_us = int_member "elapsed_us" j;
          location;
          seq;
          raw = j;
        }

(* ---- search ---- *)

type filter = {
  q : string option;
  caller : string option;
  policy : string option;
  outcome : Record.outcome option;
  code : string option;
  table : string option;
  fingerprint : string option;
  verifier : string option;
  since : float option;
  until : float option;
}

let no_filter =
  {
    q = None;
    caller = None;
    policy = None;
    outcome = None;
    code = None;
    table = None;
    fingerprint = None;
    verifier = None;
    since = None;
    until = None;
  }

let outcome_of_string = function
  | "allowed" -> Some Record.Allowed
  | "denied" -> Some Record.Denied
  | "shadow_denied" -> Some Record.Shadow_denied
  | _ -> None

let contains ~sub s =
  let n = String.length sub and m = String.length s in
  (* compares in place: no substring per position *)
  let rec at i j = j = n || (s.[i + j] = sub.[j] && at i (j + 1)) in
  let rec go i = i + n <= m && (at i 0 || go (i + 1)) in
  n = 0 || go 0

let starts_with ~prefix s = String.starts_with ~prefix s

let table_matches t tables =
  List.exists (fun x -> x = t || String.ends_with ~suffix:("." ^ t) x) tables

let matches f e =
  let r = e.record in
  let ok o p = match o with None -> true | Some v -> p v in
  ok f.caller (fun c -> contains ~sub:c r.caller)
  && ok f.policy (fun p -> r.policy = p)
  && ok f.outcome (fun o -> r.outcome = o)
  && ok f.code (fun c -> List.mem c r.codes)
  && ok f.table (fun t -> table_matches t r.tables)
  && ok f.fingerprint (fun fp ->
      match r.fingerprint with Some x -> starts_with ~prefix:fp x | None -> false)
  && ok f.verifier (fun v -> e.verifier = v)
  && ok f.since (fun s -> e.ts >= s)
  && ok f.until (fun u -> e.ts < u)
  && ok f.q (fun q ->
      starts_with ~prefix:q e.request_id
      || contains ~sub:q r.caller
      || (match r.fingerprint with Some x -> starts_with ~prefix:q x | None -> false)
      || table_matches q r.tables)

let filter_range (f : filter) =
  let lo = match f.since with Some s -> bucket_of s | None -> min_int in
  let hi = match f.until with Some u -> bucket_of u | None -> max_int in
  let empty =
    match (f.since, f.until) with Some s, Some u -> not (s < u) | _ -> false
  in
  (lo, hi, empty)

let by_ts_desc a b = compare b.ts a.ts
let rec take n = function x :: rest when n > 0 -> x :: take (n - 1) rest | _ -> []

let search ?limit t f =
  let lo, hi, empty = filter_range f in
  let empty =
    empty
    || (match limit with Some n -> n <= 0 | None -> false)
    || match f.verifier with Some v -> not (Hashtbl.mem t.streams v) | None -> false
  in
  if empty then []
  else begin
    let acc = ref [] and found = ref 0 in
    (* Newest bucket first; each bucket is taken whole (sorted newest first, equal
       timestamps newest-inserted first), so the first [limit] results are exactly those
       of an unlimited search. *)
    iter_buckets_desc t ~lo ~hi (fun v ->
        let part = ref [] and k = ref 0 in
        vec_iter v (fun e ->
            if matches f e then begin
              part := e :: !part;
              incr k
            end);
        acc := List.rev_append (List.stable_sort by_ts_desc !part) !acc;
        found := !found + !k;
        match limit with Some n -> !found < n | None -> true);
    let all = List.rev !acc in
    match limit with Some n -> take n all | None -> all
  end

let count t f =
  if f = no_filter then size t
  else
    let lo, hi, empty = filter_range f in
    if empty then 0
    else begin
      let c = ref 0 in
      iter_buckets_asc t ~lo ~hi (fun v ->
          vec_iter v (fun e -> if matches f e then incr c));
      !c
    end

(* ---- snapshot ---- *)

let snapshot t path =
  let tmp = Printf.sprintf "%s.tmp.%d" path (Unix.getpid ()) in
  let oc = open_out_bin tmp in
  let n = ref 0 in
  (try
     iter t (fun e ->
         let line : Yojson.Safe.t =
           `Assoc
             [
               ("verifier", `String e.verifier);
               ("location", `String e.location);
               ("seq", `Int e.seq);
               ("ts", `Float e.ts);
               ("raw", e.raw);
             ]
         in
         Yojson.Safe.to_channel oc line;
         output_char oc '\n';
         incr n);
     close_out oc
   with exn ->
     close_out_noerr oc;
     (try Sys.remove tmp with Sys_error _ -> ());
     raise exn);
  Sys.rename tmp path;
  !n

let restore t path =
  if not (Sys.file_exists path) then 0
  else begin
    let ic = open_in_bin path in
    let n = ref 0 in
    Fun.protect
      ~finally:(fun () -> close_in_noerr ic)
      (fun () ->
        try
          while true do
            let line = input_line ic in
            match Yojson.Safe.from_string line with
            | `Assoc l as j -> (
                let s k = str_member k j in
                let seq = int_member "seq" j in
                let ts =
                  match List.assoc_opt "ts" l with
                  | Some (`Float f) -> Some f
                  | Some (`Int i) -> Some (float_of_int i)
                  | _ -> None
                in
                match (s "verifier", s "location", seq, ts, List.assoc_opt "raw" l) with
                | Some verifier, Some location, Some seq, Some now, Some raw -> (
                    match entry_of_json ~verifier ~location ~seq ~now raw with
                    | Some e -> if add_entry t e then incr n
                    | None -> ())
                | _ -> ())
            | _ -> ()
            | exception Yojson.Json_error _ -> ()
          done
        with End_of_file -> ());
    !n
  end

(* ---- JSON ---- *)

let raw_sql e =
  match e.record.sql with
  | Some s -> Some s
  | None -> (
      match str_member "sql" e.raw with
      | Some s -> Some s
      | None -> str_member "statement" e.raw)

let opt_s = function None -> `Null | Some s -> `String s

let entry_to_json e =
  let r = e.record in
  `Assoc
    [
      ("request_id", `String e.request_id);
      ("ts", `String (Api.iso8601 e.ts));
      ("verifier", `String e.verifier);
      ("source", `String (Record.source_to_string r.source));
      ("caller", `String r.caller);
      ("caller_type", opt_s r.caller_type);
      ("policy", `String r.policy);
      ("policy_version", opt_s r.policy_version);
      ("outcome", `String (Record.outcome_to_string r.outcome));
      ("codes", Api.strings r.codes);
      ("tables", Api.strings r.tables);
      ("fingerprint", opt_s r.fingerprint);
      ("sql_sha256", opt_s r.sql_sha256);
      ("elapsed_us", match e.elapsed_us with None -> `Null | Some i -> `Int i);
      ("has_raw_sql", `Bool (raw_sql e <> None));
    ]
