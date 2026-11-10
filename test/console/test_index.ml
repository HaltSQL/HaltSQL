(* Index tests: incremental aggregates, time buckets, limited search, per-verifier
   streams and snapshot/restore, checked against brute-force models. *)

open Helpers
module C = Haltsql_console
module I = C.Index

let now = 1_700_000_000.

let entry ?(verifier = "v") ?(seq = 0) ?(allowed = true) ?(caller = "token:agent") ~id ~ts
    () =
  let j =
    server_record ~request_id:id ~ts ~allowed ~caller
      ~codes:(if allowed then [] else [ "E_TENANT_MISMATCH" ])
      ()
  in
  match
    I.entry_of_json ~verifier
      ~location:(Printf.sprintf "%s.jsonl#L%d" verifier seq)
      ~seq ~now j
  with
  | Some e -> e
  | None -> Alcotest.fail "entry_of_json"

(* A few distinct records; random entries are copies with new id/ts/verifier/seq. *)
let bases =
  lazy
    [|
      entry ~id:"b0" ~ts:now ();
      entry ~id:"b1" ~ts:now ~allowed:false ();
      entry ~id:"b2" ~ts:now ~caller:"token:etl" ();
      entry ~id:"b3" ~ts:now ~caller:"token:etl" ~allowed:false ();
    |]

let verifier_names = [| "a"; "b"; "c"; "d" |]
let seqs = Hashtbl.create 8

let random_entry st i ~spread =
  let base = (Lazy.force bases).(Random.State.int st 4) in
  let verifier = verifier_names.(Random.State.int st 4) in
  let last = Option.value (Hashtbl.find_opt seqs verifier) ~default:0 in
  (* Mostly increasing seq, occasionally out of order. *)
  let seq = if Random.State.int st 20 = 0 then max 0 (last - 5) else last + 1 in
  Hashtbl.replace seqs verifier (max seq last);
  (* Close to time order: steady clock plus jitter, some far outliers either way, and
     whole-second timestamps to exercise ties. *)
  let ts =
    let base_ts = now +. (float_of_int i *. 2.) in
    match Random.State.int st 10 with
    | 0 -> base_ts -. Random.State.float st spread
    | 1 -> base_ts +. Random.State.float st spread
    | 2 -> Float.round (base_ts /. 10.) *. 10.
    | _ -> base_ts +. Random.State.float st 30. -. 15.
  in
  {
    base with
    I.request_id = Printf.sprintf "r%d" i;
    ts;
    verifier;
    seq;
    location = Printf.sprintf "%s.jsonl#L%d" verifier i;
  }

(* Reference model: the live entries in insertion order, queried by brute force. *)
module Model = struct
  type t = { mutable l : I.entry list; max : int; retention : float }

  let create ~max ~retention = { l = []; max; retention }

  let add m e =
    m.l <- m.l @ [ e ];
    let n = List.length m.l in
    if n > m.max then m.l <- List.filteri (fun i _ -> i >= n - m.max) m.l

  let expire m ~now = m.l <- List.filter (fun e -> e.I.ts >= now -. m.retention) m.l

  let extreme m better =
    List.fold_left
      (fun acc e ->
        match acc with Some x when not (better e.I.ts x) -> acc | _ -> Some e.I.ts)
      None m.l

  let verifier_counts m =
    let h = Hashtbl.create 8 in
    List.iter
      (fun (e : I.entry) ->
        Hashtbl.replace h e.verifier
          (1 + Option.value (Hashtbl.find_opt h e.verifier) ~default:0))
      m.l;
    Hashtbl.fold (fun k v acc -> (k, v) :: acc) h [] |> List.sort compare

  let between m ~since ~until =
    List.filter (fun e -> e.I.ts >= since && e.I.ts < until) m.l
    |> List.stable_sort (fun a b -> compare a.I.ts b.I.ts)

  let stream m v =
    List.filter (fun (e : I.entry) -> e.verifier = v) m.l
    |> List.stable_sort (fun a b -> compare a.I.seq b.I.seq)

  (* The original implementation: newest-inserted first, then a stable sort newest
     first. Only the filter fields the tests use are modelled. *)
  let search m (f : I.filter) =
    List.rev m.l
    |> List.filter (fun (e : I.entry) ->
        let r = e.record in
        (match f.outcome with None -> true | Some o -> r.outcome = o)
        && (match f.caller with None -> true | Some c -> r.caller = c)
        && (match f.verifier with None -> true | Some v -> e.verifier = v)
        && (match f.since with None -> true | Some s -> e.ts >= s)
        && match f.until with None -> true | Some u -> e.ts < u)
    |> List.stable_sort (fun a b -> compare b.I.ts a.I.ts)
end

let ids l = List.map (fun e -> e.I.request_id) l
let fopt = Alcotest.(option (float 0.))

let check_aggregates msg idx (m : Model.t) =
  Alcotest.(check int) (msg ^ ": size") (List.length m.l) (I.size idx);
  Alcotest.check fopt (msg ^ ": oldest") (Model.extreme m ( < )) (I.oldest idx);
  Alcotest.check fopt (msg ^ ": newest") (Model.extreme m ( > )) (I.newest idx);
  Alcotest.(check (list (pair string int)))
    (msg ^ ": verifier counts") (Model.verifier_counts m) (I.verifier_counts idx);
  Alcotest.(check (list string))
    (msg ^ ": verifiers")
    (List.map fst (Model.verifier_counts m))
    (I.verifiers idx);
  Alcotest.(check (list string))
    (msg ^ ": iter order") (ids m.l)
    (List.rev (I.fold idx ~init:[] ~f:(fun acc e -> e.I.request_id :: acc)))

let aggregates () =
  let idx = I.create ~max_records:5 ~retention_seconds:100. () in
  let m = Model.create ~max:5 ~retention:100. in
  let add e =
    I.add idx e;
    Model.add m e
  in
  check_aggregates "empty" idx m;
  (* Out of order: the maximum arrives first and is evicted first. *)
  add (entry ~verifier:"a" ~id:"e1" ~ts:(now +. 50.) ());
  add (entry ~verifier:"b" ~id:"e2" ~ts:(now -. 300.) ());
  add (entry ~verifier:"a" ~id:"e3" ~ts:(now -. 10.) ());
  check_aggregates "three" idx m;
  add (entry ~verifier:"c" ~id:"e4" ~ts:(now -. 300.) ());
  add (entry ~verifier:"a" ~id:"e5" ~ts:(now +. 5.) ());
  add (entry ~verifier:"a" ~id:"e6" ~ts:(now +. 1.) ());
  check_aggregates "evicted newest" idx m;
  add (entry ~verifier:"a" ~id:"e7" ~ts:(now +. 2.) ());
  check_aggregates "evicted one oldest (tie remains)" idx m;
  add (entry ~verifier:"a" ~id:"e8" ~ts:(now +. 3.) ());
  check_aggregates "evicted other oldest, verifier c gone" idx m;
  (* Duplicate (same id, verifier and location) is ignored. *)
  I.add idx (entry ~verifier:"a" ~id:"e8" ~ts:(now +. 3.) ());
  Alcotest.(check int) "dup ignored" 5 (I.size idx);
  (* Expire drops stragglers that are not at the front. *)
  add (entry ~verifier:"d" ~id:"e9" ~ts:(now -. 1000.) ());
  check_aggregates "old straggler" idx m;
  I.expire idx ~now;
  Model.expire m ~now;
  check_aggregates "expired" idx m;
  Alcotest.(check bool) "straggler gone" true (I.find idx "e9" = None);
  I.expire idx ~now:(now +. 1000.);
  Model.expire m ~now:(now +. 1000.);
  check_aggregates "all expired" idx m;
  add (entry ~verifier:"z" ~id:"e10" ~ts:now ());
  check_aggregates "after empty" idx m

let random_ops () =
  let st = Random.State.make [| 42 |] in
  Hashtbl.reset seqs;
  let max = 400 and retention = 600. in
  let idx = I.create ~max_records:max ~retention_seconds:retention () in
  let m = Model.create ~max ~retention in
  for i = 1 to 3000 do
    let e = random_entry st i ~spread:400. in
    I.add idx e;
    Model.add m e;
    if i mod 97 = 0 then begin
      let at = now +. (float_of_int i *. 2.) in
      I.expire idx ~now:at;
      Model.expire m ~now:at
    end;
    if i mod 50 = 0 then begin
      let msg = Printf.sprintf "step %d" i in
      check_aggregates msg idx m;
      (* between vs brute force, including empty, inverted and unbounded ranges. *)
      for _ = 1 to 10 do
        let lo, hi =
          match (I.oldest idx, I.newest idx) with
          | Some a, Some b -> (a -. 100., b +. 100.)
          | _ -> (now, now +. 1.)
        in
        let since = lo +. Random.State.float st (hi -. lo) in
        let until =
          match Random.State.int st 6 with
          | 0 -> since -. 10.
          | 1 -> infinity
          | 2 -> since +. 60.
          | _ -> since +. Random.State.float st (hi -. lo)
        in
        let since = if Random.State.int st 10 = 0 then neg_infinity else since in
        Alcotest.(check (list string))
          (Printf.sprintf "%s between %.1f %.1f" msg since until)
          (ids (Model.between m ~since ~until))
          (ids (I.between idx ~since ~until))
      done;
      (* search with and without limit and time bounds; count. *)
      let at k = Some (now +. (float_of_int i *. k)) in
      let filters =
        [
          I.no_filter;
          { I.no_filter with outcome = Some Haltsql_report.Record.Denied };
          { I.no_filter with caller = Some "token:etl"; verifier = Some "b" };
          { I.no_filter with verifier = Some "nope" };
          { I.no_filter with since = at 1.5; until = at 1.9 };
          { I.no_filter with since = at 1.8 };
          {
            I.no_filter with
            until = at 1.7;
            outcome = Some Haltsql_report.Record.Allowed;
          };
          { I.no_filter with since = at 1.9; until = at 1.5 };
        ]
      in
      List.iteri
        (fun fi f ->
          let full = I.search idx f in
          Alcotest.(check (list string))
            (Printf.sprintf "%s search %d" msg fi)
            (ids (Model.search m f))
            (ids full);
          Alcotest.(check int)
            (Printf.sprintf "%s count %d" msg fi)
            (List.length full) (I.count idx f);
          List.iter
            (fun n ->
              Alcotest.(check (list string))
                (Printf.sprintf "%s search %d limit %d" msg fi n)
                (ids (List.filteri (fun j _ -> j < n) full))
                (ids (I.search ~limit:n idx f)))
            [ 0; 1; 7; 50; 10_000 ])
        filters;
      Array.iter
        (fun v ->
          Alcotest.(check (list string))
            (Printf.sprintf "%s stream %s" msg v)
            (ids (Model.stream m v))
            (ids (I.verifier_stream idx v)))
        verifier_names
    end
  done

let stream_order () =
  let idx = I.create () in
  let add v seq id =
    I.add idx (entry ~verifier:v ~seq ~id ~ts:(now +. float_of_int seq) ())
  in
  add "a" 0 "a0";
  add "b" 0 "b0";
  add "a" 1 "a1";
  add "a" 3 "a3";
  add "a" 2 "a2";
  add "b" 1 "b1";
  Alcotest.(check (list string))
    "a in seq order" [ "a0"; "a1"; "a2"; "a3" ]
    (ids (I.verifier_stream idx "a"));
  add "a" 4 "a4";
  Alcotest.(check (list string))
    "append after resort"
    [ "a0"; "a1"; "a2"; "a3"; "a4" ]
    (ids (I.verifier_stream idx "a"));
  Alcotest.(check (list string)) "b" [ "b0"; "b1" ] (ids (I.verifier_stream idx "b"));
  Alcotest.(check (list string)) "unknown" [] (ids (I.verifier_stream idx "x"))

let snapshot_restore () =
  let dir = temp_dir "console-index" in
  let path = Filename.concat dir "index.jsonl" in
  let idx = I.create () in
  for i = 0 to 9 do
    I.add idx
      (entry
         ~verifier:(if i mod 2 = 0 then "a" else "b")
         ~seq:i ~id:(Printf.sprintf "s%d" i)
         ~ts:(now -. float_of_int (i * 7))
         ~allowed:(i mod 3 <> 0)
         ())
  done;
  (* A record without ts keeps the one it was given at ingestion. *)
  let no_ts =
    match server_record ~request_id:"nots" () with
    | `Assoc l -> `Assoc (List.remove_assoc "ts" l)
    | j -> j
  in
  (match
     I.entry_of_json ~verifier:"p" ~location:"p.jsonl#L1" ~seq:0 ~now:(now -. 3.25) no_ts
   with
  | Some e -> I.add idx e
  | None -> ());
  let written = I.snapshot idx path in
  Alcotest.(check int) "written" (I.size idx) written;
  let idx2 = I.create () in
  Alcotest.(check int) "restored" written (I.restore idx2 path);
  let dump t =
    I.fold t ~init:[] ~f:(fun acc e ->
        let e : I.entry = e in
        Printf.sprintf "%s|%s|%s|%d|%.3f|%s|%s" e.request_id e.verifier e.location e.seq
          e.ts
          (Yojson.Safe.to_string (I.entry_to_json e))
          (Yojson.Safe.to_string e.raw)
        :: acc)
    |> List.rev
  in
  Alcotest.(check (list string)) "same entries" (dump idx) (dump idx2);
  Alcotest.check fopt "oldest" (I.oldest idx) (I.oldest idx2);
  Alcotest.check fopt "newest" (I.newest idx) (I.newest idx2);
  Alcotest.(check (list (pair string int)))
    "counts" (I.verifier_counts idx) (I.verifier_counts idx2);
  Alcotest.(check int) "restore again: all duplicates" 0 (I.restore idx2 path);
  Alcotest.(check int) "missing file" 0 (I.restore (I.create ()) (path ^ ".missing"));
  let oc = open_out_gen [ Open_append ] 0o600 path in
  output_string oc "not json\n{\"verifier\":\"a\"}\n";
  close_out oc;
  Alcotest.(check int) "malformed lines skipped" written (I.restore (I.create ()) path)

(* Not a benchmark: prints timings and only checks results, never durations. *)
let timing () =
  let n = 200_000 in
  let base = (Lazy.force bases).(0) in
  let idx = I.create () in
  let t0 = Unix.gettimeofday () in
  for i = 0 to n - 1 do
    I.add idx
      {
        base with
        I.request_id = Printf.sprintf "t%d" i;
        ts = now +. float_of_int i;
        seq = i;
        verifier = verifier_names.(i mod 4);
        location = Printf.sprintf "t#L%d" i;
      }
  done;
  let t1 = Unix.gettimeofday () in
  let r = I.between idx ~since:(now +. 100_000.) ~until:(now +. 100_060.) in
  let t2 = Unix.gettimeofday () in
  let page = I.search ~limit:50 idx I.no_filter in
  let t3 = Unix.gettimeofday () in
  Alcotest.(check int) "window" 60 (List.length r);
  Alcotest.(check int) "page" 50 (List.length page);
  Alcotest.(check (list string)) "verifiers" [ "a"; "b"; "c"; "d" ] (I.verifiers idx);
  Printf.printf "add %d: %.3fs; between 1 min: %.6fs; search limit 50: %.6fs\n" n
    (t1 -. t0) (t2 -. t1) (t3 -. t2)

let () =
  Alcotest.run "console-index"
    [
      ( "index",
        [
          Alcotest.test_case "aggregates through eviction and expire" `Quick aggregates;
          Alcotest.test_case "random ops vs brute force" `Quick random_ops;
          Alcotest.test_case "verifier stream order" `Quick stream_order;
          Alcotest.test_case "snapshot restore" `Quick snapshot_restore;
          Alcotest.test_case "200k timing sanity" `Quick timing;
        ] );
    ]
