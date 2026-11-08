(* In-process Haltsql.verify latency: one call at a time on one domain, cycling
   through the workload's queries. *)

open Workloads

(* A fixed CPU workload that does not depend on HaltSQL's code: SHA-256 of 64 KiB
   (C), sorting pseudo-random ints and hashing short strings (OCaml allocation and
   GC). Used to normalize the CI regression check across machines and load levels:
   gated metrics are compared as (metric / calibration), see Report.compare.
   [calibration_once ~scale ()] runs [scale] of the full workload and returns the
   time scaled back to the full workload, in milliseconds. *)
let calib_buf = lazy (String.init 65536 (fun i -> Char.chr (i land 0xff)))

let calibration_once ?(scale = 1.0) () =
  let buf = Lazy.force calib_buf in
  let k n = max 1 (int_of_float (float_of_int n *. scale)) in
  let t0 = Stats.now () in
  for _ = 1 to k 40 do
    ignore (Sys.opaque_identity (Digestif.SHA256.digest_string buf))
  done;
  let st = Random.State.make [| 42 |] in
  let a = Array.init (k 200_000) (fun _ -> Random.State.bits st) in
  Array.sort compare a;
  let h = Hashtbl.create 1024 in
  for i = 0 to k 100_000 - 1 do
    let key = "key_" ^ string_of_int (i * 7919 mod 50_000) in
    Hashtbl.replace h key (String.length key + i)
  done;
  ignore (Sys.opaque_identity (a, h));
  (Stats.now () -. t0) *. 1e3 /. scale

let median a =
  let a = Array.copy a in
  Array.sort Float.compare a;
  a.(Array.length a / 2)

(* The run-level calibration result (7 full runs). *)
let calibration () =
  ignore (calibration_once ());
  let runs = Array.init 7 (fun _ -> calibration_once ()) in
  Stats.summarize ~suite:"calibration" ~name:"cpu_reference" ~unit_:"ms" ~wall:0.0 runs

let run_workload ~iters ~gate (w : workload) =
  let n = Array.length w.items in
  let warm = min (max (n * 3) 200) 2000 in
  for i = 0 to warm - 1 do
    let it = w.items.(i mod n) in
    ignore (Sys.opaque_identity (Haltsql.verify it.policy it.context it.sql))
  done;
  let total = max iters n in
  let lat = Array.make total 0.0 in
  (* the timed loop is split into chunks with a short calibration run before each
     one and after the last, so the normalization sees the same machine state (load,
     CPU frequency, core type) as the measurement *)
  let chunks = 8 in
  let calib = Array.make (chunks + 1) 0.0 in
  let calib_time = ref 0.0 in
  let t_start = Stats.now () in
  for c = 0 to chunks - 1 do
    let tc = Stats.now () in
    calib.(c) <- calibration_once ~scale:0.25 ();
    calib_time := !calib_time +. (Stats.now () -. tc);
    for i = c * total / chunks to ((c + 1) * total / chunks) - 1 do
      let it = w.items.(i mod n) in
      let t0 = Stats.now () in
      ignore (Sys.opaque_identity (Haltsql.verify it.policy it.context it.sql));
      lat.(i) <- (Stats.now () -. t0) *. 1e6
    done
  done;
  calib.(chunks) <- calibration_once ~scale:0.25 ();
  let wall = Stats.now () -. t_start -. !calib_time in
  let sizes = Array.map (fun it -> String.length it.sql) w.items in
  Array.sort compare sizes;
  Stats.summarize ~gate ~suite:"library" ~name:w.wname ~unit_:"us" ~wall
    ~extra:
      [
        ("queries", `Int n);
        ("median_sql_bytes", `Int sizes.(n / 2));
        ("max_sql_bytes", `Int sizes.(n - 1));
        ("calibration_ms", `Float (median calib));
      ]
    lat

let run ~root ~iters ~small =
  let tiers = tiers root in
  let ws =
    List.map (fun w -> (w, true)) tiers
    @ [ (benign root, true); (attack root, false) ]
    @ if small then [] else [ (pathological root, false) ]
  in
  List.iter (fun (w, _) -> check w) ws;
  let iters_for (w : workload) =
    (* the pathological inputs take milliseconds each *)
    if w.wname = "pathological" then max 200 (iters / 20) else iters
  in
  List.filter_map
    (fun ((w : workload), gate) ->
      if Array.length w.items = 0 then None
      else Some (run_workload ~iters:(iters_for w) ~gate w))
    ws
