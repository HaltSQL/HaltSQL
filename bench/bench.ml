(* Verify latency benchmark.

   Workloads:
   - benign: every case of test/corpus/benign_analytics.suite.yaml against
     the saas fixture policy (the realistic, allowed path);
   - attack: every other corpus case run against its own policy (mostly
     denials, exercising early exits);
   - pathological: huge IN lists, deep nesting, 50-way joins, long
     identifiers, a query just under max_bytes (PLAN.md §8.6).

   Reports p50/p95/p99/max latency in microseconds and throughput per
   workload. [--json FILE] writes the numbers; [--baseline FILE] compares p99
   with a previous JSON run and exits 1 if any workload regressed by more
   than [--max-regress] (default 0.10, i.e. 10%; workloads whose baseline p99
   is under 20 us are compared with a 20 us floor to absorb timer noise). *)

open Haltsql

let ( // ) = Filename.concat
let root = ref "."
let iters = ref 2000
let json_out = ref None
let baseline = ref None
let max_regress = ref 0.10

let () =
  let rec go = function
    | "--root" :: d :: tl ->
        root := d;
        go tl
    | "--iters" :: n :: tl ->
        iters := int_of_string n;
        go tl
    | "--json" :: f :: tl ->
        json_out := Some f;
        go tl
    | "--baseline" :: f :: tl ->
        baseline := Some f;
        go tl
    | "--max-regress" :: x :: tl ->
        max_regress := float_of_string x;
        go tl
    | x :: _ ->
        Printf.eprintf "bench: unknown argument %s\n" x;
        exit 2
    | [] -> ()
  in
  go (List.tl (Array.to_list Sys.argv))

let load_policy f =
  match Policy_load.of_file f with
  | Ok p -> p
  | Error es -> failwith (String.concat "\n" (f :: List.map Load_error.to_string es))

let suite f =
  match Test_suite.of_file f with
  | Ok s -> s
  | Error es -> failwith (String.concat "\n" (f :: List.map Load_error.to_string es))

let acme = Context.make [ ("tenant_id", Context.One "acme") ]

type workload = { wname : string; items : (Policy.t * Context.t * string) array }

let percentile sorted p =
  let n = Array.length sorted in
  if n = 0 then 0.0 else sorted.(min (n - 1) (int_of_float (Float.of_int n *. p)))

let run w =
  let n = Array.length w.items in
  (* warm-up *)
  for i = 0 to min (n * 2) 500 do
    let p, c, s = w.items.(i mod n) in
    ignore (Haltsql.verify p c s)
  done;
  let total = max !iters n in
  let lat = Array.make total 0.0 in
  let t_start = Unix.gettimeofday () in
  for i = 0 to total - 1 do
    let p, c, s = w.items.(i mod n) in
    let t0 = Unix.gettimeofday () in
    ignore (Sys.opaque_identity (Haltsql.verify p c s));
    lat.(i) <- (Unix.gettimeofday () -. t0) *. 1e6
  done;
  let wall = Unix.gettimeofday () -. t_start in
  Array.sort compare lat;
  let r =
    [
      ("queries", float_of_int n);
      ("calls", float_of_int total);
      ("p50_us", percentile lat 0.50);
      ("p95_us", percentile lat 0.95);
      ("p99_us", percentile lat 0.99);
      ("max_us", lat.(total - 1));
      ("throughput_per_s", float_of_int total /. wall);
    ]
  in
  Printf.printf "%-14s %7d %8d %9.1f %9.1f %9.1f %10.1f %12.0f\n%!" w.wname n total
    (List.assoc "p50_us" r) (List.assoc "p95_us" r) (List.assoc "p99_us" r)
    (List.assoc "max_us" r)
    (List.assoc "throughput_per_s" r);
  (w.wname, r)

let () =
  let corpus = !root // "test/corpus" and fixtures = !root // "test/fixtures/policies" in
  let saas = load_policy (fixtures // "saas.yaml") in
  let benign =
    let s = suite (corpus // "benign_analytics.suite.yaml") in
    Array.of_list
      (List.map (fun (c : Test_suite.case) -> (saas, c.context, c.sql)) s.cases)
  in
  let attack =
    Sys.readdir corpus |> Array.to_list |> List.sort compare
    |> List.filter (fun f ->
        Filename.check_suffix f ".suite.yaml" && f <> "benign_analytics.suite.yaml")
    |> List.concat_map (fun f ->
        match Test_suite.of_file (corpus // f) with
        | Error _ -> []
        | Ok s -> (
            match Policy_load.of_file s.policy_path with
            | Error _ -> []
            | Ok p ->
                List.map (fun (c : Test_suite.case) -> (p, c.context, c.sql)) s.cases))
    |> Array.of_list
  in
  let in_list n = String.concat ", " (List.init n string_of_int) in
  let nest n =
    String.concat "" (List.init n (fun _ -> "(1 + ")) ^ "1" ^ String.make n ')'
  in
  let joins n =
    "SELECT t0.id FROM orders t0"
    ^ String.concat ""
        (List.init n (fun i ->
             Printf.sprintf " JOIN orders t%d ON t%d.tenant_id = $1 AND t%d.id = t0.id"
               (i + 1) (i + 1) (i + 1)))
    ^ " WHERE t0.tenant_id = $1 LIMIT 10"
  in
  let near_limit =
    (* a realistic query padded with filtered OR-free conjuncts to ~15 KB *)
    let b = Buffer.create 16000 in
    Buffer.add_string b "SELECT o.id, o.status FROM orders o WHERE o.tenant_id = $1";
    let i = ref 0 in
    while Buffer.length b < 15_500 do
      Buffer.add_string b (Printf.sprintf " AND o.total_cents <> %d" !i);
      incr i
    done;
    Buffer.add_string b " LIMIT 10";
    Buffer.contents b
  in
  let patho =
    [
      "SELECT id FROM orders WHERE tenant_id = $1 AND id IN (" ^ in_list 10_000
      ^ ") LIMIT 10";
      "SELECT id FROM orders WHERE tenant_id = $1 AND id IN (" ^ in_list 2_500
      ^ ") LIMIT 10";
      "SELECT " ^ nest 30 ^ " AS x FROM orders WHERE tenant_id = $1 LIMIT 1";
      "SELECT " ^ nest 500 ^ " AS x FROM orders WHERE tenant_id = $1 LIMIT 1";
      joins 50;
      joins 6;
      "SELECT o.id AS " ^ String.make 63 'x'
      ^ " FROM orders o WHERE o.tenant_id = $1 LIMIT 1";
      "SELECT o.id FROM orders " ^ String.make 4000 'a' ^ " WHERE tenant_id = $1 LIMIT 1";
      near_limit;
      String.concat " UNION ALL "
        (List.init 100 (fun _ -> "SELECT id FROM orders WHERE tenant_id = $1"))
      ^ " LIMIT 10";
    ]
    |> List.map (fun s -> (saas, acme, s))
    |> Array.of_list
  in
  Printf.printf "haltsql bench (iters per workload >= %d)\n" !iters;
  Printf.printf "%-14s %7s %8s %9s %9s %9s %10s %12s\n" "workload" "queries" "calls"
    "p50_us" "p95_us" "p99_us" "max_us" "verify/s";
  let results =
    List.map run
      (List.filter
         (fun w -> Array.length w.items > 0)
         [
           { wname = "benign"; items = benign };
           { wname = "attack"; items = attack };
           { wname = "pathological"; items = patho };
         ])
  in
  let to_json rs =
    `Assoc
      [
        ("haltsql_version", `String Haltsql.version);
        ( "workloads",
          `Assoc
            (List.map
               (fun (n, r) -> (n, `Assoc (List.map (fun (k, v) -> (k, `Float v)) r)))
               rs) );
      ]
  in
  (* per-query breakdown of the pathological inputs *)
  Printf.printf "\npathological breakdown (median of 50 runs):\n";
  Array.iter
    (fun (p, c, sql) ->
      let ts =
        Array.init 50 (fun _ ->
            let t0 = Unix.gettimeofday () in
            let v = Haltsql.verify p c sql in
            ignore (Sys.opaque_identity v);
            (Unix.gettimeofday () -. t0) *. 1e6)
      in
      Array.sort compare ts;
      let v = Haltsql.verify p c sql in
      let codes =
        String.concat ","
          (List.map (fun (r : Reason.t) -> Reason.code_to_string r.code) v.reasons)
      in
      let label = if String.length sql > 60 then String.sub sql 0 60 ^ "..." else sql in
      Printf.printf "  %9.1f us  %6d B  %-20s %s\n" ts.(25) (String.length sql)
        (if codes = "" then "allowed" else codes)
        label)
    patho;
  (match !json_out with Some f -> Yojson.Safe.to_file f (to_json results) | None -> ());
  match !baseline with
  | None -> ()
  | Some f ->
      let b = Yojson.Safe.from_file f in
      let failed = ref false in
      List.iter
        (fun (n, r) ->
          match
            try Yojson.Safe.Util.(b |> member "workloads" |> member n |> member "p99_us")
            with _ -> `Null
          with
          | `Float old ->
              let now = List.assoc "p99_us" r in
              let base = Float.max old 20.0 in
              let ratio = now /. base in
              Printf.printf "regression check %-14s p99 %.1f -> %.1f us (x%.2f)\n" n old
                now ratio;
              if ratio > 1.0 +. !max_regress then failed := true
          | _ -> Printf.printf "regression check %-14s: no baseline\n" n)
        results;
      if !failed then (
        print_endline "bench: p99 regression above threshold";
        exit 1)
