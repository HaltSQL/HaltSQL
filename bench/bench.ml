(* HaltSQL benchmark harness.

   Suites (select with --suite, comma separated; default all):
   - library  in-process Haltsql.verify latency per workload (complexity tiers t1..t5,
              the benign and attack corpora, pathological inputs);
   - cli      `haltsql verify --batch --jobs N` throughput, single-invocation cost;
   - http     haltsql-server POST /v1/verify latency under 1..128 concurrent
              keep-alive connections (built-in closed-loop load generator);
   - proxy    haltsql-proxy added latency versus direct PostgreSQL (needs a reachable
              Postgres; skipped with a message otherwise).

   Every run also measures a fixed CPU calibration workload used to normalize the
   baseline comparison. Output: a markdown table on stdout (and --markdown FILE) and
   machine-readable JSON (--json FILE, schema "haltsql-bench/1"). --baseline FILE
   compares gated p50 values with a previous JSON run (see Report.compare) and exits 1
   on a regression above --max-regress (default 1.5, i.e. more than 2.5x slower). Any
   failed request or wrong verdict also exits 1.

   Typical use (scripts/bench.sh wraps this):
     bench.exe --root . --haltsql BIN --server BIN --proxy BIN --json out.json
     bench.exe --root . --small --suite library,cli,http \
       --baseline bench/baseline/ci-small.json *)

let root = ref "."
let suites = ref [ "library"; "cli"; "http"; "proxy" ]
let small = ref false
let iters = ref 0
let lines = ref 0
let haltsql = ref None
let server = ref None
let proxy = ref None
let pg_host = ref "127.0.0.1"
let pg_port = ref 5417
let pg_user = ref "postgres"
let json_out = ref None
let md_out = ref None
let baseline = ref None
let max_regress = ref 1.5

let usage () =
  prerr_endline
    "usage: bench.exe [--root DIR] [--suite library,cli,http,proxy] [--small]\n\
    \  [--iters N] [--lines N] [--haltsql BIN] [--server BIN] [--proxy BIN]\n\
    \  [--pg-host H] [--pg-port P] [--pg-user U] (password: HALTSQL_PGPASSWORD)\n\
    \  [--json FILE] [--markdown FILE] [--baseline FILE] [--max-regress X]";
  exit 2

let () =
  let rec go = function
    | "--root" :: d :: tl ->
        root := d;
        go tl
    | "--suite" :: s :: tl ->
        suites := if s = "all" then !suites else String.split_on_char ',' s;
        go tl
    | "--small" :: tl ->
        small := true;
        go tl
    | "--iters" :: n :: tl ->
        iters := int_of_string n;
        go tl
    | "--lines" :: n :: tl ->
        lines := int_of_string n;
        go tl
    | "--haltsql" :: f :: tl ->
        haltsql := Some f;
        go tl
    | "--server" :: f :: tl ->
        server := Some f;
        go tl
    | "--proxy" :: f :: tl ->
        proxy := Some f;
        go tl
    | "--pg-host" :: h :: tl ->
        pg_host := h;
        go tl
    | "--pg-port" :: p :: tl ->
        pg_port := int_of_string p;
        go tl
    | "--pg-user" :: u :: tl ->
        pg_user := u;
        go tl
    | "--json" :: f :: tl ->
        json_out := Some f;
        go tl
    | "--markdown" :: f :: tl ->
        md_out := Some f;
        go tl
    | "--baseline" :: f :: tl ->
        baseline := Some f;
        go tl
    | "--max-regress" :: x :: tl ->
        max_regress := float_of_string x;
        go tl
    | ("-h" | "--help") :: _ -> usage ()
    | x :: _ ->
        Printf.eprintf "bench: unknown argument %s\n" x;
        usage ()
    | [] -> ()
  in
  go (List.tl (Array.to_list Sys.argv));
  List.iter
    (fun s ->
      if not (List.mem s [ "library"; "cli"; "http"; "proxy" ]) then (
        Printf.eprintf "bench: unknown suite %s\n" s;
        exit 2))
    !suites

let absolute p = if Filename.is_relative p then Filename.concat (Sys.getcwd ()) p else p

let need name = function
  | Some f when Sys.file_exists f -> absolute f
  | Some f ->
      Printf.eprintf "bench: %s binary %s does not exist\n" name f;
      exit 2
  | None ->
      Printf.eprintf "bench: suite needs --%s BIN\n" name;
      exit 2

let () =
  Random.self_init ();
  let root = absolute !root in
  let iters = if !iters > 0 then !iters else if !small then 2000 else 20000 in
  let lines = if !lines > 0 then !lines else if !small then 8000 else 24000 in
  let on s = List.mem s !suites in
  let section name f =
    Printf.printf "== %s\n%!" name;
    let t0 = Stats.now () in
    let r = f () in
    Printf.printf "   (%.1f s)\n%!" (Stats.now () -. t0);
    r
  in
  (* Suites without their own interleaved calibration get the median of short
     calibration runs taken right before and after them (see Report.compare). *)
  let calibrated f () =
    let c0 = Array.init 3 (fun _ -> Lib_bench.calibration_once ~scale:0.25 ()) in
    let rs = f () in
    let c1 = Array.init 3 (fun _ -> Lib_bench.calibration_once ~scale:0.25 ()) in
    let c = Lib_bench.median (Array.append c0 c1) in
    List.map
      (fun (r : Stats.result) ->
        if List.mem_assoc "calibration_ms" r.extra then r
        else { r with extra = r.extra @ [ ("calibration_ms", `Float c) ] })
      rs
  in
  let load_start = Report.load_average () in
  Printf.printf "load average at start (1/5/15 min): %s\n%!" load_start;
  let calib = section "calibration" Lib_bench.calibration in
  (* sequenced explicitly: the proxy suite runs an Lwt loop in this process, and the
     HTTP suite forks workers, so the order matters *)
  let lib =
    if on "library" then
      section "library" (fun () -> Lib_bench.run ~root ~iters ~small:!small)
    else []
  in
  let cli =
    if on "cli" then
      let haltsql = need "haltsql" !haltsql in
      section "cli"
        (calibrated (fun () -> Cli_bench.run ~root ~haltsql ~lines ~small:!small))
    else []
  in
  let http =
    if on "http" then
      let server = need "server" !server in
      section "http" (calibrated (fun () -> Http_bench.run ~root ~server ~small:!small))
    else []
  in
  let prox =
    if on "proxy" then
      let proxy = need "proxy" !proxy in
      let pg : Proxy_bench.target =
        {
          host = !pg_host;
          port = !pg_port;
          user = !pg_user;
          password = Option.value ~default:"haltlab" (Sys.getenv_opt "HALTSQL_PGPASSWORD");
        }
      in
      section "proxy" (fun () -> Proxy_bench.run ~root ~proxy ~pg ~small:!small)
    else []
  in
  let results = (calib :: lib) @ cli @ http @ prox in
  let md = Report.markdown results in
  print_string ("\n" ^ md);
  let config =
    `Assoc
      [
        ("suites", `List (List.map (fun s -> `String s) !suites));
        ("small", `Bool !small);
        ("library_iters", `Int iters);
        ("cli_lines", `Int lines);
        ("load_average_at_start", `String load_start);
      ]
  in
  Option.iter (fun f -> Yojson.Safe.to_file f (Report.to_json ~config results)) !json_out;
  Option.iter (fun f -> Procs.write_file f md) !md_out;
  let errors = List.fold_left (fun a (r : Stats.result) -> a + r.errors) 0 results in
  let ok_baseline =
    match !baseline with
    | None -> true
    | Some f -> Report.compare ~baseline_file:f ~max_regress:!max_regress results
  in
  if errors > 0 then Printf.printf "bench: %d failed operations\n" errors;
  if not ok_baseline then print_endline "bench: regression above threshold";
  if errors > 0 || not ok_baseline then exit 1
