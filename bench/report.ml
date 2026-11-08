(* JSON and markdown output, host description, and the baseline regression check. *)

(* stdout of a command (stderr discarded), or None if it fails *)
let cmd_output c =
  try
    let r, w = Unix.pipe ~cloexec:true () in
    let null = Unix.openfile "/dev/null" [ O_RDWR ] 0 in
    let pid =
      Fun.protect
        ~finally:(fun () ->
          Unix.close w;
          Unix.close null)
        (fun () -> Unix.create_process c.(0) c null w null)
    in
    let ic = Unix.in_channel_of_descr r in
    let s = In_channel.input_all ic in
    close_in ic;
    match Procs.waitpid_eintr pid with WEXITED 0 -> Some (String.trim s) | _ -> None
  with _ -> None

let cpu_model () =
  match cmd_output [| "sysctl"; "-n"; "machdep.cpu.brand_string" |] with
  | Some s when s <> "" -> s
  | _ -> (
      try
        In_channel.with_open_text "/proc/cpuinfo" In_channel.input_all
        |> String.split_on_char '\n'
        |> List.find_map (fun l ->
            match String.index_opt l ':' with
            | Some i ->
                let k = String.trim (String.sub l 0 i) in
                if k = "model name" || k = "Model" then
                  Some (String.trim (String.sub l (i + 1) (String.length l - i - 1)))
                else None
            | None -> None)
        |> Option.value ~default:"unknown"
      with _ -> "unknown")

let mem_bytes () =
  match cmd_output [| "sysctl"; "-n"; "hw.memsize" |] with
  | Some s when int_of_string_opt s <> None -> int_of_string s
  | _ -> (
      try
        In_channel.with_open_text "/proc/meminfo" In_channel.input_all
        |> String.split_on_char '\n'
        |> List.find_map (fun l ->
            if String.length l > 9 && String.sub l 0 9 = "MemTotal:" then
              Scanf.sscanf_opt l "MemTotal: %d kB" (fun k -> k * 1024)
            else None)
        |> Option.value ~default:0
      with _ -> 0)

let load_average () =
  match cmd_output [| "sysctl"; "-n"; "vm.loadavg" |] with
  | Some s -> String.trim (String.map (function '{' | '}' -> ' ' | c -> c) s)
  | None -> (
      try
        In_channel.with_open_text "/proc/loadavg" In_channel.input_all
        |> String.split_on_char ' '
        |> List.filteri (fun i _ -> i < 3)
        |> String.concat " "
      with _ -> "unknown")

let host () =
  `Assoc
    [
      ("load_average_at_end", `String (load_average ()));
      ("os", `String (Option.value ~default:"unknown" (cmd_output [| "uname"; "-sr" |])));
      ("arch", `String (Option.value ~default:"unknown" (cmd_output [| "uname"; "-m" |])));
      ("cpu", `String (cpu_model ()));
      ("logical_cpus", `Int (Domain.recommended_domain_count ()));
      ("memory_bytes", `Int (mem_bytes ()));
      ("ocaml", `String Sys.ocaml_version);
    ]

let to_json ~config results =
  let tm = Unix.gmtime (Unix.time ()) in
  `Assoc
    [
      ("schema", `String "haltsql-bench/1");
      ("haltsql_version", `String Haltsql.version);
      ( "timestamp",
        `String
          (Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02dZ" (tm.tm_year + 1900)
             (tm.tm_mon + 1) tm.tm_mday tm.tm_hour tm.tm_min tm.tm_sec) );
      ("host", host ());
      ("config", config);
      ("results", `List (List.map Stats.to_json results));
    ]

let fmt v =
  if Float.is_nan v then "-"
  else if Float.abs v >= 100.0 then Printf.sprintf "%.0f" v
  else if Float.abs v >= 10.0 then Printf.sprintf "%.1f" v
  else Printf.sprintf "%.2f" v

let markdown results =
  let b = Buffer.create 4096 in
  let suites =
    List.fold_left
      (fun acc (r : Stats.result) ->
        if List.mem r.suite acc then acc else acc @ [ r.suite ])
      [] results
  in
  List.iter
    (fun s ->
      let rs = List.filter (fun (r : Stats.result) -> r.suite = s) results in
      Printf.bprintf b "### %s\n\n" s;
      Buffer.add_string b
        "| workload | unit | samples | p50 | p90 | p99 | p99.9 | max | ops/s | errors |\n\
         |---|---|---:|---:|---:|---:|---:|---:|---:|---:|\n";
      List.iter
        (fun (r : Stats.result) ->
          Printf.bprintf b "| %s | %s | %d | %s | %s | %s | %s | %s | %s | %d |\n" r.name
            r.unit_ r.samples (fmt r.p50) (fmt r.p90) (fmt r.p99) (fmt r.p999) (fmt r.max)
            (if Float.is_nan r.throughput then "-" else Printf.sprintf "%.0f" r.throughput)
            r.errors)
        rs;
      Buffer.add_char b '\n')
    suites;
  Buffer.contents b

(* Regression check against a committed baseline (bench/baseline/ci-small.json).

   Only results with gate=true are compared, on p50 (the most stable statistic on a
   shared CI runner). Absolute numbers from different machines are not comparable,
   so each p50 is first divided by a calibration time (a fixed CPU workload that
   does not exercise HaltSQL, see Lib_bench.calibration_once):

     ratio = (p50_now / calib_now) / (p50_base / calib_base)

   The calibration is the one measured next to that workload (the result's
   "calibration_ms": interleaved with the library loop, before/after the CLI and
   HTTP suites), so a busy or throttled machine slows both sides of the fraction.
   Results without it fall back to the run-level cpu_reference p50.

   The check fails when ratio > 1 + max_regress for any gated workload. The default
   max_regress is 1.5: only a slowdown of more than 2.5x fails. That is above the
   run-to-run and machine-to-machine noise of the normalized numbers measured while
   building this harness (up to ~1.3x between macOS and Linux on the same machine,
   more on a heavily loaded host) and still catches algorithmic regressions (an
   accidental quadratic pass, a lost cache, per-call policy recompilation).
   p50 values under 5 us are raised to 5 us on both sides to absorb timer noise. *)
let compare ~baseline_file ~max_regress results =
  let b = Yojson.Safe.from_file baseline_file in
  let open Yojson.Safe.Util in
  let rows = b |> member "results" |> to_list in
  let find suite name =
    List.find_opt
      (fun j -> member "suite" j = `String suite && member "name" j = `String name)
      rows
  in
  let calib_of_rows () =
    match find "calibration" "cpu_reference" with
    | Some j -> (
        match member "p50" j with
        | `Float f -> Some f
        | `Int i -> Some (float i)
        | _ -> None)
    | None -> None
  in
  let calib_now =
    List.find_map
      (fun (r : Stats.result) -> if r.suite = "calibration" then Some r.p50 else None)
      results
  in
  match (calib_of_rows (), calib_now) with
  | None, _ | _, None ->
      print_endline "baseline check: no calibration result on one side, cannot compare";
      false
  | Some cb, Some cn ->
      Printf.printf
        "baseline check against %s (calibration %.2f ms baseline, %.2f ms now)\n"
        baseline_file cb cn;
      let failed = ref false in
      List.iter
        (fun (r : Stats.result) ->
          if r.gate then
            match find r.suite r.name with
            | None -> Printf.printf "  %-36s no baseline entry\n" (Stats.key r)
            | Some j ->
                let num = function
                  | `Float f -> Some f
                  | `Int i -> Some (float i)
                  | _ -> None
                in
                let old = Option.value ~default:nan (num (member "p50" j)) in
                let cb, cn =
                  match
                    ( num (member "calibration_ms" j),
                      Option.bind (List.assoc_opt "calibration_ms" r.extra) num )
                  with
                  | Some b, Some n -> (b, n)
                  | _ -> (cb, cn)
                in
                let ratio = Float.max 5.0 r.p50 /. cn /. (Float.max 5.0 old /. cb) in
                let bad = ratio > 1.0 +. max_regress in
                if bad then failed := true;
                Printf.printf "  %-36s p50 %9s -> %9s %s  normalized x%.2f%s\n"
                  (Stats.key r) (fmt old) (fmt r.p50) r.unit_ ratio
                  (if bad then "  REGRESSION" else ""))
        results;
      not !failed
