(* `haltsql verify --batch --jobs N` throughput, and the cost of a single CLI
   invocation (process start, policy load, one verify). *)

let ( // ) = Filename.concat

let count_lines_with s needle =
  let n = ref 0 and lines = ref 0 in
  List.iter
    (fun l ->
      if l <> "" then (
        incr lines;
        let ln = String.length needle and ll = String.length l in
        let rec has i = i + ln <= ll && (String.sub l i ln = needle || has (i + 1)) in
        if has 0 then incr n))
    (String.split_on_char '\n' s);
  (!lines, !n)

let run ~root ~haltsql ~lines ~small =
  let dir = Procs.temp_dir "haltsql-bench-cli" in
  Fun.protect
    ~finally:(fun () -> Procs.rm_rf dir)
    (fun () ->
      let policy = Workloads.saas_policy_path root in
      let sqls = Array.of_list (Workloads.mix_sqls root) in
      let input = dir // "in.jsonl" and output = dir // "out.jsonl" in
      let b = Buffer.create (lines * 400) in
      for i = 0 to lines - 1 do
        Buffer.add_string b
          (Yojson.Safe.to_string
             (`Assoc
                [
                  ("id", `Int i);
                  ("sql", `String sqls.(i mod Array.length sqls));
                  ("context", `Assoc [ ("tenant_id", `String "acme") ]);
                ]));
        Buffer.add_char b '\n'
      done;
      Procs.write_file input (Buffer.contents b);
      let ncpu = Domain.recommended_domain_count () in
      let jobs =
        List.filter (fun j -> j <= ncpu) (if small then [ 1; 2 ] else [ 1; 2; 4; 8 ])
      in
      let reps = 3 in
      let batch =
        List.map
          (fun j ->
            let walls =
              Array.init reps (fun _ ->
                  let st, wall =
                    Procs.run_timed ~stdin:input ~stdout:output haltsql
                      [ "verify"; "-p"; policy; "--batch"; "--jobs"; string_of_int j ]
                  in
                  (* exit status: 0 when every line is allowed *)
                  if not (Procs.exited_ok st) then
                    failwith ("haltsql --batch: " ^ Procs.status_string st);
                  let got, allowed =
                    count_lines_with (Procs.read_file output) "\"allowed\":true"
                  in
                  if got <> lines || allowed <> lines then
                    failwith
                      (Printf.sprintf "haltsql --batch: %d lines, %d allowed, expected %d"
                         got allowed lines);
                  wall)
            in
            Array.sort Float.compare walls;
            let med = walls.(reps / 2) in
            let per_query_us =
              Array.map (fun w -> w /. float_of_int lines *. 1e6) walls
            in
            let r =
              Stats.summarize ~gate:(j = 1) ~suite:"cli"
                ~name:(Printf.sprintf "batch_jobs_%d" j)
                ~unit_:"us" ~wall:0.0
                ~extra:
                  [
                    ("lines", `Int lines);
                    ("jobs", `Int j);
                    ("runs", `Int reps);
                    ("median_wall_s", `Float med);
                  ]
                per_query_us
            in
            (* throughput of the median run, in verdicts per second *)
            { r with throughput = float_of_int lines /. med })
          jobs
      in
      let single =
        let q = sqls.(0) in
        let n = if small then 10 else 30 in
        let walls =
          Array.init n (fun _ ->
              let st, wall =
                Procs.run_timed haltsql
                  [ "verify"; "-p"; policy; "-c"; {|{"tenant_id":"acme"}|}; "--sql"; q ]
              in
              if not (Procs.exited_ok st) then
                failwith ("haltsql verify: " ^ Procs.status_string st);
              wall *. 1e3)
        in
        Stats.summarize ~suite:"cli" ~name:"single_invocation" ~unit_:"ms" ~wall:0.0
          ~extra:[ ("runs", `Int n) ]
          walls
      in
      batch @ [ single ])
