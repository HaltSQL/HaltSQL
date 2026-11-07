(* Attack-corpus and conformance runner.

   Discovers every [*.suite.yaml], [*.suite.yml] and [*.suite.json] file under
   [<root>/corpus] and [<root>/conformance] (recursively), runs each through
   [Haltsql.Suite_runner.run_file ~verify:Haltsql.verify], prints a
   per-threat-class summary table, and then reports one Alcotest case per
   corpus case (group = suite file, case = case name).

   Usage: corpus.exe [--root DIR] [--summary-only] [-- ALCOTEST-ARGS...]

   Environment:
   - HALTSQL_TEST_ROOT      root directory (default ".."; overridden by --root)
   - HALTSQL_CORPUS_FILTER  only run suite files whose path contains this string
   - HALTSQL_CORPUS_REPORT_ONLY=1  print the summary and exit 0 even on failures
   - HALTSQL_CORPUS_JSON=FILE      also write a machine-readable summary *)

open Haltsql

let ( // ) = Filename.concat

let rec walk dir =
  match Sys.readdir dir with
  | exception Sys_error _ -> []
  | entries ->
      Array.sort compare entries;
      Array.to_list entries
      |> List.concat_map (fun e ->
          let p = dir // e in
          if Sys.is_directory p then walk p
          else if
            List.exists
              (fun suf -> Filename.check_suffix e suf)
              [ ".suite.yaml"; ".suite.yml"; ".suite.json" ]
          then [ p ]
          else [])

let rel root p =
  let r = root ^ Filename.dir_sep in
  let lr = String.length r in
  if String.length p > lr && String.sub p 0 lr = r then
    String.sub p lr (String.length p - lr)
  else p

(* Threat class of a case: its first tag, else the suite file stem. *)
let threat_class file (c : Test_suite.case) =
  match c.tags with
  | t :: _ -> t
  | [] -> (
      let b = Filename.basename file in
      match String.index_opt b '.' with Some i -> String.sub b 0 i | None -> b)

type outcome = Load_failed of string | Ran of Suite_runner.result

let load_errors_to_string es = String.concat "\n" (List.map Load_error.to_string es)

let codes_of (v : Verdict.t) =
  List.map
    (fun (r : Reason.t) -> Reason.code_to_string r.code)
    (v.reasons @ v.shadow_reasons)

(* Failure classification used in the summary: helps tell "module still a
   stub" apart from real disagreements. *)
let failure_kind (r : Suite_runner.case_result) =
  let codes = codes_of r.verdict in
  if List.mem "E_INTERNAL" codes then `Internal else `Mismatch

let () =
  let root = ref (Option.value (Sys.getenv_opt "HALTSQL_TEST_ROOT") ~default:"..") in
  let summary_only = ref false in
  let rest = ref [] in
  let rec parse = function
    | "--root" :: d :: tl ->
        root := d;
        parse tl
    | "--summary-only" :: tl ->
        summary_only := true;
        parse tl
    | "--" :: tl -> rest := tl
    | x :: tl ->
        rest := !rest @ [ x ];
        parse tl
    | [] -> ()
  in
  parse (List.tl (Array.to_list Sys.argv));
  let root = !root in
  let filter = Sys.getenv_opt "HALTSQL_CORPUS_FILTER" in
  let files =
    walk (root // "corpus") @ walk (root // "conformance")
    |> List.filter (fun f ->
        match filter with
        | None | Some "" -> true
        | Some s ->
            let ls = String.length s and lf = String.length f in
            let rec has i = i + ls <= lf && (String.sub f i ls = s || has (i + 1)) in
            has 0)
  in
  if files = [] then (
    Printf.eprintf "corpus: no suite files found under %s/{corpus,conformance}\n" root;
    exit 2);
  let outcomes =
    List.map
      (fun f ->
        let o =
          match Suite_runner.run_file ~verify:Haltsql.verify f with
          | Ok r -> Ran r
          | Error es -> Load_failed (load_errors_to_string es)
          | exception e -> Load_failed ("exception: " ^ Printexc.to_string e)
        in
        (rel root f, o))
      files
  in
  (* ---- per-threat-class summary ---- *)
  let tbl : (string, int ref * int ref * int ref * int ref) Hashtbl.t =
    Hashtbl.create 64
  in
  let get k =
    match Hashtbl.find_opt tbl k with
    | Some v -> v
    | None ->
        let v = (ref 0, ref 0, ref 0, ref 0) in
        Hashtbl.add tbl k v;
        v
  in
  let load_failures = ref [] in
  List.iter
    (fun (f, o) ->
      match o with
      | Load_failed msg -> load_failures := (f, msg) :: !load_failures
      | Ran r ->
          List.iter
            (fun (cr : Suite_runner.case_result) ->
              let total, passed, internal, mismatch = get (threat_class f cr.case) in
              incr total;
              if cr.passed then incr passed
              else
                match failure_kind cr with
                | `Internal -> incr internal
                | `Mismatch -> incr mismatch)
            r.results)
    outcomes;
  let classes = Hashtbl.fold (fun k v acc -> (k, v) :: acc) tbl [] |> List.sort compare in
  let sum f = List.fold_left (fun a (_, v) -> a + f v) 0 classes in
  let t_total = sum (fun (t, _, _, _) -> !t)
  and t_pass = sum (fun (_, p, _, _) -> !p)
  and t_int = sum (fun (_, _, i, _) -> !i)
  and t_mis = sum (fun (_, _, _, m) -> !m) in
  Printf.printf "\nHaltSQL corpus summary (%d suite files under %s)\n" (List.length files)
    root;
  Printf.printf "%-36s %6s %6s %6s %9s %9s\n" "threat class" "cases" "pass" "fail"
    "internal" "mismatch";
  Printf.printf "%s\n" (String.make 78 '-');
  List.iter
    (fun (k, (t, p, i, m)) ->
      Printf.printf "%-36s %6d %6d %6d %9d %9d\n" k !t !p (!t - !p) !i !m)
    classes;
  Printf.printf "%s\n" (String.make 78 '-');
  Printf.printf "%-36s %6d %6d %6d %9d %9d\n" "TOTAL" t_total t_pass (t_total - t_pass)
    t_int t_mis;
  Printf.printf
    "(internal = denied with E_INTERNAL, usually an unimplemented module; mismatch = \
     real disagreement)\n";
  if !load_failures <> [] then begin
    Printf.printf "\n%d suite file(s) failed to load:\n" (List.length !load_failures);
    List.iter
      (fun (f, m) ->
        let first =
          match String.index_opt m '\n' with Some i -> String.sub m 0 i | None -> m
        in
        Printf.printf "  %s: %s\n" f first)
      (List.rev !load_failures)
  end;
  flush stdout;
  (match Sys.getenv_opt "HALTSQL_CORPUS_JSON" with
  | Some out when out <> "" ->
      let j =
        `Assoc
          [
            ("total", `Int t_total);
            ("passed", `Int t_pass);
            ("internal", `Int t_int);
            ("mismatch", `Int t_mis);
            ( "classes",
              `Assoc
                (List.map
                   (fun (k, (t, p, i, m)) ->
                     ( k,
                       `Assoc
                         [
                           ("cases", `Int !t);
                           ("passed", `Int !p);
                           ("internal", `Int !i);
                           ("mismatch", `Int !m);
                         ] ))
                   classes) );
            ( "load_failures",
              `List
                (List.map
                   (fun (f, m) -> `Assoc [ ("file", `String f); ("error", `String m) ])
                   (List.rev !load_failures)) );
            ( "failures",
              `List
                (List.concat_map
                   (fun (f, o) ->
                     match o with
                     | Load_failed _ -> []
                     | Ran r ->
                         List.filter_map
                           (fun (cr : Suite_runner.case_result) ->
                             if cr.passed then None
                             else
                               Some
                                 (`Assoc
                                    [
                                      ("file", `String f);
                                      ("case", `String cr.case.case_name);
                                      ("sql", `String cr.case.sql);
                                      ( "failure",
                                        `String (Option.value cr.failure ~default:"") );
                                    ]))
                           r.results)
                   outcomes) );
          ]
      in
      Yojson.Safe.to_file out j
  | _ -> ());
  let report_only = Sys.getenv_opt "HALTSQL_CORPUS_REPORT_ONLY" = Some "1" in
  if !summary_only || report_only then exit 0;
  (* ---- one alcotest case per corpus case ---- *)
  let tests =
    List.map
      (fun (f, o) ->
        match o with
        | Load_failed msg ->
            (f, [ Alcotest.test_case "load suite" `Quick (fun () -> Alcotest.fail msg) ])
        | Ran r ->
            let seen = Hashtbl.create 64 in
            ( f,
              List.map
                (fun (cr : Suite_runner.case_result) ->
                  let base = cr.case.case_name in
                  let n = try Hashtbl.find seen base with Not_found -> 0 in
                  Hashtbl.replace seen base (n + 1);
                  let name =
                    if n = 0 then base else Printf.sprintf "%s (%d)" base (n + 1)
                  in
                  Alcotest.test_case name `Quick (fun () ->
                      match cr.failure with
                      | None -> ()
                      | Some why ->
                          Alcotest.failf "%s\n  sql: %s\n  verdict: %s" why cr.case.sql
                            (Yojson.Safe.to_string
                               (Verdict.to_json { cr.verdict with elapsed_us = 0 }))))
                r.results ))
      outcomes
  in
  Alcotest.run ~argv:(Array.of_list ("corpus" :: !rest)) "haltsql-corpus" tests
