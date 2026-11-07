(* Mutation fuzzer (PLAN.md §8.1 "Fuzzing"; AFL/Crowbar are not available).

   Seeds: every SQL string in the attack corpus and conformance suites, plus
   the text of every policy / suite / catalog document. Each iteration picks a
   seed, applies 1-8 random mutations (bit flips, byte insert/delete, chunk
   duplication, splicing with another seed, SQL-token insertion, truncation,
   deep-nesting amplification) and checks:

   - Haltsql.verify never raises; a denial carries >= 1 reason, every code is
     in Reason.all_codes, and the code is never E_INTERNAL (an analyzer bug);
     an allowed verdict has no reasons; a single verify takes < 2 s.
   - Docload.of_string (YAML and JSON) and Policy_load.of_string never raise.

   Any violation is minimized (greedy chunk removal while the failure
   persists) and written to test/fuzz/crashes/<kind>-<sha>.txt.

   Environment: HALTSQL_FUZZ_ITERS (default 3000), HALTSQL_FUZZ_SEED (default
   1), HALTSQL_FUZZ_CRASH_DIR (default: <source>/test/fuzz/crashes when run
   under dune, else ./crashes). Exit code 1 if anything was found. *)

open Haltsql

let ( // ) = Filename.concat

let rec walk dir =
  match Sys.readdir dir with
  | exception Sys_error _ -> []
  | es ->
      Array.sort compare es;
      Array.to_list es
      |> List.concat_map (fun e ->
          let p = dir // e in
          if Sys.is_directory p then walk p else [ p ])

let read_file f =
  let ic = open_in_bin f in
  let s = really_input_string ic (in_channel_length ic) in
  close_in ic;
  s

let ends_with s suf =
  let ls = String.length s and lf = String.length suf in
  ls >= lf && String.sub s (ls - lf) lf = suf

let iters =
  match Option.bind (Sys.getenv_opt "HALTSQL_FUZZ_ITERS") int_of_string_opt with
  | Some n when n > 0 -> n
  | _ -> 3000

let seed =
  match Option.bind (Sys.getenv_opt "HALTSQL_FUZZ_SEED") int_of_string_opt with
  | Some n -> n
  | None -> 1

let crash_dir () =
  match Sys.getenv_opt "HALTSQL_FUZZ_CRASH_DIR" with
  | Some d -> d
  | None -> (
      match Sys.getenv_opt "DUNE_SOURCEROOT" with
      | Some r -> r // "test/fuzz/crashes"
      | None -> "crashes")

let tokens =
  [|
    " SELECT ";
    " FROM ";
    " WHERE ";
    " AND ";
    " OR ";
    " NOT ";
    " UNION ALL ";
    " WITH ";
    " LATERAL ";
    " JOIN ";
    " ON ";
    " LIMIT ";
    " ( ";
    " ) ";
    ",";
    ";";
    "*";
    " = ";
    "::";
    "::regclass";
    "$1";
    "$2";
    "$0";
    "$2147483648";
    "'";
    "\"";
    "$$";
    "$a$";
    "--";
    "/*";
    "*/";
    "E'\\\\";
    "U&\"";
    "\\";
    "\x00";
    "\xff\xfe";
    "\xc3\x28";
    "\n";
    "\t";
    " pg_sleep(1) ";
    " (SELECT 1) ";
    " EXISTS (SELECT 1) ";
    " tenant_id ";
    " orders ";
    " customers c ";
    " ARRAY[1,2] ";
    "[1]";
    ".*";
    " ROW(";
    " CASE WHEN true THEN 1 END ";
    " IS NULL ";
    " COLLATE \"C\" ";
    " FOR UPDATE ";
    " INTO t ";
    " EXPLAIN ANALYZE ";
    " DELETE FROM t ";
    ": ";
    "- ";
    "{";
    "}";
    "[";
    "]";
    "&a ";
    "*a ";
    "!!binary ";
    "<<: ";
    "? ";
    "|\n";
    ">\n";
  |]

let mutate rng (seeds : string array) s =
  let n = String.length s in
  let pos () = if n = 0 then 0 else Random.State.int rng (n + 1) in
  match Random.State.int rng 10 with
  | 0 when n > 0 ->
      let b = Bytes.of_string s in
      let i = Random.State.int rng n in
      Bytes.set b i
        (Char.chr (Char.code (Bytes.get b i) lxor (1 lsl Random.State.int rng 8)));
      Bytes.to_string b
  | 1 ->
      let i = pos () in
      String.sub s 0 i
      ^ String.make 1 (Char.chr (Random.State.int rng 256))
      ^ String.sub s i (n - i)
  | 2 when n > 0 ->
      let i = Random.State.int rng n in
      let l = 1 + Random.State.int rng (min 16 (n - i)) in
      String.sub s 0 i ^ String.sub s (i + l) (n - i - l)
  | 3 when n > 0 ->
      let i = Random.State.int rng n in
      let l = 1 + Random.State.int rng (min 64 (n - i)) in
      let chunk = String.sub s i l in
      String.sub s 0 i ^ chunk ^ chunk ^ String.sub s i (n - i)
  | 4 ->
      let o = seeds.(Random.State.int rng (Array.length seeds)) in
      let i = pos ()
      and j = if o = "" then 0 else Random.State.int rng (String.length o + 1) in
      String.sub s 0 i ^ String.sub o j (String.length o - j)
  | 5 | 6 ->
      let i = pos () in
      String.sub s 0 i
      ^ tokens.(Random.State.int rng (Array.length tokens))
      ^ String.sub s i (n - i)
  | 7 -> String.sub s 0 (pos ())
  | 8 ->
      (* amplify nesting: wrap a span in many parentheses *)
      let k = 1 + Random.State.int rng 200 in
      String.make k '(' ^ s ^ String.make k ')'
  | _ ->
      let i = pos () in
      let t = tokens.(Random.State.int rng (Array.length tokens)) in
      let k = 1 + Random.State.int rng 50 in
      String.sub s 0 i
      ^ String.concat "" (List.init k (fun _ -> t))
      ^ String.sub s i (n - i)

(* ---- oracles: [Some kind] when the input is a finding ---- *)

let ctx = Context.make [ ("tenant_id", Context.One "acme") ]

let check_sql policy sql =
  let t0 = Unix.gettimeofday () in
  match Haltsql.verify policy ctx sql with
  | exception e -> Some ("verify-exception: " ^ Printexc.to_string e)
  | v ->
      let dt = Unix.gettimeofday () -. t0 in
      let rs = v.reasons @ v.shadow_reasons in
      let codes = List.map (fun (r : Reason.t) -> r.code) rs in
      if dt > 2.0 then Some (Printf.sprintf "verify-slow: %.2fs" dt)
      else if v.allowed && v.reasons <> [] then Some "verify-allowed-with-reasons"
      else if (not v.allowed) && rs = [] then Some "verify-denied-without-reason"
      else if not (List.for_all (fun c -> List.mem c Reason.all_codes) codes) then
        Some "verify-unknown-code"
      else if List.mem Reason.E_INTERNAL codes then
        Some
          ("verify-internal: "
          ^ String.concat "; "
              (List.filter_map
                 (fun (r : Reason.t) ->
                   if r.code = Reason.E_INTERNAL then Some r.message else None)
                 rs))
      else None

let check_doc text =
  let r1 =
    try
      ignore (Docload.of_string Docload.Yaml text);
      None
    with e -> Some ("docload-yaml-exception: " ^ Printexc.to_string e)
  in
  match r1 with
  | Some _ -> r1
  | None -> (
      let r2 =
        try
          ignore (Docload.of_string Docload.Json text);
          None
        with e -> Some ("docload-json-exception: " ^ Printexc.to_string e)
      in
      match r2 with
      | Some _ -> r2
      | None -> (
          try
            ignore (Policy_load.of_string ~base_dir:"." Docload.Yaml text);
            None
          with e -> Some ("policy-load-exception: " ^ Printexc.to_string e)))

(* Greedy delta minimization: drop chunks (halving sizes) while [still_fails]. *)
let minimize still_fails s =
  let s = ref s in
  let chunk = ref (max 1 (String.length !s / 2)) in
  let budget = ref 2000 in
  while !chunk >= 1 && !budget > 0 do
    let i = ref 0 in
    let progressed = ref false in
    while !i < String.length !s && !budget > 0 do
      decr budget;
      let n = String.length !s in
      let l = min !chunk (n - !i) in
      let cand = String.sub !s 0 !i ^ String.sub !s (!i + l) (n - !i - l) in
      if still_fails cand then (
        s := cand;
        progressed := true)
      else i := !i + l
    done;
    if not !progressed then chunk := !chunk / 2
  done;
  !s

let kind_prefix k =
  match String.index_opt k ':' with Some i -> String.sub k 0 i | None -> k

let () =
  let root = ref ".." in
  let rec args = function
    | "--root" :: d :: tl ->
        root := d;
        args tl
    | _ :: tl -> args tl
    | [] -> ()
  in
  args (List.tl (Array.to_list Sys.argv));
  let files = walk (!root // "corpus") @ walk (!root // "conformance") in
  let suites =
    List.filter (fun f -> ends_with f ".suite.yaml" || ends_with f ".suite.json") files
  in
  let sql_seeds =
    List.concat_map
      (fun f ->
        match Test_suite.of_file f with
        | Ok s -> List.map (fun (c : Test_suite.case) -> c.sql) s.cases
        | Error _ -> [])
      suites
  in
  let doc_files =
    walk (!root // "fixtures") @ suites
    |> List.filter (fun f -> ends_with f ".yaml" || ends_with f ".json")
  in
  let doc_seeds =
    List.map read_file doc_files |> List.filter (fun s -> String.length s < 64_000)
  in
  let policies =
    List.filter_map
      (fun n ->
        match Policy_load.of_file (!root // "fixtures/policies" // (n ^ ".yaml")) with
        | Ok p -> Some p
        | Error _ -> None)
      [ "saas"; "strict"; "writes"; "explain"; "mixed_case"; "saas_literal" ]
  in
  if policies = [] then (
    prerr_endline "fuzz: no fixture policy could be loaded";
    exit 2);
  let policies = Array.of_list policies in
  let sql_seeds = Array.of_list (if sql_seeds = [] then [ "SELECT 1" ] else sql_seeds) in
  let doc_seeds = Array.of_list (if doc_seeds = [] then [ "a: 1" ] else doc_seeds) in
  Printf.printf "haltsql fuzz: seed=%d iters=%d sql_seeds=%d doc_seeds=%d policies=%d\n%!"
    seed iters (Array.length sql_seeds) (Array.length doc_seeds) (Array.length policies);
  let rng = Random.State.make [| seed |] in
  let found = Hashtbl.create 16 in
  let record kind input still_fails =
    let key = kind_prefix kind in
    if not (Hashtbl.mem found key) then begin
      let small = minimize still_fails input in
      Hashtbl.add found key ();
      let dir = crash_dir () in
      (try if not (Sys.file_exists dir) then Sys.mkdir dir 0o755 with _ -> ());
      let file =
        dir // Printf.sprintf "%s-%s.txt" key (String.sub (Haltsql.sha256_hex small) 0 12)
      in
      (try
         let oc = open_out_bin file in
         output_string oc small;
         close_out oc
       with Sys_error e -> Printf.printf "  (could not write %s: %s)\n" file e);
      Printf.printf "FOUND %s\n  minimized (%d bytes): %S\n  written to %s\n%!" kind
        (String.length small) small file
    end
  in
  let t0 = Unix.gettimeofday () in
  let sql_runs = ref 0 and doc_runs = ref 0 in
  for i = 1 to iters do
    let k = 1 + Random.State.int rng 8 in
    if i mod 5 <> 0 then begin
      incr sql_runs;
      let s = ref sql_seeds.(Random.State.int rng (Array.length sql_seeds)) in
      for _ = 1 to k do
        s := mutate rng sql_seeds !s
      done;
      let p = policies.(Random.State.int rng (Array.length policies)) in
      match check_sql p !s with
      | None -> ()
      | Some kind ->
          let pre = kind_prefix kind in
          record kind !s (fun c ->
              match check_sql p c with Some k -> kind_prefix k = pre | None -> false)
    end
    else begin
      incr doc_runs;
      let s = ref doc_seeds.(Random.State.int rng (Array.length doc_seeds)) in
      for _ = 1 to k do
        s := mutate rng doc_seeds !s
      done;
      match check_doc !s with
      | None -> ()
      | Some kind ->
          let pre = kind_prefix kind in
          record kind !s (fun c ->
              match check_doc c with Some k -> kind_prefix k = pre | None -> false)
    end
  done;
  let dt = Unix.gettimeofday () -. t0 in
  Printf.printf
    "haltsql fuzz: %d verify + %d document inputs in %.1fs (%.0f/s); findings: %d\n"
    !sql_runs !doc_runs dt
    (float_of_int iters /. dt)
    (Hashtbl.length found);
  if Hashtbl.length found > 0 then exit 1
