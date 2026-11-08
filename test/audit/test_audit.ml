(* haltsql audit verify: the verification engine (Cmd_audit.Verify) on chains written
   with the real sealing code (Audit_chain.seal, Object_sink), and the CLI binaries. *)

module V = Audit_cmd.Cmd_audit.Verify
module S3r = Audit_cmd.Cmd_audit.S3_read
module Chain = Haltsql_cloud.Audit_chain
module Obj = Haltsql_cloud.Object_sink
module Config = Haltsql.Config

(* ------------------------------------------------------------ helpers *)

let record i : (string * Yojson.Safe.t) list =
  [
    ("ts", `String (Printf.sprintf "2026-11-07T12:00:%02d.000Z" (i mod 60)));
    ("event", `String "statement");
    ("session", `String "abc123");
    ("user", `String "agent");
    ("policy", `String "proxy-test");
    ("allowed", `Bool (i mod 3 <> 0));
    ("sql_sha256", `String (String.make 64 (Char.chr (97 + (i mod 6)))));
    ("n", `Int i);
  ]

(* n sealed lines, chain starting at [prev] *)
let chain ?(prev = Chain.genesis) ?(from = 1) n =
  let rec go acc prev i =
    if i >= from + n then List.rev acc
    else
      let line, h = Chain.seal ~prev (record i) in
      go (line :: acc) h (i + 1)
  in
  go [] prev from

let text lines = String.concat "" (List.map (fun l -> l ^ "\n") lines)

let last_hash lines =
  Option.get (Chain.hash_of_line (List.nth lines (List.length lines - 1)))

let verify ?(opts = V.default_opts) s = V.verify_string ~opts ~source:"t.jsonl" s
let kinds r = List.map (fun (p : V.problem) -> p.kind) (V.problems r)

let errors r =
  List.filter_map
    (fun (p : V.problem) -> if p.severity = V.Error then Some p.kind else None)
    (V.problems r)

let check_ok name r =
  if not (V.ok r) then
    Alcotest.failf "%s: expected OK, got %s" name
      (Yojson.Safe.to_string (V.report_json r))

let check_errors name expected r = Alcotest.(check (list string)) name expected (errors r)

let first_line r =
  match V.first_error r with Some { where = Some l; _ } -> l.line | _ -> -1

let replace_nth l n f = List.mapi (fun i x -> if i = n then f x else x) l

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let replace_once s ~sub ~by =
  let n = String.length s and m = String.length sub in
  let rec go i =
    if i + m > n then s
    else if String.sub s i m = sub then
      String.sub s 0 i ^ by ^ String.sub s (i + m) (n - i - m)
    else go (i + 1)
  in
  go 0

(* ------------------------------------------------------- linear chains *)

let t_ok () =
  let r = verify (text (chain 10)) in
  check_ok "10 records" r;
  Alcotest.(check int) "records" 10 r.records;
  Alcotest.(check int) "chains" 1 r.chains;
  Alcotest.(check (list string)) "no problems" [] (kinds r)

let t_edit_field () =
  let lines = chain 6 in
  let tampered =
    replace_nth lines 2 (fun l ->
        replace_once l ~sub:"\"user\":\"agent\"" ~by:"\"user\":\"admin\"")
  in
  let r = verify (text tampered) in
  check_errors "edited field" [ "bad_hash" ] r;
  Alcotest.(check int) "at line 3" 3 (first_line r)

let t_edit_and_rehash () =
  (* the attacker recomputes the edited record's hash: the next link breaks *)
  let lines = chain 6 in
  let prev = Option.get (Chain.hash_of_line (List.nth lines 1)) in
  let forged, _ =
    Chain.seal ~prev
      (List.map
         (fun (k, v) -> if k = "user" then (k, `String "admin") else (k, v))
         (record 3))
  in
  let r = verify (text (replace_nth lines 2 (fun _ -> forged))) in
  check_errors "rehashed edit" [ "broken_link" ] r;
  Alcotest.(check int) "at line 4" 4 (first_line r)

let t_delete_line () =
  let lines = chain 6 in
  let r = verify (text (List.filteri (fun i _ -> i <> 2) lines)) in
  check_errors "deleted record" [ "broken_link" ] r;
  Alcotest.(check int) "at line 3" 3 (first_line r);
  match V.first_error r with
  | Some p -> Alcotest.(check bool) "says deleted" true (contains p.message "deleted")
  | None -> Alcotest.fail "no error"

let t_swap_lines () =
  let lines = chain 6 in
  let a = List.nth lines 2 and b = List.nth lines 3 in
  let swapped = replace_nth (replace_nth lines 2 (fun _ -> b)) 3 (fun _ -> a) in
  let r = verify (text swapped) in
  Alcotest.(check bool) "broken" false (V.ok r);
  Alcotest.(check int) "first break at line 3" 3 (first_line r);
  Alcotest.(check bool)
    "reordering diagnosed" true
    (List.exists (fun (p : V.problem) -> contains p.message "reordered") (V.problems r))

let t_truncate_partial () =
  let s = text (chain 5) in
  let cut = String.sub s 0 (String.length s - 40) in
  let r = verify cut in
  check_errors "truncated last line" [ "truncated" ] r;
  Alcotest.(check int) "at line 5" 5 (first_line r)

let t_truncate_whole_lines () =
  let lines = chain 6 in
  let head = last_hash lines in
  let short = List.filteri (fun i _ -> i < 4) lines in
  (* undetectable from the records alone ... *)
  check_ok "tail cut without anchor" (verify (text short));
  (* ... detected against a recorded head *)
  let r = verify ~opts:{ V.default_opts with expect_head = Some head } (text short) in
  check_errors "tail cut with --expect-head" [ "head_mismatch" ] r;
  check_ok "full chain with --expect-head"
    (verify ~opts:{ V.default_opts with expect_head = Some head } (text lines))

let t_duplicate_line () =
  let lines = chain 5 in
  let dup =
    List.concat_map (fun l -> if l == List.nth lines 2 then [ l; l ] else [ l ]) lines
  in
  let r = verify (text dup) in
  check_errors "duplicated record" [ "duplicate_record" ] r;
  Alcotest.(check int) "at line 4" 4 (first_line r)

let t_mid_chain_start () =
  let lines = chain 8 in
  let tail = List.filteri (fun i _ -> i >= 3) lines in
  check_errors "mid-stream start" [ "mid_chain_start" ] (verify (text tail));
  check_ok "--any-start" (verify ~opts:{ V.default_opts with start = V.Any } (text tail));
  let h3 = Option.get (Chain.hash_of_line (List.nth lines 2)) in
  check_ok "--initial-prev"
    (verify ~opts:{ V.default_opts with start = V.Hash h3 } (text tail));
  check_errors "wrong --initial-prev" [ "start_mismatch" ]
    (verify ~opts:{ V.default_opts with start = V.Hash (String.make 64 'f') } (text tail))

let t_restart () =
  let s = text (chain 3 @ chain ~from:10 3) in
  let r = verify s in
  check_ok "restart is a warning" r;
  Alcotest.(check int) "two chains" 2 r.chains;
  Alcotest.(check (list string)) "warning" [ "chain_restart" ] (kinds r);
  check_errors "--strict" [ "chain_restart" ]
    (verify ~opts:{ V.default_opts with strict = true } s)

let t_mixed_logs () =
  let lines = chain 4 in
  let log = {|{"ts":"x","level":"info","component":"haltsql-proxy","msg":"listening"}|} in
  let interleaved =
    [ log ]
    @ [ List.nth lines 0 ]
    @ [ "plain text line"; log ]
    @ List.map (fun l -> "2026-11-07T12:00:00Z stdout F " ^ l) (List.tl lines)
  in
  let r = verify ~opts:{ V.default_opts with mixed = true } (text interleaved) in
  check_ok "--mixed" r;
  Alcotest.(check int) "records" 4 r.records;
  Alcotest.(check int) "skipped" 3 r.skipped;
  let r = verify (text ([ log ] @ lines)) in
  check_errors "log line without --mixed" [ "not_audit_record" ] r

let t_invalid_records () =
  let lines = chain 3 in
  let bad =
    replace_nth lines 1 (fun l ->
        replace_once l ~sub:"\"prev_hash\":\"" ~by:"\"prev_hash\":\"Z")
  in
  Alcotest.(check bool)
    "bad hex" true
    (List.mem "invalid_record" (errors (verify (text bad))));
  let garbage = replace_nth lines 1 (fun _ -> "{not json") in
  let r = verify (text garbage) in
  Alcotest.(check (list string)) "garbage line" [ "invalid_record" ] (errors r)

let t_parse_name () =
  let sha = String.make 64 'a' in
  Alcotest.(check (option (pair string (pair string (pair int string)))))
    "host with dashes"
    (Some ("my-host.example", ("20260101T000000.000000Z.42", (7, sha))))
    (Option.map
       (fun (h, r, s, x) -> (h, (r, (s, x))))
       (V.parse_name
          ("p/2026/01/01/00/my-host.example-20260101T000000.000000Z.42-0000000007-" ^ sha
         ^ ".jsonl")));
  Alcotest.(check bool)
    "bad seq" true
    (V.parse_name ("h-r-00000007-" ^ sha ^ ".jsonl") = None);
  Alcotest.(check bool) "bad sha" true (V.parse_name "h-r-0000000007-abc.jsonl" = None)

let t_s3_url () =
  Alcotest.(check (option (pair string string)))
    "bucket + prefix"
    (Some ("audit", "haltsql/audit/"))
    (Option.map
       (fun (t : S3r.target) -> (t.bucket, t.prefix))
       (S3r.parse_url "s3://audit/haltsql/audit/"));
  Alcotest.(check bool) "no scheme" true (S3r.parse_url "audit/x" = None);
  Alcotest.(check bool) "bad bucket" true (S3r.parse_url "s3://A_B/x" = None)

(* ------------------------------------------------------ object outputs *)

let tmpdir prefix =
  let d = Filename.temp_file prefix "" in
  Sys.remove d;
  Unix.mkdir d 0o700;
  d

let rec mkdir_p d =
  if not (Sys.file_exists d) then (
    mkdir_p (Filename.dirname d);
    Unix.mkdir d 0o700)

let write_file path s =
  mkdir_p (Filename.dirname path);
  Out_channel.with_open_bin path (fun oc -> Out_channel.output_string oc s)

let read_file path = In_channel.with_open_bin path In_channel.input_all

(* The real object sink, uploading into a local directory (as `aws s3 cp --recursive`
   would download it). *)
let disk_uploader dir ~key ~body =
  write_file (Filename.concat dir key) body;
  Lwt.return (Ok ())

let t0 = 1_780_000_000.

let make_sink ?spool_dir ?(run_id = "20260101T000000.000000Z.1") ?(host = "proxy-a") dir =
  match
    Obj.create
      ~now:(fun () -> t0)
      ~host ~run_id ?spool_dir ~name:"t" ~prefix:"haltsql/audit/"
      ~batch:{ Config.max_records = 3; max_seconds = 3600 }
      ~on_error:Config.Fail_closed (disk_uploader dir)
  with
  | Ok s -> s
  | Error e -> Alcotest.fail e

let write_n s from n =
  for i = from to from + n - 1 do
    match Obj.write s (record i) with Ok () -> () | Error e -> Alcotest.fail e
  done

let flush s =
  match Lwt_main.run (Obj.flush s) with Ok () -> () | Error e -> Alcotest.fail e

let close s =
  match Lwt_main.run (Obj.close s) with Ok () -> () | Error e -> Alcotest.fail e

let objects dir = List.sort compare (List.map fst (V.read_dir dir))

let vdir ?(opts = V.default_opts) ?spool dir =
  V.verify_objects ~opts ?spool ~source:dir ~kind:"objects" (V.read_dir dir)

let t_objects_ok () =
  let dir = tmpdir "objs" in
  let s = make_sink dir in
  write_n s 1 10;
  close s;
  let r = vdir dir in
  check_ok "10 records in 4 objects" r;
  Alcotest.(check int) "objects" 4 r.objects;
  Alcotest.(check int) "records" 10 r.records;
  Alcotest.(check int) "chains" 1 r.chains

let t_objects_deleted () =
  let dir = tmpdir "objs" in
  let s = make_sink dir in
  write_n s 1 10;
  close s;
  Sys.remove (Filename.concat dir (List.nth (objects dir) 1));
  let r = vdir dir in
  Alcotest.(check bool) "seq gap" true (List.mem "seq_gap" (errors r));
  Alcotest.(check bool) "broken link" true (List.mem "broken_link" (errors r))

let t_objects_duplicate () =
  let dir = tmpdir "objs" in
  let s = make_sink dir in
  write_n s 1 6;
  close s;
  let k = List.nth (objects dir) 0 in
  (* the same object stored again under another hour directory *)
  let base = Filename.basename k in
  write_file
    (Filename.concat dir ("haltsql/audit/2030/01/01/00/" ^ base))
    (read_file (Filename.concat dir k));
  check_errors "duplicate object" [ "duplicate_object" ] (vdir dir)

let t_objects_modified () =
  let dir = tmpdir "objs" in
  let s = make_sink dir in
  write_n s 1 6;
  close s;
  let f = Filename.concat dir (List.nth (objects dir) 1) in
  write_file f (replace_once (read_file f) ~sub:"\"agent\"" ~by:"\"admin\"");
  let r = vdir dir in
  Alcotest.(check (list string))
    "modified body"
    [ "body_mismatch"; "bad_hash" ]
    (errors r)

let t_objects_truncated () =
  let dir = tmpdir "objs" in
  let s = make_sink dir in
  write_n s 1 6;
  close s;
  let f = Filename.concat dir (List.nth (objects dir) 1) in
  let b = read_file f in
  write_file f (String.sub b 0 (String.length b - 30));
  let r = vdir dir in
  Alcotest.(check bool) "body mismatch" true (List.mem "body_mismatch" (errors r));
  Alcotest.(check bool) "truncated" true (List.mem "truncated" (errors r))

let t_objects_reordered () =
  (* swap the seq numbers of objects 1 and 2 (names keep their body hash) *)
  let dir = tmpdir "objs" in
  let s = make_sink dir in
  write_n s 1 9;
  close s;
  let os = objects dir in
  let rename k seq =
    let d = Filename.dirname k and b = Filename.basename k in
    let host_run_end = String.length b - 6 - 64 - 11 in
    Filename.concat d
      (String.sub b 0 host_run_end ^ Printf.sprintf "%010d" seq
      ^ String.sub b (host_run_end + 10) (String.length b - host_run_end - 10))
  in
  let a = List.nth os 1 and b = List.nth os 2 in
  let ba = read_file (Filename.concat dir a) and bb = read_file (Filename.concat dir b) in
  Sys.remove (Filename.concat dir a);
  Sys.remove (Filename.concat dir b);
  write_file (Filename.concat dir (rename a 2)) ba;
  write_file (Filename.concat dir (rename b 1)) bb;
  let r = vdir dir in
  Alcotest.(check bool) "broken" false (V.ok r);
  Alcotest.(check bool)
    "reordering diagnosed" true
    (List.exists (fun (p : V.problem) -> contains p.message "reordered") (V.problems r))

let t_objects_conflict () =
  let dir = tmpdir "objs" in
  let s = make_sink dir in
  write_n s 1 3;
  close s;
  let k = List.hd (objects dir) in
  let other = text (chain ~from:50 3) in
  let sha = V.sha256_hex other in
  let k2 = String.sub k 0 (String.length k - 6 - 64) ^ sha ^ ".jsonl" in
  write_file (Filename.concat dir k2) other;
  Alcotest.(check bool)
    "conflict" true
    (List.mem "conflicting_objects" (errors (vdir dir)))

let t_runs_spool_continuity () =
  let dir = tmpdir "objs" and spool = tmpdir "spool" in
  let s1 = make_sink ~spool_dir:spool ~run_id:"20260101T000000.000000Z.1" dir in
  write_n s1 1 5;
  close s1;
  let s2 = make_sink ~spool_dir:spool ~run_id:"20260102T000000.000000Z.2" dir in
  write_n s2 6 4;
  close s2;
  let r = vdir dir in
  check_ok "two runs, one chain" r;
  Alcotest.(check int) "chains" 1 r.chains;
  Alcotest.(check int) "records" 9 r.records;
  check_ok "spool head" (vdir ~spool dir)

let t_wrong_run_order () =
  let dir = tmpdir "objs" and spool = tmpdir "spool" in
  let s1 = make_sink ~spool_dir:spool ~run_id:"20260105T000000.000000Z.1" dir in
  write_n s1 1 3;
  close s1;
  (* the continuing run claims to have started earlier *)
  let s2 = make_sink ~spool_dir:spool ~run_id:"20260101T000000.000000Z.2" dir in
  write_n s2 4 3;
  close s2;
  Alcotest.(check bool) "run order" true (List.mem "run_order" (errors (vdir dir)))

let t_earlier_run_deleted () =
  let dir = tmpdir "objs" and spool = tmpdir "spool" in
  let s1 = make_sink ~spool_dir:spool ~run_id:"20260101T000000.000000Z.1" dir in
  write_n s1 1 3;
  close s1;
  let s2 = make_sink ~spool_dir:spool ~run_id:"20260102T000000.000000Z.2" dir in
  write_n s2 4 3;
  close s2;
  List.iter
    (fun k -> if contains k "20260101T" then Sys.remove (Filename.concat dir k))
    (objects dir);
  check_errors "earlier run gone" [ "mid_chain_start" ] (vdir dir);
  check_ok "--any-start" (vdir ~opts:{ V.default_opts with start = V.Any } dir)

let t_restart_without_spool () =
  let dir = tmpdir "objs" in
  let s1 = make_sink ~run_id:"20260101T000000.000000Z.1" dir in
  write_n s1 1 3;
  close s1;
  let s2 = make_sink ~run_id:"20260102T000000.000000Z.2" dir in
  write_n s2 4 3;
  close s2;
  let r = vdir dir in
  check_ok "independent runs" r;
  Alcotest.(check int) "chains" 2 r.chains;
  check_errors "--strict" [ "chain_restart" ]
    (vdir ~opts:{ V.default_opts with strict = true } dir)

let t_spool_tail_missing () =
  let dir = tmpdir "objs" and spool = tmpdir "spool" in
  let s = make_sink ~spool_dir:spool dir in
  write_n s 1 6;
  flush s;
  write_n s 7 1;
  (* spool: head.json (next seq 2) + current.jsonl with one record *)
  check_ok "objects + spool" (vdir ~spool dir);
  let last = List.nth (objects dir) (List.length (objects dir) - 1) in
  Sys.remove (Filename.concat dir last);
  let r = vdir ~spool dir in
  Alcotest.(check bool) "head mismatch" true (List.mem "spool_head_mismatch" (errors r))

let t_unrecognized_name () =
  let dir = tmpdir "objs" in
  let s = make_sink dir in
  write_n s 1 3;
  close s;
  write_file (Filename.concat dir "haltsql/audit/notes.jsonl") (text (chain 1));
  Alcotest.(check bool)
    "unrecognized" true
    (List.mem "unrecognized_name" (errors (vdir dir)))

(* ------------------------------------------------------------------ CLI *)

let absolute p = if Filename.is_relative p then Filename.concat (Sys.getcwd ()) p else p
let harness = Option.map absolute (Sys.getenv_opt "HALTSQL_AUDIT_CLI")

(* The real `haltsql` binary, if `audit` is registered in main.ml. *)
let real_bin =
  match Option.map absolute (Sys.getenv_opt "HALTSQL_BIN") with
  | None -> None
  | Some b ->
      let out = Filename.temp_file "haltsql_help" "" in
      let _ =
        Unix.system
          (Filename.quote_command b
             [ "audit"; "verify"; "--help=plain" ]
             ~stdout:out ~stderr:"/dev/null")
      in
      let help = In_channel.with_open_bin out In_channel.input_all in
      Sys.remove out;
      if contains help "haltsql-audit-verify" then Some b else None

let run_bin ?stdin bin args =
  let out = Filename.temp_file "audit_out" ""
  and err = Filename.temp_file "audit_err" "" in
  let cmd =
    Filename.quote_command bin ("audit" :: "verify" :: args) ?stdin ~stdout:out
      ~stderr:err
  in
  let rec sys () =
    try Unix.system cmd with Unix.Unix_error (Unix.EINTR, _, _) -> sys ()
  in
  let code = match sys () with Unix.WEXITED c -> c | _ -> -1 in
  let o = read_file out and e = read_file err in
  Sys.remove out;
  Sys.remove err;
  (code, o, e)

let cli_cases bin () =
  let dir = tmpdir "cli" in
  let good = Filename.concat dir "good.jsonl" in
  let lines = chain 5 in
  write_file good (text lines);
  let bad = Filename.concat dir "bad.jsonl" in
  write_file bad (text (List.filteri (fun i _ -> i <> 1) lines));
  let code, out, _ = run_bin bin [ good ] in
  Alcotest.(check int) "good: exit 0" 0 code;
  Alcotest.(check bool) "good: OK" true (contains out "OK, 5 records");
  let code, out, _ = run_bin bin [ bad ] in
  Alcotest.(check int) "bad: exit 1" 1 code;
  Alcotest.(check bool) "bad: first broken link" true (contains out "first broken link");
  let code, out, _ = run_bin bin [ "--json"; good; bad ] in
  Alcotest.(check int) "json: exit 1" 1 code;
  let j = Yojson.Safe.from_string out in
  let open Yojson.Safe.Util in
  Alcotest.(check bool) "json ok=false" false (to_bool (member "ok" j));
  Alcotest.(check string)
    "json first_broken" "broken_link"
    (to_string (member "kind" (member "first_broken" j)));
  Alcotest.(check int)
    "json first_broken line" 2
    (to_int (member "line" (member "first_broken" j)));
  Alcotest.(check int) "json inputs" 2 (List.length (to_list (member "inputs" j)));
  (* stdin *)
  let code, out, _ = run_bin ~stdin:good bin [ "-" ] in
  Alcotest.(check int) "stdin: exit 0" 0 code;
  Alcotest.(check bool) "stdin: named" true (contains out "stdin: OK");
  (* --concat across a rotated pair *)
  let a = Filename.concat dir "a.jsonl" and b = Filename.concat dir "b.jsonl" in
  write_file a (text (List.filteri (fun i _ -> i < 2) lines));
  write_file b (text (List.filteri (fun i _ -> i >= 2) lines));
  Alcotest.(check int)
    "b alone: mid-chain" 1
    (let c, _, _ = run_bin bin [ b ] in
     c);
  Alcotest.(check int)
    "--concat a b" 0
    (let c, _, _ = run_bin bin [ "--concat"; a; b ] in
     c);
  Alcotest.(check int)
    "--concat b a" 1
    (let c, _, _ = run_bin bin [ "--concat"; b; a ] in
     c);
  (* expect-head *)
  Alcotest.(check int)
    "--expect-head ok" 0
    (let c, _, _ = run_bin bin [ "--expect-head"; last_hash lines; good ] in
     c);
  (* objects directory *)
  let objs = tmpdir "cliobjs" in
  let s = make_sink objs in
  write_n s 1 7;
  close s;
  let code, out, _ = run_bin bin [ "--json"; objs ] in
  Alcotest.(check int) "objects: exit 0" 0 code;
  Alcotest.(check int)
    "objects: records" 7
    (to_int
       (member "records"
          (List.hd (to_list (member "inputs" (Yojson.Safe.from_string out))))));
  (* usage errors *)
  let code, _, err = run_bin bin [] in
  Alcotest.(check int) "no input: exit 2" 2 code;
  Alcotest.(check bool) "no input: message" true (contains err "no input");
  Alcotest.(check int)
    "missing file: exit 2" 2
    (let c, _, _ = run_bin bin [ Filename.concat dir "nope" ] in
     c);
  Alcotest.(check int)
    "bad --expect-head: exit 2" 2
    (let c, _, _ = run_bin bin [ "--expect-head"; "xyz"; good ] in
     c);
  Alcotest.(check int)
    "unknown option: exit 2" 2
    (let c, _, _ = run_bin bin [ "--bogus"; good ] in
     c);
  Alcotest.(check int)
    "--spool on a file: exit 2" 2
    (let c, _, _ = run_bin bin [ "--spool"; dir; good ] in
     c)

let () =
  let cli =
    (match harness with
      | Some h ->
          [ Alcotest.test_case "harness binary (Cmd_audit.cmd)" `Quick (cli_cases h) ]
      | None ->
          [
            Alcotest.test_case "HALTSQL_AUDIT_CLI not set (run via dune test)" `Quick
              Alcotest.skip;
          ])
    @
    match real_bin with
    | Some b -> [ Alcotest.test_case "haltsql binary" `Quick (cli_cases b) ]
    | None ->
        [
          Alcotest.test_case
            "haltsql binary: audit not registered in main.ml yet (skipped)" `Quick
            (fun () -> Alcotest.skip ());
        ]
  in
  Alcotest.run "audit-verify"
    [
      ( "lines",
        [
          Alcotest.test_case "valid chain" `Quick t_ok;
          Alcotest.test_case "edited field" `Quick t_edit_field;
          Alcotest.test_case "edited + rehashed record" `Quick t_edit_and_rehash;
          Alcotest.test_case "deleted line" `Quick t_delete_line;
          Alcotest.test_case "swapped lines" `Quick t_swap_lines;
          Alcotest.test_case "truncated last line" `Quick t_truncate_partial;
          Alcotest.test_case "truncated tail vs --expect-head" `Quick
            t_truncate_whole_lines;
          Alcotest.test_case "duplicated line" `Quick t_duplicate_line;
          Alcotest.test_case "mid-chain start" `Quick t_mid_chain_start;
          Alcotest.test_case "restart (new chain)" `Quick t_restart;
          Alcotest.test_case "logs with --mixed" `Quick t_mixed_logs;
          Alcotest.test_case "invalid records" `Quick t_invalid_records;
          Alcotest.test_case "object names" `Quick t_parse_name;
          Alcotest.test_case "s3 URLs" `Quick t_s3_url;
        ] );
      ( "objects",
        [
          Alcotest.test_case "valid objects" `Quick t_objects_ok;
          Alcotest.test_case "deleted object" `Quick t_objects_deleted;
          Alcotest.test_case "duplicated object" `Quick t_objects_duplicate;
          Alcotest.test_case "modified object" `Quick t_objects_modified;
          Alcotest.test_case "truncated object" `Quick t_objects_truncated;
          Alcotest.test_case "reordered objects" `Quick t_objects_reordered;
          Alcotest.test_case "conflicting objects" `Quick t_objects_conflict;
          Alcotest.test_case "spool continuity across runs" `Quick t_runs_spool_continuity;
          Alcotest.test_case "wrong run order" `Quick t_wrong_run_order;
          Alcotest.test_case "earlier run deleted" `Quick t_earlier_run_deleted;
          Alcotest.test_case "restart without spool" `Quick t_restart_without_spool;
          Alcotest.test_case "spool head: tail missing" `Quick t_spool_tail_missing;
          Alcotest.test_case "unrecognized object name" `Quick t_unrecognized_name;
        ] );
      ("cli", cli);
    ]
