(* Store and activity-log tests: log replay, compaction, torn and corrupt logs, per-
   collection concurrency, activity seq resume, rotation and keyset paging. *)

open Lwt.Syntax
open Helpers
module C = Haltsql_console

let file_lines p =
  if not (Sys.file_exists p) then []
  else
    In_channel.with_open_bin p In_channel.input_all
    |> String.split_on_char '\n'
    |> List.filter (fun l -> String.trim l <> "")

let append_raw p s =
  Out_channel.with_open_gen [ Open_append; Open_creat; Open_binary ] 0o640 p (fun oc ->
      Out_channel.output_string oc s)

let ids s coll = List.rev (C.Store.fold s coll (fun id _ acc -> id :: acc) [])
let json = Alcotest.testable Yojson.Safe.pp Yojson.Safe.equal

let contains ~sub m =
  let n = String.length sub and h = String.length m in
  let rec at i = i + n <= h && (String.sub m i n = sub || at (i + 1)) in
  at 0

let store_tests =
  [
    ( "put update delete persist across reopen",
      `Quick,
      fun () ->
        let d = temp_dir "store" in
        let s = C.Store.create d in
        Lwt_main.run
          (let* () = C.Store.put s "cases" "a" (`Int 1) in
           let* () = C.Store.put s "cases" "b" (`Int 2) in
           let* () = C.Store.put s "cases" "c" (`Int 3) in
           let* r =
             C.Store.update s "cases" "a" (function
               | Some (`Int n) -> Some (`Int (n + 10))
               | _ -> None)
           in
           Alcotest.(check (option json)) "update result" (Some (`Int 11)) r;
           let* () = C.Store.delete s "cases" "b" in
           C.Store.put s "cases" "d" (`String "x"));
        Alcotest.(check bool)
          "log, no snapshot" true
          (Sys.file_exists (Filename.concat d "cases.log")
          && not (Sys.file_exists (Filename.concat d "cases.json")));
        let s' = C.Store.create d in
        Alcotest.(check (list string))
          "insertion order" [ "a"; "c"; "d" ] (ids s' "cases");
        Alcotest.(check (option json)) "a" (Some (`Int 11)) (C.Store.get s' "cases" "a");
        Alcotest.(check (option json)) "b deleted" None (C.Store.get s' "cases" "b");
        Alcotest.(check int) "count" 3 (C.Store.count s' "cases");
        Alcotest.(check int) "empty collection" 0 (C.Store.count s' "nothing") );
    ( "compaction preserves data and truncates the log",
      `Quick,
      fun () ->
        let d = temp_dir "store" in
        let s = C.Store.create ~compact_min_ops:5 d in
        Lwt_main.run
          (let* () = C.Store.put s "sig" "first" (`String "kept") in
           let rec go i =
             if i > 40 then Lwt.return_unit
             else
               let* () = C.Store.put s "sig" "hot" (`Int i) in
               go (i + 1)
           in
           let* () = go 1 in
           let* () = C.Store.put s "sig" "gone" `Null in
           C.Store.delete s "sig" "gone");
        Alcotest.(check bool)
          "snapshot written" true
          (Sys.file_exists (Filename.concat d "sig.json"));
        Alcotest.(check bool)
          "log truncated" true
          (List.length (file_lines (Filename.concat d "sig.log")) <= 5);
        let s' = C.Store.create d in
        Alcotest.(check (list string)) "ids" [ "first"; "hot" ] (ids s' "sig");
        Alcotest.(check (option json)) "hot" (Some (`Int 40)) (C.Store.get s' "sig" "hot");
        Alcotest.(check (option json))
          "first"
          (Some (`String "kept"))
          (C.Store.get s' "sig" "first") );
    ( "torn last log line is dropped",
      `Quick,
      fun () ->
        let d = temp_dir "store" in
        let s = C.Store.create d in
        Lwt_main.run
          (let* () = C.Store.put s "cases" "a" (`Int 1) in
           C.Store.put s "cases" "b" (`Int 2));
        append_raw (Filename.concat d "cases.log") {|{"op":"put","id":"c","do|};
        let s' = C.Store.create d in
        Alcotest.(check (list string)) "torn op dropped" [ "a"; "b" ] (ids s' "cases");
        (* the torn bytes were truncated, so later appends start on a clean line *)
        Lwt_main.run (C.Store.put s' "cases" "d" (`Int 4));
        let s'' = C.Store.create d in
        Alcotest.(check (list string)) "after append" [ "a"; "b"; "d" ] (ids s'' "cases")
    );
    ( "corrupt middle log line fails create",
      `Quick,
      fun () ->
        let d = temp_dir "store" in
        let s = C.Store.create d in
        Lwt_main.run (C.Store.put s "cases" "a" (`Int 1));
        let log = Filename.concat d "cases.log" in
        append_raw log "not json\n{\"op\":\"put\",\"id\":\"b\",\"doc\":2}\n";
        match C.Store.create d with
        | _ -> Alcotest.fail "expected create to fail"
        | exception Failure m ->
            Alcotest.(check bool)
              ("names the file: " ^ m) true
              (contains ~sub:(log ^ ":2:") m) );
    ( "corrupt snapshot fails create",
      `Quick,
      fun () ->
        let d = temp_dir "store" in
        let snap = Filename.concat d "cases.json" in
        append_raw snap "{\n\"a\": 1,\n\"b\": \n}\n";
        match C.Store.create d with
        | _ -> Alcotest.fail "expected create to fail"
        | exception Failure m ->
            Alcotest.(check bool) ("names the file: " ^ m) true (contains ~sub:snap m) );
    ( "concurrent puts to different collections",
      `Quick,
      fun () ->
        let d = temp_dir "store" in
        let s = C.Store.create d in
        let many coll =
          Lwt.join
            (List.init 20 (fun i ->
                 C.Store.put s coll (Printf.sprintf "k%02d" i) (`Int i)))
        in
        Lwt_main.run (Lwt.join [ many "cases"; many "signals" ]);
        let s' = C.Store.create d in
        Alcotest.(check int) "cases" 20 (C.Store.count s' "cases");
        Alcotest.(check int) "signals" 20 (C.Store.count s' "signals") );
    ( "counter",
      `Quick,
      fun () ->
        let d = temp_dir "store" in
        let s = C.Store.create d in
        let n1, n2 =
          Lwt_main.run
            (let* a = C.Store.next_counter s "case" ~start:1000 in
             let* b = C.Store.next_counter s "case" ~start:1000 in
             Lwt.return (a, b))
        in
        Alcotest.(check (pair int int)) "counter" (1000, 1001) (n1, n2);
        let s' = C.Store.create d in
        Alcotest.(check int)
          "resumes" 1002
          (Lwt_main.run (C.Store.next_counter s' "case" ~start:1000)) );
    ( "writable",
      `Quick,
      fun () ->
        let s = C.Store.create (temp_dir "store") in
        Alcotest.(check bool) "writable" true (Lwt_main.run (C.Store.writable s)) );
  ]

(* ---- fault injection ---- *)

(* Runs [f] with the store's low-level I/O hooks restored afterwards, whatever happens. *)
let with_io f = Fun.protect ~finally:C.Store.reset_io f
let enospc fn = Unix.Unix_error (Unix.ENOSPC, fn, "")

(* The next write lands only its first half and the one after that fails, as a full disk
   does; later writes are real. *)
let partial_write_once () =
  let calls = ref 0 in
  C.Store.io.write <-
    (fun fd b off len ->
      incr calls;
      match !calls with
      | 1 -> Lwt_unix.write fd b off (max 1 (len / 2))
      | 2 -> Lwt.fail (enospc "write")
      | _ -> Lwt_unix.write fd b off len)

let fail_fsync_once () =
  let failed = ref false in
  C.Store.io.fsync <-
    (fun fd ->
      if !failed then Lwt_unix.fsync fd
      else (
        failed := true;
        Lwt.fail (Unix.Unix_error (Unix.EIO, "fsync", ""))))

let rejects p =
  Lwt_main.run
    (Lwt.catch (fun () -> Lwt.map (fun () -> false) (p ())) (fun _ -> Lwt.return_true))

let file_contents p = In_channel.with_open_bin p In_channel.input_all

let fault_tests =
  [
    ( "partial write is rolled back",
      `Quick,
      fun () ->
        let d = temp_dir "store" in
        let s = C.Store.create d in
        let log = Filename.concat d "cases.log" in
        Lwt_main.run (C.Store.put s "cases" "a" (`Int 1));
        let before = file_contents log in
        with_io (fun () ->
            partial_write_once ();
            Alcotest.(check bool)
              "rejected" true
              (rejects (fun () -> C.Store.put s "cases" "b" (`String "lost"))));
        Alcotest.(check string) "log rolled back" before (file_contents log);
        Alcotest.(check (option json)) "not in memory" None (C.Store.get s "cases" "b");
        Lwt_main.run (C.Store.put s "cases" "c" (`Int 3));
        let s' = C.Store.create d in
        Alcotest.(check (list string)) "after reopen" [ "a"; "c" ] (ids s' "cases") );
    ( "fsync failure: rejected write does not reappear",
      `Quick,
      fun () ->
        let d = temp_dir "store" in
        let s = C.Store.create d in
        Lwt_main.run (C.Store.put s "cases" "a" (`Int 1));
        with_io (fun () ->
            fail_fsync_once ();
            Alcotest.(check bool)
              "rejected" true
              (rejects (fun () -> C.Store.put s "cases" "b" (`Int 2))));
        Alcotest.(check (option json)) "not in memory" None (C.Store.get s "cases" "b");
        let s' = C.Store.create d in
        Alcotest.(check (list string)) "not on disk" [ "a" ] (ids s' "cases");
        Lwt_main.run (C.Store.put s "cases" "c" (`Int 3));
        let s'' = C.Store.create d in
        Alcotest.(check (list string)) "later write" [ "a"; "c" ] (ids s'' "cases") );
    ( "failed rollback poisons the collection",
      `Quick,
      fun () ->
        let d = temp_dir "store" in
        let s = C.Store.create d in
        Lwt_main.run (C.Store.put s "cases" "a" (`Int 1));
        with_io (fun () ->
            C.Store.io.fsync <-
              (fun _ -> Lwt.fail (Unix.Unix_error (Unix.EIO, "fsync", "")));
            Alcotest.(check bool)
              "rejected" true
              (rejects (fun () -> C.Store.put s "cases" "b" (`Int 2))));
        (match Lwt_main.run (C.Store.put s "cases" "c" (`Int 3)) with
        | () -> Alcotest.fail "expected the poisoned collection to refuse writes"
        | exception Failure m ->
            Alcotest.(check bool) ("clear error: " ^ m) true (contains ~sub:"restart" m));
        Alcotest.(check (option json)) "memory unchanged" None (C.Store.get s "cases" "c");
        (* other collections are independent *)
        Lwt_main.run (C.Store.put s "other" "x" (`Int 1));
        Alcotest.(check int) "other" 1 (C.Store.count (C.Store.create d) "other") );
    ( "compaction failure does not reject the write",
      `Quick,
      fun () ->
        let d = temp_dir "store" in
        let s = C.Store.create ~compact_min_ops:3 d in
        let snap = Filename.concat d "counters.json" in
        let got =
          with_io (fun () ->
              let fails = ref 0 in
              C.Store.io.rename <-
                (fun _ _ ->
                  incr fails;
                  Lwt.fail (enospc "rename"));
              let got =
                Lwt_main.run
                  (Lwt_list.map_s
                     (fun _ -> C.Store.next_counter s "case" ~start:1)
                     (List.init 6 Fun.id))
              in
              Alcotest.(check bool) "compaction attempted" true (!fails >= 1);
              got)
        in
        Alcotest.(check (list int)) "no value skipped" [ 1; 2; 3; 4; 5; 6 ] got;
        Alcotest.(check bool) "no snapshot yet" false (Sys.file_exists snap);
        Alcotest.(check bool) "tmp removed" false (Sys.file_exists (snap ^ ".tmp"));
        (* retried on the next write, now that renames work *)
        Alcotest.(check int)
          "next" 7
          (Lwt_main.run (C.Store.next_counter s "case" ~start:1));
        Alcotest.(check bool) "compacted later" true (Sys.file_exists snap);
        Alcotest.(check int)
          "resumes" 8
          (Lwt_main.run (C.Store.next_counter (C.Store.create d) "case" ~start:1)) );
    ( "cancelled write completes in memory and on disk",
      `Quick,
      fun () ->
        let d = temp_dir "store" in
        let s = C.Store.create d in
        Lwt_main.run (C.Store.put s "cases" "a" (`Int 1));
        with_io (fun () ->
            (* block inside fsync, after the bytes landed, on a cancelable promise *)
            let gate, open_gate = Lwt.task () in
            let entered, enter = Lwt.wait () in
            C.Store.io.fsync <-
              (fun fd ->
                if Lwt.is_sleeping entered then Lwt.wakeup enter ();
                let* () = gate in
                Lwt_unix.fsync fd);
            Lwt_main.run
              (let p = C.Store.put s "cases" "b" (`Int 2) in
               let* () = entered in
               (* let the write reach the gate before cancelling *)
               let* () = Lwt.pause () in
               Lwt.cancel p;
               Lwt.wakeup open_gate ();
               Lwt.catch (fun () -> p) (fun _ -> Lwt.return_unit)));
        Alcotest.(check (option json))
          "in memory"
          (Some (`Int 2))
          (C.Store.get s "cases" "b");
        let s' = C.Store.create d in
        Alcotest.(check (list string))
          "memory matches log" (ids s "cases") (ids s' "cases");
        Alcotest.(check (list string)) "committed" [ "a"; "b" ] (ids s' "cases") );
    ( "create reports I/O errors as Failure",
      `Quick,
      fun () ->
        if Unix.geteuid () = 0 then () (* root ignores permissions *)
        else
          let parent = temp_dir "store" in
          Unix.chmod parent 0o500;
          let d = Filename.concat parent "state" in
          Fun.protect
            ~finally:(fun () -> Unix.chmod parent 0o700)
            (fun () ->
              match C.Store.create d with
              | _ -> Alcotest.fail "expected create to fail"
              | exception Failure m ->
                  Alcotest.(check bool) ("names the path: " ^ m) true (contains ~sub:d m))
    );
  ]

(* ---- activity ---- *)

let principal =
  {
    C.Ctx.id = "a@b";
    name = "a";
    auth = "dev";
    groups = [];
    roles = [ C.Rbac.Admin ];
    role = C.Rbac.Admin;
  }

let ctx_for ?max_file_bytes ?window d =
  let store = C.Store.create d in
  C.Activity.init ?max_file_bytes ?window store;
  C.Ctx.create ~config:(config ()) ~store ~index:(C.Index.create ())

let log_n ctx n =
  let rec go i =
    if i > n then Lwt.return_unit
    else
      let* () =
        C.Activity.log ctx principal ~action:"test.action" ~target:(string_of_int i) ()
      in
      go (i + 1)
  in
  go 1

let seqs l = List.map (fun j -> match member "seq" j with `Int n -> n | _ -> -1) l

let activity_tests =
  [
    ( "seq resumes after reopen",
      `Quick,
      fun () ->
        let d = temp_dir "activity" in
        let ctx = ctx_for d in
        Lwt_main.run (log_n ctx 3);
        Alcotest.(check int) "last" 3 (C.Activity.last_seq ctx);
        let ctx' = ctx_for d in
        Alcotest.(check int) "resumed" 3 (C.Activity.last_seq ctx');
        Lwt_main.run (log_n ctx' 1);
        Alcotest.(check (list int))
          "window" [ 4; 3; 2; 1 ]
          (seqs (C.Activity.recent ctx')) );
    ( "rotation by size",
      `Quick,
      fun () ->
        let d = temp_dir "activity" in
        let ctx = ctx_for ~max_file_bytes:600 ~window:3 d in
        Lwt_main.run (log_n ctx 10);
        let rotated =
          Sys.readdir d |> Array.to_list
          |> List.filter (fun f -> String.starts_with ~prefix:"activity-" f)
        in
        Alcotest.(check bool) "rotated files kept" true (List.length rotated >= 2);
        Alcotest.(check bool)
          "first file named by first seq" true
          (List.mem "activity-1.jsonl" rotated);
        List.iter
          (fun f ->
            Alcotest.(check bool)
              (f ^ " under size") true
              ((Unix.stat (Filename.concat d f)).st_size <= 600))
          ("activity.jsonl" :: rotated);
        Alcotest.(check (list int)) "window" [ 10; 9; 8 ] (seqs (C.Activity.recent ctx));
        let all = ref [] in
        Lwt_main.run
          (C.Activity.iter_all ctx (fun j ->
               all := j :: !all;
               Lwt.return_unit));
        Alcotest.(check (list int))
          "iter_all reads every file" (List.init 10 succ)
          (seqs (List.rev !all));
        let ctx' = ctx_for ~max_file_bytes:600 ~window:5 d in
        Alcotest.(check int) "resumed" 10 (C.Activity.last_seq ctx');
        Alcotest.(check (list int))
          "window from the file tails" [ 10; 9; 8; 7; 6 ]
          (seqs (C.Activity.recent ctx')) );
    ( "torn last activity line",
      `Quick,
      fun () ->
        let d = temp_dir "activity" in
        let ctx = ctx_for d in
        Lwt_main.run (log_n ctx 2);
        append_raw (Filename.concat d "activity.jsonl") {|{"seq":3,"act|};
        let ctx' = ctx_for d in
        Alcotest.(check int) "resumed" 2 (C.Activity.last_seq ctx');
        Lwt_main.run (log_n ctx' 1);
        let ctx'' = ctx_for d in
        Alcotest.(check (list int)) "clean" [ 3; 2; 1 ] (seqs (C.Activity.recent ctx''))
    );
    ( "failed append rolls back and never reuses its seq",
      `Quick,
      fun () ->
        let d = temp_dir "activity" in
        let ctx = ctx_for d in
        Lwt_main.run (log_n ctx 2);
        with_io (fun () ->
            partial_write_once ();
            Alcotest.(check bool) "rejected" true (rejects (fun () -> log_n ctx 1)));
        Alcotest.(check int) "seq consumed" 3 (C.Activity.last_seq ctx);
        Lwt_main.run (log_n ctx 1);
        Alcotest.(check (list int)) "window" [ 4; 2; 1 ] (seqs (C.Activity.recent ctx));
        let ctx' = ctx_for d in
        Alcotest.(check (list int)) "on disk" [ 4; 2; 1 ] (seqs (C.Activity.recent ctx'));
        Alcotest.(check int)
          "every line parses" 3
          (List.length (file_lines (Filename.concat d "activity.jsonl"))) );
    ( "failed activity rollback poisons the log",
      `Quick,
      fun () ->
        let d = temp_dir "activity" in
        let ctx = ctx_for d in
        Lwt_main.run (log_n ctx 1);
        with_io (fun () ->
            C.Store.io.fsync <-
              (fun _ -> Lwt.fail (Unix.Unix_error (Unix.EIO, "fsync", "")));
            Alcotest.(check bool) "rejected" true (rejects (fun () -> log_n ctx 1)));
        match Lwt_main.run (log_n ctx 1) with
        | () -> Alcotest.fail "expected the poisoned log to refuse appends"
        | exception Failure m ->
            Alcotest.(check bool) ("clear error: " ^ m) true (contains ~sub:"restart" m)
    );
    ( "directory fsync failure during rotation leaves no stale state",
      `Quick,
      fun () ->
        let d = temp_dir "activity" in
        let ctx = ctx_for ~max_file_bytes:600 d in
        Lwt_main.run (log_n ctx 2);
        let size () = (Unix.stat (Filename.concat d "activity.jsonl")).st_size in
        (* fill the current file to just before the next append rotates it *)
        let last_line () =
          String.length
            (List.hd (List.rev (file_lines (Filename.concat d "activity.jsonl"))))
          + 1
        in
        let rec fill () =
          if size () + last_line () > 600 then ()
          else (
            Lwt_main.run (log_n ctx 1);
            fill ())
        in
        fill ();
        let n0 = C.Activity.last_seq ctx in
        with_io (fun () ->
            C.Store.io.fsync <-
              (fun fd ->
                let* st = Lwt_unix.fstat fd in
                if st.Unix.st_kind = Unix.S_DIR then
                  Lwt.fail (Unix.Unix_error (Unix.EIO, "fsync", ""))
                else Lwt_unix.fsync fd);
            ignore (rejects (fun () -> log_n ctx 1)));
        Alcotest.(check bool)
          "rotated" true
          (Sys.readdir d
          |> Array.exists (fun f -> String.starts_with ~prefix:"activity-" f));
        (* appends work again: no rename of a vanished activity.jsonl *)
        Lwt_main.run (log_n ctx 2);
        let ctx' = ctx_for ~max_file_bytes:600 d in
        Alcotest.(check int) "resumed" (n0 + 3) (C.Activity.last_seq ctx') );
    ( "cancelled append completes",
      `Quick,
      fun () ->
        let d = temp_dir "activity" in
        let ctx = ctx_for d in
        Lwt_main.run (log_n ctx 1);
        with_io (fun () ->
            let gate, open_gate = Lwt.task () in
            let entered, enter = Lwt.wait () in
            C.Store.io.fsync <-
              (fun fd ->
                if Lwt.is_sleeping entered then Lwt.wakeup enter ();
                let* () = gate in
                Lwt_unix.fsync fd);
            Lwt_main.run
              (let p = log_n ctx 1 in
               let* () = entered in
               (* let the write reach the gate before cancelling *)
               let* () = Lwt.pause () in
               Lwt.cancel p;
               Lwt.wakeup open_gate ();
               Lwt.catch (fun () -> p) (fun _ -> Lwt.return_unit)));
        Lwt_main.run (log_n ctx 1);
        Alcotest.(check (list int)) "memory" [ 3; 2; 1 ] (seqs (C.Activity.recent ctx));
        let ctx' = ctx_for d in
        Alcotest.(check (list int)) "disk" [ 3; 2; 1 ] (seqs (C.Activity.recent ctx')) );
    ( "iter_all closes channels when an open fails",
      `Quick,
      fun () ->
        if Unix.geteuid () = 0 then ()
        else
          let d = temp_dir "activity" in
          let ctx = ctx_for ~max_file_bytes:600 d in
          Lwt_main.run (log_n ctx 12);
          let rotated =
            Sys.readdir d |> Array.to_list
            |> List.filter (fun f -> String.starts_with ~prefix:"activity-" f)
            |> List.sort compare
          in
          Alcotest.(check bool) "several files" true (List.length rotated >= 2);
          (* the newest rotated file is opened after the older ones *)
          let last = Filename.concat d (List.nth rotated (List.length rotated - 1)) in
          let open_fds () = Array.length (Sys.readdir "/dev/fd") in
          let before = open_fds () in
          Unix.chmod last 0o000;
          Fun.protect
            ~finally:(fun () -> Unix.chmod last 0o640)
            (fun () ->
              Alcotest.(check bool)
                "fails" true
                (rejects (fun () -> C.Activity.iter_all ctx (fun _ -> Lwt.return_unit))));
          Alcotest.(check int) "no leaked fds" before (open_fds ()) );
    ( "page_desc cursors survive appends",
      `Quick,
      fun () ->
        with_console ~background:false (config ()) (fun r ->
            let page path =
              let* code, j = get r path in
              Alcotest.(check int) path 200 code;
              let items = match member "entries" j with `List l -> l | _ -> [] in
              let next =
                match member "next_cursor" j with `String c -> Some c | _ -> None
              in
              Lwt.return (seqs items, next)
            in
            let* () = log_n r.ctx 5 in
            let* p1, c1 = page "/api/v1/activity?limit=2" in
            Alcotest.(check (list int)) "page 1" [ 5; 4 ] p1;
            let* () = log_n r.ctx 3 in
            let* p2, c2 = page ("/api/v1/activity?limit=2&cursor=" ^ Option.get c1) in
            Alcotest.(check (list int)) "page 2 unshifted" [ 3; 2 ] p2;
            let* p3, c3 = page ("/api/v1/activity?limit=2&cursor=" ^ Option.get c2) in
            Alcotest.(check (list int)) "page 3" [ 1 ] p3;
            Alcotest.(check bool) "end" true (c3 = None);
            let* top, _ = page "/api/v1/activity?limit=2" in
            Alcotest.(check (list int)) "new first page" [ 8; 7 ] top;
            Lwt.return_unit) );
  ]

let () =
  Alcotest.run "console-store"
    [ ("store", store_tests); ("faults", fault_tests); ("activity", activity_tests) ]
