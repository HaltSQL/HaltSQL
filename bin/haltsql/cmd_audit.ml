(* haltsql audit verify: checks the hash chain of HaltSQL audit records (server and proxy
   file/stdout sinks, logs, and the S3/GCS object-sink outputs).

   [cmd] is the [audit] command group (register it in main.ml). Self-contained (no
   Common) so the test suite can build it into a harness binary. Exit codes: 0 every
   chain verifies, 1 a chain is broken, 2 usage or input error. See docs/audit-verify.md.

   [Verify] is the engine (pure apart from reading local files); [S3_read] lists and
   downloads objects with SigV4; the rest is the command line. *)

open Cmdliner
module Chain = Haltsql_cloud.Audit_chain

let exit_ok = 0
let exit_broken = 1
let exit_usage = 2

exception Usage of string

let usage fmt = Printf.ksprintf (fun s -> raise (Usage s)) fmt

module Verify = struct
  type severity = Error | Warning
  type loc = { src : string; line : int }

  type problem = {
    severity : severity;
    kind : string;
        (** stable code: bad_hash, broken_link, duplicate_record, invalid_record,
            not_audit_record, truncated, mid_chain_start, start_mismatch, chain_restart,
            head_mismatch, body_mismatch, unrecognized_name, duplicate_object,
            conflicting_objects, empty_object, seq_gap, run_order, fork, spool_corrupt,
            spool_head_mismatch *)
    where : loc option;
    message : string;
  }

  type start = Genesis | Any | Hash of string

  type opts = {
    start : start;  (** what the first record of an input must link to *)
    strict : bool;  (** a new chain (prev_hash = genesis) mid-stream is an error *)
    mixed : bool;  (** skip lines that are not audit records (logs) *)
    expect_head : string option;  (** the last record's hash must be this *)
  }

  let default_opts =
    { start = Genesis; strict = false; mixed = false; expect_head = None }

  type report = {
    source : string;
    kind : string;  (** file | stdin | files | objects | s3 *)
    mutable records : int;
    mutable objects : int;
    mutable chains : int;
    mutable skipped : int;  (** non-audit lines skipped with [mixed] *)
    mutable heads : (string * string) list;  (** (label, last hash) per chain head *)
    mutable problems : problem list;  (** reversed *)
  }

  let new_report ~source ~kind =
    {
      source;
      kind;
      records = 0;
      objects = 0;
      chains = 0;
      skipped = 0;
      heads = [];
      problems = [];
    }

  let add r severity kind where message =
    r.problems <- { severity; kind; where; message } :: r.problems

  let err r kind where message = add r Error kind where message
  let problems r = List.rev r.problems
  let ok r = not (List.exists (fun p -> p.severity = Error) r.problems)
  let loc_to_string l = Printf.sprintf "%s:%d" l.src l.line

  let first_error r =
    List.find_opt (fun p -> p.severity = Error && p.where <> None) (problems r)

  let is_hex64 h =
    String.length h = 64
    && String.for_all (fun c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) h

  let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))

  (* ---------------------------------------------------------------- *)
  (* One line                                                           *)

  type item =
    | Blank
    | Other  (** not an audit record (skipped with [mixed]) *)
    | Record of { prev : string; hash : string; self : (unit, string) result }
    | Bad of { kind : string; msg : string; claimed : string option }

  (* With [mixed], a log line may carry a prefix (timestamps, container names). *)
  let braces s =
    match (String.index_opt s '{', String.rindex_opt s '}') with
    | Some i, Some j when j > i -> Some (String.sub s i (j - i + 1))
    | _ -> None

  (* Messages never quote the line: records may carry raw SQL. *)
  let classify ~mixed text =
    if String.trim text = "" then Blank
    else
      match if mixed then braces text else Some text with
      | None -> Other
      | Some jt -> (
          match Yojson.Safe.from_string jt with
          | exception Yojson.Json_error _ ->
              if mixed then Other
              else Bad { kind = "invalid_record"; msg = "not valid JSON"; claimed = None }
          | `Assoc kv -> (
              let str k =
                match List.assoc_opt k kv with Some (`String s) -> Some s | _ -> None
              in
              let has k = List.mem_assoc k kv in
              match (str "prev_hash", str "hash") with
              | _ when (not (has "prev_hash")) && not (has "hash") ->
                  if mixed then Other
                  else
                    Bad
                      {
                        kind = "not_audit_record";
                        msg =
                          "JSON object without prev_hash/hash (a log line? --mixed skips \
                           them)";
                        claimed = None;
                      }
              | Some p, Some h when is_hex64 p && is_hex64 h ->
                  let self =
                    match Chain.verify_lines ~initial_prev:None [ jt ] with
                    | Ok _ -> Ok ()
                    | Error (_, m) -> Error m
                  in
                  Record { prev = p; hash = h; self }
              | _, h ->
                  Bad
                    {
                      kind = "invalid_record";
                      msg = "prev_hash/hash missing or not 64 lower-case hex digits";
                      claimed =
                        Option.bind h (fun h -> if is_hex64 h then Some h else None);
                    })
          | _ ->
              if mixed then Other
              else
                Bad { kind = "invalid_record"; msg = "not a JSON object"; claimed = None }
          )

  (* ---------------------------------------------------------------- *)
  (* A linear chain                                                     *)

  type chain = {
    rep : report;
    opts : opts;
    mutable started : bool;
    mutable expected : string option;  (** None: next link unchecked (after garbage) *)
    mutable first_prev : string option;
    mutable head : string option;
    mutable count : int;
    mutable restarts : int;
    seen : (string, loc) Hashtbl.t;  (** record hash -> first location *)
  }

  let new_chain rep opts =
    {
      rep;
      opts;
      started = false;
      expected = None;
      first_prev = None;
      head = None;
      count = 0;
      restarts = 0;
      seen = Hashtbl.create 1024;
    }

  let genesis = Chain.genesis

  let feed_record c loc ~prev ~hash ~self =
    let r = c.rep in
    (match self with
    | Ok () -> ()
    | Error m ->
        err r "bad_hash" (Some loc) (m ^ ": the record's content does not match its hash"));
    match Hashtbl.find_opt c.seen hash with
    | Some l0 when self = Ok () ->
        (* a copy: report it and keep linking to the original *)
        err r "duplicate_record" (Some loc)
          (Printf.sprintf "duplicate of the record at %s" (loc_to_string l0))
    | _ ->
        if not c.started then begin
          c.first_prev <- Some prev;
          match c.opts.start with
          | Any -> ()
          | Genesis when prev = genesis -> ()
          | Hash h when prev = h -> ()
          | Genesis ->
              err r "mid_chain_start" (Some loc)
                "the first record's prev_hash is not genesis: the chain starts \
                 mid-stream (earlier records missing or rotated away; --any-start \
                 verifies from here)"
          | Hash h ->
              err r "start_mismatch" (Some loc)
                (Printf.sprintf
                   "the first record's prev_hash is %s, not --initial-prev %s" prev h)
        end
        else
          begin match c.expected with
          | None -> ()
          | Some e when e = prev -> ()
          | Some _ when prev = genesis ->
              c.restarts <- c.restarts + 1;
              add r
                (if c.opts.strict then Error else Warning)
                "chain_restart" (Some loc)
                "a new chain starts here (prev_hash is genesis): the writer restarted \
                 without continuing the chain"
          | Some _ ->
              let why =
                match Hashtbl.find_opt c.seen prev with
                | Some l0 ->
                    Printf.sprintf
                      "it continues the record at %s instead: records were reordered"
                      (loc_to_string l0)
                | None ->
                    "records before this one were deleted, inserted, reordered or \
                     rewritten"
              in
              err r "broken_link" (Some loc)
                ("prev_hash does not match the previous record's hash; " ^ why)
          end;
        c.started <- true;
        Hashtbl.replace c.seen hash loc;
        c.expected <- Some hash;
        c.head <- Some hash;
        c.count <- c.count + 1;
        r.records <- r.records + 1

  let feed_line c loc text ~terminated =
    match classify ~mixed:c.opts.mixed text with
    | Blank -> ()
    | Other -> c.rep.skipped <- c.rep.skipped + 1
    | Record { prev; hash; self } ->
        if (not terminated) && self <> Ok () then
          err c.rep "truncated" (Some loc) "the last line is incomplete (truncated write)"
        else feed_record c loc ~prev ~hash ~self
    | Bad { kind; msg; claimed } ->
        if not terminated then
          err c.rep "truncated" (Some loc) "the last line is incomplete (truncated write)"
        else err c.rep kind (Some loc) msg;
        (* resynchronise: link to what it claimed, or check nothing next *)
        c.started <- true;
        c.expected <- claimed

  (* Calls [f line_no text ~terminated] for each line; bounded line length. *)
  let max_line = 64 * 1024 * 1024

  let fold_channel ic f =
    let buf = Bytes.create 65536 in
    let acc = Buffer.create 4096 in
    let n = ref 0 in
    let overflow = ref false in
    let emit ~terminated =
      incr n;
      f !n (if !overflow then "\000" else Buffer.contents acc) ~terminated;
      Buffer.clear acc;
      overflow := false
    in
    let add b off len =
      if Buffer.length acc + len > max_line then overflow := true
      else Buffer.add_subbytes acc b off len
    in
    let rec loop () =
      let k = input ic buf 0 (Bytes.length buf) in
      if k = 0 then (if Buffer.length acc > 0 || !overflow then emit ~terminated:false)
      else begin
        let start = ref 0 in
        for i = 0 to k - 1 do
          if Bytes.get buf i = '\n' then begin
            add buf !start (i - !start);
            emit ~terminated:true;
            start := i + 1
          end
        done;
        add buf !start (k - !start);
        loop ()
      end
    in
    loop ()

  let fold_string s f =
    let n = String.length s in
    let rec go line i =
      if i < n then
        match String.index_from_opt s i '\n' with
        | Some j ->
            f line (String.sub s i (j - i)) ~terminated:true;
            go (line + 1) (j + 1)
        | None -> f line (String.sub s i (n - i)) ~terminated:false
    in
    go 1 0

  let finish_chain c ~label =
    let r = c.rep in
    if c.started then r.chains <- r.chains + 1 + c.restarts;
    (match c.head with Some h -> r.heads <- r.heads @ [ (label, h) ] | None -> ());
    match c.opts.expect_head with
    | None -> ()
    | Some h when c.head = Some h -> ()
    | Some h ->
        err r "head_mismatch" None
          (Printf.sprintf
             "the last record's hash is %s, not --expect-head %s: records are missing at \
              the end (truncated) or were appended"
             (Option.value c.head ~default:"(no records)")
             h)

  (* A stream of lines: one file, stdin, or several files in order (--concat). *)
  let verify_streams ~source ~kind opts
      (streams : (string * ((in_channel -> unit) -> unit)) list) =
    let r = new_report ~source ~kind in
    let c = new_chain r opts in
    List.iter
      (fun (src, with_ic) ->
        with_ic (fun ic ->
            fold_channel ic (fun line text ~terminated ->
                feed_line c { src; line } text ~terminated)))
      streams;
    finish_chain c ~label:source;
    r

  let with_file path f = In_channel.with_open_bin path f

  let verify_file ?(opts = default_opts) path =
    verify_streams ~source:path ~kind:"file" opts [ (path, with_file path) ]

  let verify_string ?(opts = default_opts) ~source s =
    let r = new_report ~source ~kind:"file" in
    let c = new_chain r opts in
    fold_string s (fun line text ~terminated ->
        feed_line c { src = source; line } text ~terminated);
    finish_chain c ~label:source;
    r

  (* ---------------------------------------------------------------- *)
  (* Object-sink outputs                                                *)

  type obj = {
    key : string;
    host : string;
    run : string;
    seq : int;
    sha : string;
    body : string;
  }

  let valid_run r =
    r <> ""
    && String.length r <= 64
    && String.for_all
         (fun c ->
           (c >= 'a' && c <= 'z')
           || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9')
           || c = '.')
         r

  let valid_host h =
    h <> ""
    && String.for_all
         (fun c ->
           (c >= 'a' && c <= 'z')
           || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9')
           || c = '-' || c = '.' || c = '_')
         h

  (* <host>-<run>-<seq:10 digits>-<sha256>.jsonl; the run id has no '-'. *)
  let parse_name key =
    let base = Filename.basename key in
    let n = String.length base in
    if n < 6 + 64 + 1 + 10 + 1 + 3 || not (Filename.check_suffix base ".jsonl") then None
    else
      let stem = String.sub base 0 (n - 6) in
      let m = String.length stem in
      let sha = String.sub stem (m - 64) 64 in
      let seq_s = String.sub stem (m - 64 - 11) 10 in
      if
        (not (is_hex64 sha))
        || stem.[m - 65] <> '-'
        || stem.[m - 76] <> '-'
        || not (String.for_all (fun c -> c >= '0' && c <= '9') seq_s)
      then None
      else
        let hr = String.sub stem 0 (m - 76) in
        match String.rindex_opt hr '-' with
        | None -> None
        | Some i ->
            let host = String.sub hr 0 i
            and run = String.sub hr (i + 1) (String.length hr - i - 1) in
            if valid_host host && valid_run run then
              Some (host, run, int_of_string seq_s, sha)
            else None

  type run_summary = {
    r_host : string;
    r_run : string;
    r_first_seq : int;
    r_last_seq : int;
    r_first_prev : string option;
    r_head : string option;
    r_first_key : string;
  }

  type spool = {
    sp_dir : string;
    sp_head : (int * string) option;
    sp_batches : (int * string * string) list;  (** seq, file, body *)
    sp_current : (string * string) option;  (** file, body *)
  }

  let read_spool rep dir =
    let path f = Filename.concat dir f in
    let read f = In_channel.with_open_bin f In_channel.input_all in
    let head =
      let f = path "head.json" in
      if not (Sys.file_exists f) then None
      else
        match Yojson.Safe.from_string (read f) with
        | `Assoc kv -> (
            match (List.assoc_opt "seq" kv, List.assoc_opt "prev" kv) with
            | Some (`Int s), Some (`String p) when s >= 0 && is_hex64 p -> Some (s, p)
            | _ ->
                err rep "spool_corrupt"
                  (Some { src = f; line = 1 })
                  "head.json is corrupt";
                None)
        | _ | (exception Yojson.Json_error _) ->
            err rep "spool_corrupt" (Some { src = f; line = 1 }) "head.json is corrupt";
            None
    in
    let batches =
      Sys.readdir dir |> Array.to_list |> List.sort compare
      |> List.filter_map (fun f ->
          if
            String.length f = 22
            && String.sub f 0 6 = "batch-"
            && Filename.check_suffix f ".jsonl"
          then
            Option.map
              (fun s -> (s, path f, read (path f)))
              (int_of_string_opt (String.sub f 6 10))
          else None)
    in
    let current =
      let f = path "current.jsonl" in
      if Sys.file_exists f then Some (f, read f) else None
    in
    { sp_dir = dir; sp_head = head; sp_batches = batches; sp_current = current }

  let feed_body c ~src body =
    fold_string body (fun line text ~terminated ->
        feed_line c { src; line } text ~terminated)

  (* [items]: (object key, body). [spool]: the sink's local spool directory. *)
  let verify_objects ?(opts = default_opts) ?host ?spool ~source ~kind items =
    let r = new_report ~source ~kind in
    let by_sha = Hashtbl.create 64 and by_id = Hashtbl.create 64 in
    let objs =
      List.filter_map
        (fun (key, body) ->
          if not (Filename.check_suffix key ".jsonl") then None
          else
            match parse_name key with
            | None ->
                err r "unrecognized_name"
                  (Some { src = key; line = 0 })
                  "not a <host>-<run>-<seq>-<sha256>.jsonl object name";
                None
            | Some (h, run, seq, sha) -> (
                r.objects <- r.objects + 1;
                let actual = sha256_hex body in
                if actual <> sha then
                  err r "body_mismatch"
                    (Some { src = key; line = 0 })
                    "the object body does not match the SHA-256 in its name (modified or \
                     truncated)";
                match Hashtbl.find_opt by_sha actual with
                | Some k0 ->
                    err r "duplicate_object"
                      (Some { src = key; line = 0 })
                      (Printf.sprintf "same body as %s: the object was stored twice" k0);
                    None
                | None -> (
                    Hashtbl.add by_sha actual key;
                    match Hashtbl.find_opt by_id (h, run, seq) with
                    | Some k0 ->
                        err r "conflicting_objects"
                          (Some { src = key; line = 0 })
                          (Printf.sprintf "seq %d of run %s is also claimed by %s" seq run
                             k0);
                        None
                    | None ->
                        Hashtbl.add by_id (h, run, seq) key;
                        Some { key; host = h; run; seq; sha; body })))
        (List.sort (fun (a, _) (b, _) -> compare a b) items)
    in
    let objs =
      match host with Some h -> List.filter (fun o -> o.host = h) objs | None -> objs
    in
    let hosts = List.sort_uniq compare (List.map (fun o -> o.host) objs) in
    let summaries = ref [] in
    List.iter
      (fun h ->
        let mine = List.filter (fun o -> o.host = h) objs in
        let runs = List.sort_uniq compare (List.map (fun o -> o.run) mine) in
        (* each run: one chain over its objects in seq order *)
        let runs =
          List.map
            (fun run ->
              let os =
                List.filter (fun o -> o.run = run) mine
                |> List.sort (fun a b -> compare a.seq b.seq)
              in
              let c =
                new_chain r { opts with start = Any; strict = true; expect_head = None }
              in
              let prev_seq = ref None in
              List.iter
                (fun o ->
                  (match !prev_seq with
                  | Some p when o.seq <> p + 1 ->
                      err r "seq_gap"
                        (Some { src = o.key; line = 0 })
                        (Printf.sprintf "objects with seq %d..%d of run %s are missing"
                           (p + 1) (o.seq - 1) run)
                  | _ -> ());
                  prev_seq := Some o.seq;
                  let n0 = c.count in
                  if o.body = "" then
                    err r "empty_object"
                      (Some { src = o.key; line = 0 })
                      "the object is empty"
                  else begin
                    if o.body.[String.length o.body - 1] <> '\n' then
                      err r "truncated"
                        (Some { src = o.key; line = 0 })
                        "the object body does not end with a newline (truncated)";
                    feed_body c ~src:o.key o.body;
                    if c.count = n0 then
                      err r "empty_object"
                        (Some { src = o.key; line = 0 })
                        "the object holds no audit record"
                  end)
                os;
              let first = List.hd os and last = List.nth os (List.length os - 1) in
              ( {
                  r_host = h;
                  r_run = run;
                  r_first_seq = first.seq;
                  r_last_seq = last.seq;
                  r_first_prev = c.first_prev;
                  r_head = c.head;
                  r_first_key = first.key;
                },
                c ))
            runs
        in
        (* link the runs of this host: spool continuity across restarts *)
        let by_head = Hashtbl.create 8 in
        List.iter
          (fun (s, _) -> Option.iter (fun hd -> Hashtbl.replace by_head hd s) s.r_head)
          runs;
        let continued = Hashtbl.create 8 in
        List.iteri
          (fun i (s, _) ->
            let at = Some { src = s.r_first_key; line = 1 } in
            match s.r_first_prev with
            | None -> ()
            | Some p when p = genesis ->
                r.chains <- r.chains + 1;
                if s.r_first_seq <> 0 then
                  err r "seq_gap" at
                    (Printf.sprintf
                       "run %s starts a new chain at seq %d: objects 0..%d are missing"
                       s.r_run s.r_first_seq (s.r_first_seq - 1));
                if i > 0 then
                  add r
                    (if opts.strict then Error else Warning)
                    "chain_restart" at
                    (Printf.sprintf
                       "run %s starts a new chain (no spool continuity with the earlier \
                        runs of host %s)"
                       s.r_run h)
            | Some p -> (
                match Hashtbl.find_opt by_head p with
                | Some pred ->
                    if Hashtbl.mem continued pred.r_run then
                      err r "fork" at
                        (Printf.sprintf "run %s and run %s both continue run %s" s.r_run
                           (Hashtbl.find continued pred.r_run)
                           pred.r_run)
                    else Hashtbl.add continued pred.r_run s.r_run;
                    if compare pred.r_run s.r_run > 0 then
                      err r "run_order" at
                        (Printf.sprintf
                           "run %s continues run %s, which started later: runs are out \
                            of order"
                           s.r_run pred.r_run);
                    if s.r_first_seq <> pred.r_last_seq + 1 then
                      err r "seq_gap" at
                        (Printf.sprintf
                           "run %s continues run %s (last seq %d) at seq %d: objects are \
                            missing between the runs"
                           s.r_run pred.r_run pred.r_last_seq s.r_first_seq)
                | None -> (
                    r.chains <- r.chains + 1;
                    if i > 0 then
                      err r "broken_link" at
                        (Printf.sprintf
                           "run %s's first record links to a hash found in no provided \
                            object: objects of an earlier run were deleted or are \
                            missing"
                           s.r_run)
                    else
                      match opts.start with
                      | Any -> ()
                      | Hash x when x = p -> ()
                      | Hash x ->
                          err r "start_mismatch" at
                            (Printf.sprintf
                               "the first record's prev_hash is %s, not --initial-prev %s"
                               p x)
                      | Genesis ->
                          err r "mid_chain_start" at
                            (Printf.sprintf
                               "run %s does not start at genesis and continues no \
                                provided object: earlier objects are missing \
                                (--any-start verifies from here)"
                               s.r_run))))
          runs;
        let tails =
          List.filter (fun (s, _) -> not (Hashtbl.mem continued s.r_run)) runs
        in
        List.iter
          (fun (s, _) ->
            Option.iter
              (fun hd ->
                r.heads <-
                  r.heads @ [ (Printf.sprintf "%s/%s seq %d" h s.r_run s.r_last_seq, hd) ])
              s.r_head)
          tails;
        summaries := !summaries @ tails)
      hosts;
    (* --expect-head: the newest tail *)
    (match opts.expect_head with
    | None -> ()
    | Some x ->
        if not (List.exists (fun (s, _) -> s.r_head = Some x) !summaries) then
          err r "head_mismatch" None
            (Printf.sprintf
               "no chain ends at --expect-head %s: objects are missing at the end or \
                were appended"
               x));
    (* spool head continuity *)
    (match spool with
    | None -> ()
    | Some dir -> (
        if List.length hosts > 1 then
          usage "--spool needs the objects of exactly one host (found %d; use --host)"
            (List.length hosts);
        let sp = read_spool r dir in
        let tail =
          match
            List.rev (List.sort (fun (a, _) (b, _) -> compare a.r_run b.r_run) !summaries)
          with
          | (s, _) :: _ -> Some s
          | [] -> None
        in
        let start, next_seq =
          match tail with
          | Some { r_head = Some hd; r_last_seq; _ } -> (Hash hd, Some (r_last_seq + 1))
          | _ -> (Any, None)
        in
        let c = new_chain r { opts with start; strict = true; expect_head = None } in
        let last_sealed =
          ref
            (match tail with
            | Some s -> Option.map (fun h -> (s.r_last_seq, h)) s.r_head
            | None -> None)
        in
        let expect_seq = ref next_seq in
        List.iter
          (fun (seq, file, body) ->
            if Hashtbl.mem by_sha (sha256_hex body) then () (* already uploaded *)
            else begin
              (match !expect_seq with
              | Some e when seq <> e ->
                  err r "seq_gap"
                    (Some { src = file; line = 0 })
                    (Printf.sprintf "spool batch seq %d does not follow seq %d" seq (e - 1))
              | _ -> ());
              expect_seq := Some (seq + 1);
              feed_body c ~src:file body;
              Option.iter (fun h -> last_sealed := Some (seq, h)) c.head
            end)
          sp.sp_batches;
        Option.iter (fun (file, body) -> feed_body c ~src:file body) sp.sp_current;
        if c.count > 0 then r.heads <- r.heads @ [ (dir, Option.get c.head) ];
        let head_file = Some { src = Filename.concat dir "head.json"; line = 1 } in
        match (sp.sp_head, !last_sealed) with
        | None, _ -> ()
        | Some (hseq, hprev), Some (lseq, lhash) ->
            if hseq > lseq + 1 then
              err r "spool_head_mismatch" head_file
                (Printf.sprintf
                   "head.json says batches up to seq %d were sealed, but the newest \
                    provided object or spooled batch has seq %d: objects are missing at \
                    the end"
                   (hseq - 1) lseq)
            else if hseq < lseq + 1 then
              err r "spool_head_mismatch" head_file
                (Printf.sprintf
                   "head.json (next seq %d) is behind the newest object (seq %d): the \
                    spool belongs to another sink or was replaced"
                   hseq lseq)
            else if hprev <> lhash then
              err r "spool_head_mismatch" head_file
                "head.json's chain head is not the hash of the last sealed record"
        | Some (hseq, _), None ->
            err r "spool_head_mismatch" head_file
              (Printf.sprintf
                 "head.json says batches up to seq %d were sealed, but no object was \
                  provided"
                 (hseq - 1))));
    r

  (* Local directory of downloaded objects (recursive, symlinks not followed). *)
  let read_dir dir =
    let rec walk acc rel =
      let abs = if rel = "" then dir else Filename.concat dir rel in
      Array.fold_left
        (fun acc f ->
          let rel' = if rel = "" then f else Filename.concat rel f in
          let p = Filename.concat abs f in
          match (Unix.lstat p).Unix.st_kind with
          | Unix.S_DIR -> walk acc rel'
          | Unix.S_REG when Filename.check_suffix f ".jsonl" ->
              (rel', In_channel.with_open_bin p In_channel.input_all) :: acc
          | _ -> acc)
        acc
        (let a = Sys.readdir abs in
         Array.sort compare a;
         a)
    in
    List.rev (walk [] "")

  (* ---------------------------------------------------------------- *)
  (* Output                                                             *)

  let severity_name = function Error -> "error" | Warning -> "warning"

  let problem_json p : Yojson.Safe.t =
    `Assoc
      ([ ("severity", `String (severity_name p.severity)); ("kind", `String p.kind) ]
      @ (match p.where with
        | Some l ->
            [ ("source", `String l.src) ]
            @ if l.line > 0 then [ ("line", `Int l.line) ] else []
        | None -> [])
      @ [ ("message", `String p.message) ])

  let report_json r : Yojson.Safe.t =
    `Assoc
      [
        ("source", `String r.source);
        ("kind", `String r.kind);
        ("ok", `Bool (ok r));
        ("records", `Int r.records);
        ("objects", `Int r.objects);
        ("chains", `Int r.chains);
        ("skipped_lines", `Int r.skipped);
        ( "heads",
          `List
            (List.map
               (fun (l, h) -> `Assoc [ ("chain", `String l); ("hash", `String h) ])
               r.heads) );
        ("problems", `List (List.map problem_json (problems r)));
      ]

  let summary_json reports : Yojson.Safe.t =
    let first = List.find_map (fun r -> first_error r) reports in
    `Assoc
      [
        ("ok", `Bool (List.for_all ok reports));
        ("records", `Int (List.fold_left (fun a r -> a + r.records) 0 reports));
        ("inputs", `List (List.map report_json reports));
        ("first_broken", match first with Some p -> problem_json p | None -> `Null);
      ]

  let print_text oc reports =
    List.iter
      (fun r ->
        Printf.fprintf oc "%s: %s, %d record%s" r.source
          (if ok r then "OK" else "BROKEN")
          r.records
          (if r.records = 1 then "" else "s");
        if r.objects > 0 then
          Printf.fprintf oc " in %d object%s" r.objects
            (if r.objects = 1 then "" else "s");
        Printf.fprintf oc ", %d chain%s" r.chains (if r.chains = 1 then "" else "s");
        if r.skipped > 0 then Printf.fprintf oc ", %d non-audit line(s) skipped" r.skipped;
        output_char oc '\n';
        List.iter (fun (l, h) -> Printf.fprintf oc "  head %s: %s\n" l h) r.heads;
        List.iter
          (fun p ->
            Printf.fprintf oc "  %s %s%s: %s\n" (severity_name p.severity) p.kind
              (match p.where with
              | Some l when l.line > 0 -> " at " ^ loc_to_string l
              | Some l -> " at " ^ l.src
              | None -> "")
              p.message)
          (problems r))
      reports;
    match List.find_map first_error reports with
    | Some p ->
        Printf.fprintf oc "first broken link: %s: %s\n"
          (match p.where with
          | Some l when l.line > 0 -> loc_to_string l
          | Some l -> l.src
          | None -> "")
          p.message
    | None -> ()
end

(* ------------------------------------------------------------------ *)
(* Direct S3 read (S3 and S3-compatible endpoints)                       *)

module S3_read = struct
  open Lwt.Syntax
  module Http = Haltsql_cloud.Http

  type target = { bucket : string; prefix : string }

  let parse_url u =
    let p = "s3://" in
    let lp = String.length p in
    if String.length u <= lp || String.sub u 0 lp <> p then None
    else
      let rest = String.sub u lp (String.length u - lp) in
      let bucket, prefix =
        match String.index_opt rest '/' with
        | Some i ->
            (String.sub rest 0 i, String.sub rest (i + 1) (String.length rest - i - 1))
        | None -> (rest, "")
      in
      if
        String.length bucket >= 3
        && String.length bucket <= 63
        && String.for_all
             (fun c ->
               (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c = '-' || c = '.')
             bucket
      then Some { bucket; prefix }
      else None

  let base ~endpoint ~region t =
    match endpoint with
    | Some e ->
        let e =
          if String.length e > 0 && e.[String.length e - 1] = '/' then
            String.sub e 0 (String.length e - 1)
          else e
        in
        Printf.sprintf "%s/%s" e t.bucket
    | None -> Printf.sprintf "https://%s.s3.%s.amazonaws.com" t.bucket region

  let signed_get ~creds ~region ?(max_body = 8 * 1024 * 1024) uri =
    let* c = Haltsql_cloud.Aws_creds.get creds in
    match c with
    | Error m -> Lwt.return (Error ("credentials: " ^ m))
    | Ok c -> (
        let headers =
          Haltsql_cloud.Sigv4.sign ~s3:true c ~service:"s3" ~region
            ~time:(Unix.gettimeofday ()) ~meth:"GET" ~uri ~headers:[] ~payload:""
        in
        let* r = Http.request ~timeout:60. ~max_body ~headers `GET uri in
        match r with
        | Error m -> Lwt.return (Error m)
        | Ok r when r.status >= 200 && r.status < 300 -> Lwt.return (Ok r.body)
        | Ok r ->
            let code =
              Option.value ~default:"" (Haltsql_cloud.Cloud_util.xml_tag r.body "Code")
            in
            Lwt.return (Error (Printf.sprintf "S3 GET returned HTTP %d %s" r.status code))
        )

  let split_on s sep =
    let n = String.length sep in
    let rec go acc i =
      let rec find j =
        if j + n > String.length s then None
        else if String.sub s j n = sep then Some j
        else find (j + 1)
      in
      match find i with
      | Some j -> go (String.sub s i (j - i) :: acc) (j + n)
      | None -> List.rev (String.sub s i (String.length s - i) :: acc)
    in
    go [] 0

  (* ListObjectsV2 (all pages), then GET every .jsonl object. *)
  let fetch ~endpoint ~region ~creds ?(max_objects = 1_000_000) t =
    let base = base ~endpoint ~region t in
    let rec list acc token pages =
      let q =
        [ ("list-type", [ "2" ]); ("prefix", [ t.prefix ]) ]
        @ match token with Some k -> [ ("continuation-token", [ k ]) ] | None -> []
      in
      let uri = Uri.with_query (Uri.of_string (base ^ "/")) q in
      let* r = signed_get ~creds ~region uri in
      match r with
      | Error e ->
          Lwt.return (Error ("listing s3://" ^ t.bucket ^ "/" ^ t.prefix ^ ": " ^ e))
      | Ok body -> (
          let keys =
            match split_on body "<Contents>" with
            | [] | [ _ ] -> []
            | _ :: chunks ->
                List.filter_map
                  (fun ch -> Haltsql_cloud.Cloud_util.xml_tag ch "Key")
                  chunks
          in
          let acc = List.rev_append keys acc in
          if List.length acc > max_objects then
            Lwt.return
              (Error (Printf.sprintf "more than %d objects under the prefix" max_objects))
          else
            match
              ( Haltsql_cloud.Cloud_util.xml_tag body "IsTruncated",
                Haltsql_cloud.Cloud_util.xml_tag body "NextContinuationToken" )
            with
            | Some "true", Some k when pages < 100_000 -> list acc (Some k) (pages + 1)
            | Some "true", _ ->
                Lwt.return (Error "S3 listing is truncated without a continuation token")
            | _ -> Lwt.return (Ok (List.rev acc)))
    in
    let* keys = list [] None 0 in
    match keys with
    | Error e -> Lwt.return (Error e)
    | Ok keys ->
        let keys = List.filter (fun k -> Filename.check_suffix k ".jsonl") keys in
        let rec get acc = function
          | [] -> Lwt.return (Ok (List.rev acc))
          | k :: rest -> (
              let uri = Uri.of_string (base ^ "/" ^ Http.pct_encode ~keep_slash:true k) in
              let* r = signed_get ~creds ~region ~max_body:(512 * 1024 * 1024) uri in
              match r with
              | Error e -> Lwt.return (Error (Printf.sprintf "downloading %s: %s" k e))
              | Ok body -> get ((k, body) :: acc) rest)
        in
        get [] keys
end

(* ------------------------------------------------------------------ *)
(* Command line                                                         *)

let exits =
  [
    Cmd.Exit.info 0 ~doc:"when every chain verifies.";
    Cmd.Exit.info 1
      ~doc:"when a chain is broken (tampering, gaps, truncation, bad hashes).";
    Cmd.Exit.info 2 ~doc:"on usage errors or when an input cannot be read.";
  ]

let man_examples ex =
  `S Manpage.s_examples
  :: List.concat_map (fun e -> [ `Pre (Manpage.escape e); `Noblank ]) ex

let run_verify inputs concat json any_start initial_prev strict mixed expect_head spool
    host endpoint region =
  try
    if inputs = [] then
      usage "no input (give files, directories, - for stdin or s3://bucket/prefix)";
    let hex what h =
      if Verify.is_hex64 h then h else usage "%s must be 64 lower-case hex digits" what
    in
    let start =
      match (any_start, initial_prev) with
      | true, Some _ -> usage "--any-start and --initial-prev are mutually exclusive"
      | true, None -> Verify.Any
      | false, Some h -> Verify.Hash (hex "--initial-prev" h)
      | false, None -> Verify.Genesis
    in
    let opts =
      {
        Verify.start;
        strict;
        mixed;
        expect_head = Option.map (hex "--expect-head") expect_head;
      }
    in
    let is_s3 i = String.length i > 5 && String.sub i 0 5 = "s3://" in
    let stdin_count = List.length (List.filter (( = ) "-") inputs) in
    if stdin_count > 1 then usage "- (stdin) can be given only once";
    List.iter
      (fun i ->
        if i <> "-" && (not (is_s3 i)) && not (Sys.file_exists i) then
          usage "%s: no such file or directory" i)
      inputs;
    let is_dir i = i <> "-" && (not (is_s3 i)) && Sys.is_directory i in
    if
      (spool <> None || host <> None)
      && not (List.exists (fun i -> is_dir i || is_s3 i) inputs)
    then usage "--spool and --host apply to object directories and s3:// inputs";
    if
      spool <> None && List.length (List.filter (fun i -> is_dir i || is_s3 i) inputs) > 1
    then usage "--spool applies to a single object directory or s3:// input";
    Option.iter
      (fun d ->
        if not (Sys.file_exists d && Sys.is_directory d) then
          usage "%s: not a directory" d)
      spool;
    let stream_of i =
      if i = "-" then ("stdin", fun f -> f stdin)
      else (i, fun f -> In_channel.with_open_bin i f)
    in
    let objects ~source ~kind items =
      if not (List.exists (fun (k, _) -> Filename.check_suffix k ".jsonl") items) then
        usage "%s: no .jsonl audit objects found" source;
      Verify.verify_objects ~opts ?host ?spool ~source ~kind items
    in
    let fetch_s3 i =
      match S3_read.parse_url i with
      | None -> usage "%s: expected s3://bucket/prefix" i
      | Some t -> (
          Option.iter
            (fun e ->
              match Haltsql_cloud.Http.check_endpoint ~what:"--endpoint" e with
              | Ok _ -> ()
              | Error m -> usage "%s" m)
            endpoint;
          let region =
            match region with
            | Some r -> r
            | None -> Option.value ~default:"us-east-1" (Sys.getenv_opt "AWS_REGION")
          in
          let creds =
            Haltsql_cloud.Aws_creds.create ~region Haltsql_cloud.Aws_creds.default_chain
          in
          match Lwt_main.run (S3_read.fetch ~endpoint ~region ~creds t) with
          | Ok items -> objects ~source:i ~kind:"s3" items
          | Error e -> usage "%s" e)
    in
    let reports =
      if concat then begin
        if List.exists (fun i -> is_dir i || is_s3 i) inputs then
          usage "--concat joins files and stdin only";
        [
          Verify.verify_streams ~source:(String.concat " + " inputs) ~kind:"files" opts
            (List.map stream_of inputs);
        ]
      end
      else
        List.map
          (fun i ->
            if is_s3 i then fetch_s3 i
            else if is_dir i then objects ~source:i ~kind:"objects" (Verify.read_dir i)
            else
              let src, f = stream_of i in
              Verify.verify_streams ~source:src
                ~kind:(if i = "-" then "stdin" else "file")
                opts
                [ (src, f) ])
          inputs
    in
    if json then
      print_endline (Yojson.Safe.pretty_to_string (Verify.summary_json reports))
    else Verify.print_text stdout reports;
    if List.for_all Verify.ok reports then exit_ok else exit_broken
  with
  | Usage m ->
      prerr_endline ("haltsql: " ^ m);
      exit_usage
  | Sys_error m ->
      prerr_endline ("haltsql: " ^ m);
      exit_usage
  | Unix.Unix_error (e, f, a) ->
      prerr_endline (Printf.sprintf "haltsql: %s %s: %s" f a (Unix.error_message e));
      exit_usage

let verify_cmd =
  let inputs =
    Arg.(
      value & pos_all string []
      & info [] ~docv:"INPUT"
          ~doc:
            "An audit file (JSON lines from a file or stdout sink, or a log with \
             $(b,--mixed)), a directory of downloaded S3/GCS audit objects, $(b,-) for \
             stdin, or $(b,s3://BUCKET/PREFIX) to read the objects directly.")
  in
  let concat =
    Arg.(
      value & flag
      & info [ "concat" ]
          ~doc:"Treat the file inputs, in the order given, as one chain (rotated files).")
  in
  let json = Arg.(value & flag & info [ "json" ] ~doc:"Machine-readable JSON output.") in
  let any_start =
    Arg.(
      value & flag
      & info [ "any-start" ]
          ~doc:
            "Accept a chain that starts mid-stream (the first record's prev_hash is not \
             genesis), e.g. one day of objects or a rotated file.")
  in
  let initial_prev =
    Arg.(
      value
      & opt (some string) None
      & info [ "initial-prev" ] ~docv:"HASH"
          ~doc:"The first record must link to $(docv) (the head of the previous segment).")
  in
  let strict =
    Arg.(
      value & flag
      & info [ "strict" ]
          ~doc:
            "Treat a new chain starting mid-stream (a restart without chain continuity) \
             as an error instead of a warning.")
  in
  let mixed =
    Arg.(
      value & flag
      & info [ "mixed" ]
          ~doc:
            "Skip lines that are not audit records (operational log lines, container log \
             prefixes) instead of reporting them.")
  in
  let expect_head =
    Arg.(
      value
      & opt (some string) None
      & info [ "expect-head" ] ~docv:"HASH"
          ~doc:
            "The last record's hash must be $(docv) (a head recorded elsewhere): detects \
             records missing at the end.")
  in
  let spool =
    Arg.(
      value
      & opt (some string) None
      & info [ "spool" ] ~docv:"DIR"
          ~doc:
            "The object sink's spool directory: its unuploaded batches and current.jsonl \
             must continue the objects' chain, and head.json must name the last sealed \
             record (detects objects missing at the end).")
  in
  let host =
    Arg.(
      value
      & opt (some string) None
      & info [ "host" ] ~docv:"HOST"
          ~doc:"Only verify the objects written by host $(docv).")
  in
  let endpoint =
    Arg.(
      value
      & opt (some string) None
      & info [ "endpoint" ] ~docv:"URL"
          ~doc:
            "S3-compatible endpoint for s3:// inputs (path-style; https, or http on \
             loopback). Default: AWS virtual-hosted URLs.")
  in
  let region =
    Arg.(
      value
      & opt (some string) None
      & info [ "region" ] ~docv:"REGION"
          ~doc:"Signing region for s3:// inputs (default: AWS_REGION, else us-east-1).")
  in
  let doc = "Verify the hash chain of HaltSQL audit records." in
  let man =
    [
      `S Manpage.s_description;
      `P
        "Checks that every record's hash matches its content and that each record links \
         to the previous one, for the records written by haltsql-server and \
         haltsql-proxy (file and stdout sinks, logs with $(b,--mixed)) and by the S3/GCS \
         object sinks (objects named <host>-<run>-<seq>-<sha256>.jsonl: body hashes, \
         sequence gaps, duplicated or reordered objects, chain continuity across runs \
         and, with $(b,--spool), against the spool's head).";
      `P
        "Reports every problem with its location and the first broken link. Credentials \
         for s3:// inputs come from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (optional \
         AWS_SESSION_TOKEN), web identity or the instance profile. See \
         docs/audit-verify.md.";
    ]
    @ man_examples
        [
          "haltsql audit verify /var/log/haltsql/audit.jsonl";
          "haltsql audit verify --concat audit.jsonl.1 audit.jsonl";
          "kubectl logs deploy/haltsql-proxy | haltsql audit verify --mixed -";
          "haltsql audit verify --json ./downloaded-objects/";
          "haltsql audit verify --spool /var/lib/haltsql/spool ./objects/";
          "haltsql audit verify --endpoint http://127.0.0.1:9000 \
           s3://audit/haltsql/audit/";
        ]
  in
  Cmd.v
    (Cmd.info "verify" ~doc ~man ~exits)
    Term.(
      const run_verify $ inputs $ concat $ json $ any_start $ initial_prev $ strict
      $ mixed $ expect_head $ spool $ host $ endpoint $ region)

let cmd = Cmd.group (Cmd.info "audit" ~doc:"Audit log tools." ~exits) [ verify_cmd ]
