(** Batching, spooling, hash-chained object-store audit sink; see object_sink.mli. *)

open Lwt.Infix
module Config = Haltsql_load.Config

type upload_error = Retryable of string | Permanent of string
type uploader = key:string -> body:string -> (unit, upload_error) result Lwt.t

type pending = {
  key : string;
  body : string;
  records : int;
  spool : string option;  (** spooled batch file, removed after upload *)
  key_file : string option;  (** its persisted object name, removed with it *)
}

type stats = {
  records_written : int;
  objects_uploaded : int;
  upload_failures : int;
  write_rejections : int;
  buffered_records : int;
  pending_objects : int;
  last_error : string option;
  chain_head : string;
}

type t = {
  name : string;
  prefix : string;
  host : string;
  run_id : string;
  max_records : int;
  max_seconds : float;
  on_error : Config.on_error;
  max_buffer : int;
  max_attempts : int;
  base_backoff : float;
  uploader : uploader;
  now : unit -> float;
  spool_dir : string option;
  on_event : string -> unit;
  mutable cur : string list;
  mutable cur_n : int;
  mutable cur_started : float;
  mutable cur_fd : Unix.file_descr option;
  pending : pending Queue.t;
  mutable pending_records : int;
  mutable prev : string;
  mutable seq : int;
  mutable failed : bool;
  mutable next_retry : float;
  mutable last_error : string option;
  lock : Lwt_mutex.t;
  wake : unit Lwt_condition.t;
  mutable running : bool;
  mutable stopped : bool;
  mutable n_written : int;
  mutable n_uploaded : int;
  mutable n_failures : int;
  mutable n_rejected : int;
}

let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))

let object_key ~prefix ~host ~run ~seq ~time body =
  let tm = Unix.gmtime time in
  Printf.sprintf "%s%04d/%02d/%02d/%02d/%s-%s-%010d-%s.jsonl" prefix (tm.tm_year + 1900)
    (tm.tm_mon + 1) tm.tm_mday tm.tm_hour host run seq (sha256_hex body)

let valid_run_id r =
  r <> ""
  && String.length r <= 64
  && String.for_all
       (fun c ->
         (c >= 'a' && c <= 'z')
         || (c >= 'A' && c <= 'Z')
         || (c >= '0' && c <= '9')
         || c = '.')
       r

(* UTC start time with microseconds, then the pid (and a counter for further
   sinks in the same process): unique per host and lexicographically ordered by
   start time, so sorting object names within an hour directory puts runs in
   boot order. *)
let runs_created = ref 0

let default_run_id now =
  let n = !runs_created in
  incr runs_created;
  let t = now () in
  let tm = Unix.gmtime t in
  let us = int_of_float ((t -. Float.of_int (int_of_float t)) *. 1e6) in
  Printf.sprintf "%04d%02d%02dT%02d%02d%02d.%06dZ.%d" (tm.tm_year + 1900) (tm.tm_mon + 1)
    tm.tm_mday tm.tm_hour tm.tm_min tm.tm_sec
    (max 0 (min 999_999 us))
    (Unix.getpid ())
  ^ if n = 0 then "" else Printf.sprintf ".%d" n

let sanitize_host h =
  let h =
    String.map
      (fun c ->
        if
          (c >= 'a' && c <= 'z')
          || (c >= 'A' && c <= 'Z')
          || (c >= '0' && c <= '9')
          || c = '-' || c = '.'
        then c
        else '_')
      h
  in
  if h = "" then "unknown" else if String.length h > 63 then String.sub h 0 63 else h

let current_file dir = Filename.concat dir "current.jsonl"
let batch_file dir seq = Filename.concat dir (Printf.sprintf "batch-%010d.jsonl" seq)
let key_file dir seq = Filename.concat dir (Printf.sprintf "batch-%010d.key" seq)
let head_file dir = Filename.concat dir "head.json"

(* Durable small-file write: temp file, fsync, rename. *)
let write_atomic path data =
  let tmp = path ^ ".tmp" in
  let fd =
    Unix.openfile tmp [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC; Unix.O_CLOEXEC ] 0o600
  in
  Fun.protect
    ~finally:(fun () -> try Unix.close fd with _ -> ())
    (fun () ->
      let n = String.length data in
      let rec go off =
        if off < n then go (off + Unix.write_substring fd data off (n - off))
      in
      go 0;
      Unix.fsync fd);
  Unix.rename tmp path

let is_hex64 h =
  String.length h = 64
  && String.for_all (fun c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) h

(* The chain head and next sequence number, persisted whenever a batch is
   sealed so that a restart continues the chain even when every batch has
   already been uploaded and removed from the spool. *)
let write_head dir ~seq ~prev =
  write_atomic (head_file dir)
    (Yojson.Safe.to_string (`Assoc [ ("seq", `Int seq); ("prev", `String prev) ]) ^ "\n")

let read_head dir =
  let f = head_file dir in
  if not (Sys.file_exists f) then Ok None
  else
    let bad () = Error (Printf.sprintf "audit spool state %s is corrupt" f) in
    match Yojson.Safe.from_string (In_channel.with_open_bin f In_channel.input_all) with
    | `Assoc kv -> (
        match (List.assoc_opt "seq" kv, List.assoc_opt "prev" kv) with
        | Some (`Int seq), Some (`String prev) when seq >= 0 && is_hex64 prev ->
            Ok (Some (seq, prev))
        | _ -> bad ())
    | _ -> bad ()
    | exception Yojson.Json_error _ -> bad ()

(* A persisted object name is reused only if it still names this exact body
   under the current prefix: a retry after a crash then hits the create-only
   precondition (counted as delivered) instead of duplicating the batch. *)
let stored_key ~prefix dir seq body =
  let f = key_file dir seq in
  if not (Sys.file_exists f) then None
  else
    let k = String.trim (In_channel.with_open_bin f In_channel.input_all) in
    let suffix = "-" ^ sha256_hex body ^ ".jsonl" in
    let lp = String.length prefix
    and ls = String.length suffix
    and lk = String.length k in
    if
      lk > lp + ls
      && String.sub k 0 lp = prefix
      && String.sub k (lk - ls) ls = suffix
      && String.for_all (fun c -> c > ' ' && c <> '\127') k
    then Some k
    else None

let rec write_all fd s off len =
  if len > 0 then
    let n = Unix.write_substring fd s off len in
    write_all fd s (off + n) (len - n)

let read_lines path =
  In_channel.with_open_bin path In_channel.input_all
  |> String.split_on_char '\n'
  |> List.filter (fun l -> String.trim l <> "")

let body_of_lines lines = String.concat "" (List.map (fun l -> l ^ "\n") lines)

(* Re-queue spooled batches after a restart; returns (pending list, next seq, chain head). *)
let recover dir =
  (try Unix.mkdir dir 0o700 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  let files = Sys.readdir dir |> Array.to_list |> List.sort compare in
  let batches =
    List.filter_map
      (fun f ->
        if
          String.length f = 22
          && String.sub f 0 6 = "batch-"
          && Filename.check_suffix f ".jsonl"
        then
          Option.map
            (fun s -> (s, Filename.concat dir f))
            (int_of_string_opt (String.sub f 6 10))
        else None)
      files
  in
  let last_hash path lines =
    match List.rev lines with
    | [] -> Ok None
    | l :: _ -> (
        match Audit_chain.hash_of_line l with
        | Some h -> Ok (Some h)
        | None ->
            Error
              (Printf.sprintf "spool file %s: last line is not a sealed audit record" path)
        )
  in
  let rec load acc head = function
    | [] -> Ok (List.rev acc, head)
    | (seq, path) :: rest -> (
        let lines = read_lines path in
        match last_hash path lines with
        | Error e -> Error e
        | Ok None ->
            Sys.remove path;
            load acc head rest
        | Ok (Some h) -> load ((seq, path, lines) :: acc) (Some h) rest)
  in
  match load [] None batches with
  | Error e -> Error e
  | Ok (loaded, head) -> (
      match read_head dir with
      | Error e -> Error e
      | Ok saved -> (
          (* The persisted head covers batches already uploaded and removed. *)
          let next =
            List.fold_left
              (fun m (s, _, _) -> max m (s + 1))
              (match saved with Some (s, _) -> s | None -> 0)
              loaded
          in
          let head =
            match (head, saved) with
            | Some h, _ -> Some h
            | None, Some (_, h) -> Some h
            | None, None -> None
          in
          (* key files whose batch is gone (uploaded, or never renamed) *)
          List.iter
            (fun f ->
              if
                String.length f = 20
                && String.sub f 0 6 = "batch-"
                && Filename.check_suffix f ".key"
              then
                match int_of_string_opt (String.sub f 6 10) with
                | Some s when not (List.exists (fun (s', _, _) -> s' = s) loaded) ->
                    Sys.remove (Filename.concat dir f)
                | _ -> ())
            files;
          let cur = current_file dir in
          if not (Sys.file_exists cur) then Ok (loaded, next, head)
          else
            let lines = read_lines cur in
            match last_hash cur lines with
            | Error e -> Error e
            | Ok None ->
                Sys.remove cur;
                Ok (loaded, next, head)
            | Ok (Some h) ->
                let path = batch_file dir next in
                Sys.rename cur path;
                Ok (loaded @ [ (next, path, lines) ], next + 1, Some h)))

let create ?(now = Unix.gettimeofday) ?host ?run_id ?spool_dir
    ?(max_buffer_records = 100_000) ?(max_attempts = 3) ?(base_backoff = 0.2)
    ?(initial_prev = Audit_chain.genesis) ?(on_event = ignore) ~name ~prefix
    ~(batch : Config.batch) ~on_error uploader =
  let host =
    sanitize_host
      (match host with
      | Some h -> h
      | None -> ( try Unix.gethostname () with _ -> "unknown"))
  in
  if batch.max_records < 1 || batch.max_seconds < 1 then
    Error "audit sink: invalid batch settings"
  else if max_attempts < 1 then Error "audit sink: max_attempts must be >= 1"
  else if not (is_hex64 initial_prev) then
    Error "audit sink: initial_prev must be a 64-hex hash"
  else
    let run_id = match run_id with Some r -> r | None -> default_run_id now in
    if not (valid_run_id run_id) then
      Error "audit sink: run_id must be 1-64 characters [A-Za-z0-9.]"
    else
      let recovered =
        match spool_dir with
        | None -> Ok ([], 0, None)
        | Some d -> (
            try recover d with
            | Unix.Unix_error (e, _, _) ->
                Error (Printf.sprintf "audit spool %s: %s" d (Unix.error_message e))
            | Sys_error m -> Error ("audit spool: " ^ m))
      in
      match recovered with
      | Error e -> Error e
      | Ok (loaded, seq, head) -> (
          let t =
            {
              name;
              prefix;
              host;
              run_id;
              max_records = batch.max_records;
              max_seconds = float_of_int batch.max_seconds;
              on_error;
              max_buffer = max max_buffer_records batch.max_records;
              max_attempts;
              base_backoff;
              uploader;
              now;
              spool_dir;
              on_event;
              cur = [];
              cur_n = 0;
              cur_started = 0.;
              cur_fd = None;
              pending = Queue.create ();
              pending_records = 0;
              prev = Option.value ~default:initial_prev head;
              seq;
              failed = false;
              next_retry = 0.;
              last_error = None;
              lock = Lwt_mutex.create ();
              wake = Lwt_condition.create ();
              running = false;
              stopped = false;
              n_written = 0;
              n_uploaded = 0;
              n_failures = 0;
              n_rejected = 0;
            }
          in
          (* [loaded] is non-empty only when there is a spool directory. *)
          let requeue dir =
            List.iter
              (fun (s, path, lines) ->
                let body = body_of_lines lines in
                let key =
                  match stored_key ~prefix dir s body with
                  | Some k -> k
                  | None ->
                      let k =
                        object_key ~prefix ~host ~run:run_id ~seq:s ~time:(now ()) body
                      in
                      write_atomic (key_file dir s) k;
                      k
                in
                Queue.push
                  {
                    key;
                    body;
                    records = List.length lines;
                    spool = Some path;
                    key_file = Some (key_file dir s);
                  }
                  t.pending;
                t.pending_records <- t.pending_records + List.length lines)
              loaded;
            write_head dir ~seq:t.seq ~prev:t.prev
          in
          match Option.iter requeue spool_dir with
          | exception Unix.Unix_error (e, _, _) ->
              Error (Printf.sprintf "audit spool: %s" (Unix.error_message e))
          | exception Sys_error m -> Error ("audit spool: " ^ m)
          | () ->
              if loaded <> [] then
                on_event
                  (Printf.sprintf "audit sink %s: re-queued %d spooled object(s)" name
                     (List.length loaded));
              Ok t)

let name t = t.name
let buffered t = t.cur_n + t.pending_records

let healthy t =
  not ((t.on_error = Config.Fail_closed && t.failed) || buffered t >= t.max_buffer)

let close_fd t =
  match t.cur_fd with
  | Some fd ->
      (try Unix.close fd with _ -> ());
      t.cur_fd <- None
  | None -> ()

(* Close the current batch into the upload queue. With a spool, the object
   name is persisted before the batch file appears, and the chain head / next
   sequence number are persisted after, so a restart neither re-uploads the
   batch under a new name nor restarts the chain. *)
let seal_batch t =
  if t.cur_n > 0 then begin
    let lines = List.rev t.cur in
    let body = body_of_lines lines in
    let seq = t.seq in
    let key =
      object_key ~prefix:t.prefix ~host:t.host ~run:t.run_id ~seq ~time:(t.now ()) body
    in
    t.seq <- seq + 1;
    let spool, kf =
      match t.spool_dir with
      | None -> (None, None)
      | Some d -> (
          close_fd t;
          let path = batch_file d seq and kf = key_file d seq in
          try
            write_atomic kf key;
            Sys.rename (current_file d) path;
            write_head d ~seq:t.seq ~prev:t.prev;
            (Some path, Some kf)
          with
          | Unix.Unix_error (e, _, _) ->
              t.on_event
                (Printf.sprintf "audit sink %s: cannot persist spool state: %s" t.name
                   (Unix.error_message e));
              ((if Sys.file_exists path then Some path else None), Some kf)
          | Sys_error m ->
              t.on_event
                (Printf.sprintf "audit sink %s: cannot persist spool state: %s" t.name m);
              ((if Sys.file_exists path then Some path else None), Some kf))
    in
    Queue.push { key; body; records = t.cur_n; spool; key_file = kf } t.pending;
    t.pending_records <- t.pending_records + t.cur_n;
    t.cur <- [];
    t.cur_n <- 0
  end

let reject t msg =
  t.n_rejected <- t.n_rejected + 1;
  Error msg

let spool_append t line =
  match t.spool_dir with
  | None -> Ok ()
  | Some d -> (
      try
        let fd =
          match t.cur_fd with
          | Some fd -> fd
          | None ->
              let fd =
                Unix.openfile (current_file d)
                  [ Unix.O_WRONLY; Unix.O_APPEND; Unix.O_CREAT; Unix.O_CLOEXEC ]
                  0o600
              in
              t.cur_fd <- Some fd;
              fd
        in
        let data = line ^ "\n" in
        write_all fd data 0 (String.length data);
        Ok ()
      with Unix.Unix_error (e, _, _) -> Error (Unix.error_message e))

let write t fields =
  if t.stopped then reject t (Printf.sprintf "audit sink %s is closed" t.name)
  else if t.on_error = Config.Fail_closed && t.failed then
    reject t
      (Printf.sprintf "audit sink %s unavailable: %s" t.name
         (Option.value ~default:"upload failed" t.last_error))
  else if buffered t >= t.max_buffer then
    reject t
      (Printf.sprintf "audit sink %s buffer full (%d records awaiting upload)" t.name
         (buffered t))
  else
    let line, hash = Audit_chain.seal ~prev:t.prev fields in
    match spool_append t line with
    | Error m ->
        reject t (Printf.sprintf "audit sink %s: cannot write spool: %s" t.name m)
    | Ok () ->
        t.cur <- line :: t.cur;
        t.cur_n <- t.cur_n + 1;
        if t.cur_n = 1 then t.cur_started <- t.now ();
        t.prev <- hash;
        t.n_written <- t.n_written + 1;
        if t.cur_n >= t.max_records then begin
          seal_batch t;
          Lwt_condition.broadcast t.wake ()
        end;
        Ok ()

let upload_with_retry t p =
  let rec go n =
    t.uploader ~key:p.key ~body:p.body >>= function
    | Ok () -> Lwt.return (Ok ())
    | Error (Permanent m) -> Lwt.return (Error m)
    | Error (Retryable m) ->
        if n + 1 >= t.max_attempts then Lwt.return (Error m)
        else
          Lwt_unix.sleep (t.base_backoff *. (2. ** float_of_int n)) >>= fun () ->
          go (n + 1)
  in
  Lwt.catch (fun () -> go 0) (fun e -> Lwt.return (Error (Printexc.to_string e)))

let flush_pending t =
  let rec go () =
    match Queue.peek_opt t.pending with
    | None -> Lwt.return (Ok ())
    | Some p -> (
        upload_with_retry t p >>= function
        | Ok () ->
            ignore (Queue.pop t.pending);
            t.pending_records <- t.pending_records - p.records;
            List.iter
              (fun f -> try Sys.remove f with Sys_error _ -> ())
              (Option.to_list p.spool @ Option.to_list p.key_file);
            t.n_uploaded <- t.n_uploaded + 1;
            if t.failed then t.on_event (Printf.sprintf "audit sink %s recovered" t.name);
            t.failed <- false;
            t.last_error <- None;
            go ()
        | Error m ->
            t.n_failures <- t.n_failures + 1;
            t.last_error <- Some m;
            t.failed <- true;
            t.next_retry <- t.now () +. t.max_seconds;
            t.on_event
              (Printf.sprintf "audit sink %s: upload of %s failed: %s" t.name p.key m);
            Lwt.return (Error m))
  in
  go ()

let flush t =
  Lwt_mutex.with_lock t.lock (fun () ->
      seal_batch t;
      flush_pending t)

let start t =
  if not t.running then begin
    t.running <- true;
    let tick = Float.max 0.05 (Float.min 1.0 (t.max_seconds /. 4.)) in
    let rec loop () =
      if t.stopped then Lwt.return_unit
      else
        Lwt.pick [ Lwt_unix.sleep tick; Lwt_condition.wait t.wake ] >>= fun () ->
        if t.stopped then Lwt.return_unit
        else
          Lwt_mutex.with_lock t.lock (fun () ->
              if t.cur_n > 0 && t.now () -. t.cur_started >= t.max_seconds then
                seal_batch t;
              if
                (not (Queue.is_empty t.pending))
                && ((not t.failed) || t.now () >= t.next_retry)
              then flush_pending t >|= ignore
              else Lwt.return_unit)
          >>= loop
    in
    Lwt.async (fun () ->
        Lwt.catch loop (fun e ->
            t.on_event
              (Printf.sprintf "audit sink %s loop crashed: %s" t.name
                 (Printexc.to_string e));
            t.failed <- true;
            Lwt.return_unit))
  end

let close t =
  t.stopped <- true;
  Lwt_condition.broadcast t.wake ();
  flush t >|= fun r ->
  close_fd t;
  r

let stats t =
  {
    records_written = t.n_written;
    objects_uploaded = t.n_uploaded;
    upload_failures = t.n_failures;
    write_rejections = t.n_rejected;
    buffered_records = buffered t;
    pending_objects = Queue.length t.pending;
    last_error = t.last_error;
    chain_head = t.prev;
  }

let metrics_text sinks =
  let b = Buffer.create 512 in
  (* Prometheus label values escape backslash, double quote and line feed. *)
  let esc s =
    let b = Buffer.create (String.length s) in
    String.iter
      (function
        | '\\' -> Buffer.add_string b "\\\\"
        | '"' -> Buffer.add_string b "\\\""
        | '\n' -> Buffer.add_string b "\\n"
        | c -> Buffer.add_char b c)
      s;
    Buffer.contents b
  in
  let metric name typ help f =
    Printf.bprintf b "# HELP %s %s\n# TYPE %s %s\n" name help name typ;
    List.iter
      (fun s -> Printf.bprintf b "%s{sink=\"%s\"} %d\n" name (esc s.name) (f s))
      sinks
  in
  if sinks <> [] then begin
    metric "haltsql_audit_sink_healthy" "gauge" "1 when the audit sink accepts writes."
      (fun s -> if healthy s then 1 else 0);
    metric "haltsql_audit_sink_buffered_records" "gauge" "Audit records not yet uploaded."
      buffered;
    metric "haltsql_audit_sink_pending_objects" "gauge"
      "Closed audit objects awaiting upload." (fun s -> Queue.length s.pending);
    metric "haltsql_audit_sink_objects_uploaded_total" "counter" "Audit objects uploaded."
      (fun s -> s.n_uploaded);
    metric "haltsql_audit_sink_upload_failures_total" "counter"
      "Failed audit object uploads." (fun s -> s.n_failures);
    metric "haltsql_audit_sink_rejected_writes_total" "counter"
      "Audit writes refused (sink unhealthy or buffer full)." (fun s -> s.n_rejected)
  end;
  Buffer.contents b
