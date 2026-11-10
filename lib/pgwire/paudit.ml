(* Hash-chained audit sinks for haltsql-proxy; see paudit.mli. Mirrors
   bin/server/lib/audit.ml (same chain, same on_error semantics) and adds the
   proxy's drop policy. *)

module Chain = Haltsql_cloud.Audit_chain
module Obj = Haltsql_cloud.Object_sink
module Config = Haltsql.Config

type backend =
  | Fd of { fd : Unix.file_descr; owned : bool }
  | Object of Obj.t  (** chains, batches, buffers and retries by itself *)

type sink = {
  name : string;
  backend : backend;
  on_error : Proxy_config.audit_on_error;
  max_pending : int;
  mutable prev : string;
  pending : (string * Yojson.Safe.t) list Queue.t;  (** Buffer mode, unsealed *)
  mutable torn : bool;  (** a partial line may be on disk *)
  mutable last_ok : bool;
  mutable written : int;
  mutable dropped : int;
  mutable failures : int;
  mutable last_error : string option;
}

type t = {
  sinks : sink list;
  spec : Proxy_config.audit_sink_spec list;
  on_event : string -> unit;
  mutable stopped : bool;
  lock : Lwt_mutex.t;
      (** serializes {!record_async}, the retry loop and {!close}: one writer at a time,
          served in arrival order (Lwt_mutex is FIFO), so each chain's order is the order
          in which records were submitted *)
}

let spec t = t.spec

(* ------------------------------------------------------------------ *)
(* Opening                                                              *)

(* Last non-empty line of a regular file, reading only its tail. *)
let last_line path =
  match Unix.openfile path [ Unix.O_RDONLY; Unix.O_CLOEXEC ] 0 with
  | exception Unix.Unix_error _ -> None
  | fd ->
      Fun.protect
        ~finally:(fun () -> Unix.close fd)
        (fun () ->
          let size = (Unix.fstat fd).st_size in
          let rec try_tail chunk =
            let start = max 0 (size - chunk) in
            ignore (Unix.lseek fd start Unix.SEEK_SET);
            let len = size - start in
            let buf = Bytes.create len in
            let rec rd off =
              if off < len then
                let n = Unix.read fd buf off (len - off) in
                if n = 0 then off else rd (off + n)
              else off
            in
            let got = rd 0 in
            let lines =
              String.split_on_char '\n' (Bytes.sub_string buf 0 got)
              |> List.filter (fun l -> String.trim l <> "")
            in
            (* with start > 0 the first piece may be partial: need two pieces *)
            match List.rev lines with
            | l :: _ :: _ -> Some l
            | [ l ] when start = 0 -> Some l
            | [] when start = 0 -> None
            | _ -> try_tail (chunk * 4)
          in
          if size = 0 then None else try_tail 65536)

let is_regular path =
  match Unix.stat path with
  | { Unix.st_kind = Unix.S_REG; _ } -> true
  | _ -> false
  | exception Unix.Unix_error _ -> false

let make ~name ~on_error ~max_pending ~prev backend =
  {
    name;
    backend;
    on_error;
    max_pending;
    prev;
    pending = Queue.create ();
    torn = false;
    last_ok = true;
    written = 0;
    dropped = 0;
    failures = 0;
    last_error = None;
  }

let open_file ~on_error ~max_pending path =
  let prev =
    if not (is_regular path) then Chain.genesis
    else
      match last_line path with
      | None -> Chain.genesis
      | Some l -> (
          match Chain.hash_of_line l with
          | Some h -> h
          | None ->
              failwith
                (Printf.sprintf
                   "audit file %s: last line is not a sealed audit record; refusing to \
                    continue the chain (rotate the file)"
                   path))
  in
  let fd =
    try
      Unix.openfile path
        [ Unix.O_WRONLY; Unix.O_APPEND; Unix.O_CREAT; Unix.O_CLOEXEC ]
        0o640
    with Unix.Unix_error (e, _, _) ->
      failwith
        (Printf.sprintf "cannot open audit file %s: %s" path (Unix.error_message e))
  in
  make ~name:path ~on_error ~max_pending ~prev (Fd { fd; owned = true })

let open_object ~on_event (s : Proxy_config.audit_sink_spec) =
  (* The object sink applies fail_closed / buffer itself; drop is a proxy-level policy
     over a fail-closed object sink (refused writes are discarded and counted). *)
  let obj_on_error =
    match s.sink_on_error with
    | Proxy_config.Audit_buffer -> Config.Buffer
    | Proxy_config.Audit_fail_closed | Proxy_config.Audit_drop -> Config.Fail_closed
  in
  let created =
    match s.sink with
    | Config.Sink_s3 c ->
        Haltsql_cloud.S3_sink.create ~on_error:obj_on_error
          ~max_buffer_records:s.max_buffer_records ~on_event c
    | Config.Sink_gcs c ->
        Haltsql_cloud.Gcs_sink.create ~on_error:obj_on_error
          ~max_buffer_records:s.max_buffer_records ~on_event c
    | Config.Sink_stdout | Config.Sink_file _ -> Error "not an object-store sink"
  in
  match created with
  | Error e ->
      failwith (Printf.sprintf "audit sink %s: %s" (Proxy_config.sink_name s.sink) e)
  | Ok o ->
      Obj.start o;
      make ~name:(Obj.name o) ~on_error:s.sink_on_error ~max_pending:s.max_buffer_records
        ~prev:Chain.genesis (Object o)

(* ------------------------------------------------------------------ *)
(* Writing                                                              *)

exception Partial of exn

(* Writes all of [s]; on failure after some bytes, raises [Partial e]. *)
let write_all fd s =
  let len = String.length s in
  let rec go off =
    if off < len then
      match Unix.write_substring fd s off (len - off) with
      | n -> go (off + n)
      | exception e -> if off > 0 then raise (Partial e) else raise e
  in
  go 0

let error_message = function
  | Unix.Unix_error (e, _, _) -> Unix.error_message e
  | Sys_error e | Failure e -> e
  | e -> Printexc.to_string e

(* Seals and writes one record; the chain advances only on success. *)
let append sink fields =
  match sink.backend with
  | Fd { fd; _ } -> (
      let line, hash = Chain.seal ~prev:sink.prev fields in
      let data = (if sink.torn then "\n" else "") ^ line ^ "\n" in
      match write_all fd data with
      | () ->
          sink.torn <- false;
          sink.prev <- hash;
          sink.written <- sink.written + 1;
          Ok ()
      | exception Partial e ->
          sink.torn <- true;
          Error (error_message e)
      | exception e -> Error (error_message e))
  | Object o -> (
      match Obj.write o fields with
      | Ok () ->
          sink.written <- sink.written + 1;
          Ok ()
      | Error e -> Error e)

let flush_pending sink =
  let rec go () =
    match Queue.peek_opt sink.pending with
    | None -> Ok ()
    | Some f -> (
        match append sink f with
        | Ok () ->
            ignore (Queue.pop sink.pending);
            go ()
        | Error e -> Error e)
  in
  go ()

type delivery = Written | Buffered of string | Dropped of string | Failed of string

let deliver sink fields =
  let fail e =
    sink.failures <- sink.failures + 1;
    sink.last_error <- Some e;
    sink.last_ok <- false
  in
  let ok () =
    sink.last_ok <- true;
    sink.last_error <- None
  in
  match (sink.on_error, sink.backend) with
  | Proxy_config.Audit_fail_closed, _ | Proxy_config.Audit_buffer, Object _ -> (
      (* object sinks buffer internally and refuse only when full *)
      match append sink fields with
      | Ok () ->
          ok ();
          Written
      | Error e ->
          fail e;
          Failed e)
  | Proxy_config.Audit_drop, _ -> (
      match append sink fields with
      | Ok () ->
          ok ();
          Written
      | Error e ->
          fail e;
          sink.dropped <- sink.dropped + 1;
          Dropped e)
  | Proxy_config.Audit_buffer, Fd _ -> (
      let attempt =
        match flush_pending sink with Error e -> Error e | Ok () -> append sink fields
      in
      match attempt with
      | Ok () ->
          ok ();
          Written
      | Error e ->
          fail e;
          if Queue.length sink.pending >= sink.max_pending then
            Failed (e ^ "; audit buffer is full")
          else (
            Queue.push fields sink.pending;
            Buffered e))

(* Logs one sink's outcome (on the event loop); [Some reason] when it refuses the record. *)
let outcome sink = function
  | Written -> None
  | Buffered e ->
      Plog.log Plog.Warn "audit sink write failed; record buffered"
        [
          ("sink", `String sink.name);
          ("error", `String e);
          ("buffered", `Int (Queue.length sink.pending));
        ];
      None
  | Dropped e ->
      Plog.log Plog.Warn "audit sink write failed; record dropped (on_error: drop)"
        [
          ("sink", `String sink.name);
          ("error", `String e);
          ("dropped_total", `Int sink.dropped);
        ];
      None
  | Failed e ->
      Plog.log Plog.Error "audit sink write failed; refusing the statement"
        [ ("sink", `String sink.name); ("error", `String e) ];
      Some (sink.name ^ ": " ^ e)

let verdict_of failed =
  match List.filter_map Fun.id failed with
  | [] -> Ok ()
  | l -> Error (String.concat "; " l)

let stamp fields = ("ts", `String (Plog.now_rfc3339 ())) :: fields

let record t fields =
  let fields = stamp fields in
  verdict_of (List.map (fun sink -> outcome sink (deliver sink fields)) t.sinks)

(* Never raises: an unexpected exception refuses the record (fail closed). *)
let deliver_safe sink fields =
  try deliver sink fields
  with e ->
    sink.failures <- sink.failures + 1;
    sink.last_ok <- false;
    let m = error_message e in
    sink.last_error <- Some m;
    Failed m

let is_fd sink = match sink.backend with Fd _ -> true | Object _ -> false

(* stdout/file sinks write with blocking system calls: a slow disk, a full pipe or a
   stalled NFS mount must stall only the statements waiting for their audit record, not
   every session, so those writes run on a worker thread. Object sinks only append to
   memory and their spool and share state with their uploader on the event loop, so they
   stay here. The caller still waits for the outcome before it forwards anything: the
   failure policy is unchanged. *)
let record_async t fields =
  let open Lwt.Syntax in
  Lwt_mutex.with_lock t.lock (fun () ->
      (* stamped under the lock, so timestamps follow chain order *)
      let fields = stamp fields in
      let* deliveries =
        if t.sinks <> [] && List.for_all is_fd t.sinks then
          (* the common case: one hop for all sinks *)
          Lwt.catch
            (fun () ->
              Offload.run (fun () ->
                  List.map (fun sink -> deliver_safe sink fields) t.sinks))
            (fun e -> Lwt.return (List.map (fun _ -> Failed (error_message e)) t.sinks))
        else
          Lwt_list.map_s
            (fun sink ->
              if is_fd sink then
                Lwt.catch
                  (fun () -> Offload.run (fun () -> deliver_safe sink fields))
                  (fun e -> Lwt.return (Failed (error_message e)))
              else Lwt.return (deliver_safe sink fields))
            t.sinks
      in
      Lwt.return (verdict_of (List.map2 outcome t.sinks deliveries)))

let sink_healthy s =
  match (s.backend, s.on_error) with
  | _, Proxy_config.Audit_drop -> true
  | Object o, _ -> Obj.healthy o
  | Fd _, Proxy_config.Audit_fail_closed -> s.last_ok
  | Fd _, Proxy_config.Audit_buffer -> Queue.length s.pending < s.max_pending

let healthy t = List.for_all sink_healthy t.sinks

(* Buffered stdout/file records drain even without traffic. *)
let rec retry_loop t =
  let open Lwt.Syntax in
  let* () = Lwt_unix.sleep 1.0 in
  if t.stopped then Lwt.return_unit
  else
    let* () =
      Lwt_list.iter_s
        (fun s ->
          if Queue.is_empty s.pending then Lwt.return_unit
          else
            Lwt_mutex.with_lock t.lock (fun () ->
                let* r =
                  Lwt.catch
                    (fun () -> Offload.run (fun () -> flush_pending s))
                    (fun e -> Lwt.return (Error (error_message e)))
                in
                (match r with
                | Ok () ->
                    s.last_ok <- true;
                    s.last_error <- None;
                    t.on_event
                      (Printf.sprintf "audit sink %s recovered; buffer drained" s.name)
                | Error _ -> ());
                Lwt.return_unit))
        t.sinks
    in
    retry_loop t

let default_on_event m = Plog.log Plog.Warn "audit sink event" [ ("event", `String m) ]

let open_ ?(on_event = default_on_event) (specs : Proxy_config.audit_sink_spec list) =
  let opened = ref [] in
  let close_opened () =
    List.iter
      (fun s ->
        match s.backend with
        | Fd { fd; owned = true } -> ( try Unix.close fd with _ -> ())
        | Fd _ -> ()
        | Object o -> Lwt.async (fun () -> Lwt.map ignore (Obj.close o)))
      !opened
  in
  try
    List.iter
      (fun (s : Proxy_config.audit_sink_spec) ->
        let sink =
          match s.sink with
          | Config.Sink_stdout ->
              make ~name:"stdout" ~on_error:s.sink_on_error
                ~max_pending:s.max_buffer_records ~prev:Chain.genesis
                (Fd { fd = Unix.stdout; owned = false })
          | Config.Sink_file path ->
              open_file ~on_error:s.sink_on_error ~max_pending:s.max_buffer_records path
          | Config.Sink_s3 _ | Config.Sink_gcs _ -> open_object ~on_event s
        in
        opened := sink :: !opened)
      specs;
    let t =
      {
        sinks = List.rev !opened;
        spec = specs;
        on_event;
        stopped = false;
        lock = Lwt_mutex.create ();
      }
    in
    if
      List.exists
        (fun s ->
          s.on_error = Proxy_config.Audit_buffer
          && match s.backend with Fd _ -> true | Object _ -> false)
        t.sinks
    then Lwt.async (fun () -> retry_loop t);
    t
  with e ->
    close_opened ();
    raise e

let stats_json t : Yojson.Safe.t =
  `List
    (List.map
       (fun s ->
         let obj =
           match s.backend with
           | Fd _ -> [ ("buffered", `Int (Queue.length s.pending)) ]
           | Object o ->
               let st = Obj.stats o in
               [
                 ("buffered", `Int st.buffered_records);
                 ("objects_uploaded", `Int st.objects_uploaded);
                 ("upload_failures", `Int st.upload_failures);
                 ("pending_objects", `Int st.pending_objects);
               ]
         in
         `Assoc
           ([
              ("sink", `String s.name);
              ("on_error", `String (Proxy_config.on_error_name s.on_error));
              ("healthy", `Bool (sink_healthy s));
              ("records_written", `Int s.written);
              ("write_failures", `Int s.failures);
              ("dropped", `Int s.dropped);
            ]
           @ obj
           @
           match s.last_error with
           | Some e -> [ ("last_error", `String e) ]
           | None -> []))
       t.sinks)

let close_wait = 5.

let close_sinks t =
  let open Lwt.Syntax in
  Lwt_list.iter_s
    (fun s ->
      (match flush_pending s with
      | Ok () -> ()
      | Error e ->
          Plog.log Plog.Error "audit records lost at shutdown: sink still failing"
            [
              ("sink", `String s.name);
              ("error", `String e);
              ("lost", `Int (Queue.length s.pending));
            ]);
      match s.backend with
      | Fd { fd; owned } ->
          (if owned then try Unix.close fd with _ -> ());
          Lwt.return_unit
      | Object o -> (
          let* r = Obj.close o in
          match r with
          | Ok () -> Lwt.return_unit
          | Error e ->
              Plog.log Plog.Error "audit sink final flush failed"
                [ ("sink", `String s.name); ("error", `String e) ];
              Lwt.return_unit))
    t.sinks

let close t =
  let open Lwt.Syntax in
  t.stopped <- true;
  (* After any write still in flight; a write that never returns (the reason it runs on
     a worker thread) must not hang the shutdown as well. *)
  let* locked =
    Lwt.pick
      [
        Lwt.map (fun () -> true) (Lwt_mutex.lock t.lock);
        Lwt.map (fun () -> false) (Lwt_unix.sleep close_wait);
      ]
  in
  if not locked then (
    Plog.log Plog.Error
      "an audit write is still blocked at shutdown; skipping the final flush"
      [ ("sinks", `List (List.map (fun s -> `String s.name) t.sinks)) ];
    Lwt.return_unit)
  else
    Lwt.finalize
      (fun () -> close_sinks t)
      (fun () ->
        Lwt_mutex.unlock t.lock;
        Lwt.return_unit)
