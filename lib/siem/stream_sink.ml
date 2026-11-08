open Lwt.Infix
module Config = Haltsql_load.Config
module Audit_chain = Haltsql_cloud.Audit_chain

type entry = { line : string; hash : string }

type item_result =
  | Delivered
  | Retry of string
  | Rejected of { reason : string; detail : string }

type deliver = entry array -> (item_result array, string) result Lwt.t

type stats = {
  records_written : int;
  records_delivered : int;
  records_dropped : (string * int) list;
  delivery_failures : int;
  retries : int;
  write_rejections : int;
  buffered_records : int;
  delivering : bool;
  last_error : string option;
  chain_head : string;
}

type t = {
  name : string;
  kind : string;
  max_records : int;
  max_bytes : int;
  interval : float;
  on_error : Config.stream_on_error;
  max_buffer : int;
  max_attempts : int;
  base_backoff : float;
  max_backoff : float;
  jitter : unit -> float;
  prepare : (string * Yojson.Safe.t) list -> (string * Yojson.Safe.t) list;
  close_transport : unit -> unit Lwt.t;
  on_event : string -> unit;
  deliver : deliver;
  now : unit -> float;
  queue : (entry * float) Queue.t;
  mutable queue_bytes : int;
  mutable inflight : entry array;
  mutable prev : string;
  mutable failed : bool;
  mutable consecutive : int;
  mutable next_retry : float;
  mutable last_error : string option;
  lock : Lwt_mutex.t;
  wake : unit Lwt_condition.t;
  mutable running : bool;
  mutable stopped : bool;
  mutable n_written : int;
  mutable n_delivered : int;
  mutable n_failures : int;
  mutable n_retries : int;
  mutable n_rejected : int;
  mutable dropping : bool;
  dropped : (string, int) Hashtbl.t;
}

let is_hex64 h =
  String.length h = 64
  && String.for_all (fun c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) h

let default_jitter =
  let st = lazy (Random.State.make_self_init ()) in
  fun () -> 0.5 +. Random.State.float (Lazy.force st) 1.0

let create ?(now = Unix.gettimeofday) ?(max_attempts = 3) ?(base_backoff = 0.2)
    ?(max_backoff = 30.) ?(jitter = default_jitter) ?(prepare = Fun.id)
    ?(close_transport = fun () -> Lwt.return_unit) ?(on_event = ignore)
    ?(initial_prev = Audit_chain.genesis) ~name ~kind ~(batch : Config.stream_batch)
    ~on_error ~max_buffer_records deliver =
  if
    batch.batch_max_records < 1 || batch.batch_max_bytes < 1
    || batch.flush_interval_ms < 1
  then Error "audit sink: invalid batch settings"
  else if max_attempts < 1 then Error "audit sink: max_attempts must be >= 1"
  else if max_buffer_records < 1 then Error "audit sink: max_buffer_records must be >= 1"
  else if not (base_backoff >= 0. && max_backoff >= base_backoff) then
    Error "audit sink: invalid backoff settings"
  else if not (is_hex64 initial_prev) then
    Error "audit sink: initial_prev must be a 64-hex hash"
  else
    Ok
      {
        name;
        kind;
        max_records = batch.batch_max_records;
        max_bytes = batch.batch_max_bytes;
        interval = float_of_int batch.flush_interval_ms /. 1000.;
        on_error;
        max_buffer = max max_buffer_records batch.batch_max_records;
        max_attempts;
        base_backoff;
        max_backoff;
        jitter;
        prepare;
        close_transport;
        on_event;
        deliver;
        now;
        queue = Queue.create ();
        queue_bytes = 0;
        inflight = [||];
        prev = initial_prev;
        failed = false;
        consecutive = 0;
        next_retry = 0.;
        last_error = None;
        lock = Lwt_mutex.create ();
        wake = Lwt_condition.create ();
        running = false;
        stopped = false;
        n_written = 0;
        n_delivered = 0;
        n_failures = 0;
        n_retries = 0;
        n_rejected = 0;
        dropping = false;
        dropped = Hashtbl.create 4;
      }

let name t = t.name
let kind t = t.kind
let buffered t = Array.length t.inflight + Queue.length t.queue

let healthy t =
  match t.on_error with
  | Config.Stream_drop -> true
  | Config.Stream_fail_closed -> not (t.failed || buffered t >= t.max_buffer)
  | Config.Stream_buffer -> buffered t < t.max_buffer

let count_drop t reason n =
  Hashtbl.replace t.dropped reason
    (n + Option.value ~default:0 (Hashtbl.find_opt t.dropped reason))

let reject t msg =
  t.n_rejected <- t.n_rejected + 1;
  Error msg

let drop_at_write t why =
  count_drop t "on_error_drop" 1;
  if not t.dropping then begin
    t.dropping <- true;
    t.on_event
      (Printf.sprintf "audit sink %s: dropping new records (%s; on_error: drop)" t.name
         why)
  end;
  Ok ()

let due t =
  match Queue.peek_opt t.queue with
  | None -> false
  | Some (_, started) ->
      Queue.length t.queue >= t.max_records
      || t.queue_bytes >= t.max_bytes
      || t.now () -. started >= t.interval

let write t fields =
  if t.stopped then reject t (Printf.sprintf "audit sink %s is closed" t.name)
  else
    let full = buffered t >= t.max_buffer in
    match t.on_error with
    | Config.Stream_fail_closed when t.failed ->
        reject t
          (Printf.sprintf "audit sink %s unavailable: %s" t.name
             (Option.value ~default:"delivery failed" t.last_error))
    | Config.Stream_drop when t.failed -> drop_at_write t "destination unavailable"
    | Config.Stream_drop when full -> drop_at_write t "buffer full"
    | (Config.Stream_fail_closed | Config.Stream_buffer) when full ->
        reject t
          (Printf.sprintf "audit sink %s buffer full (%d records awaiting delivery)"
             t.name (buffered t))
    | Config.Stream_fail_closed | Config.Stream_buffer | Config.Stream_drop ->
        if t.dropping then begin
          t.dropping <- false;
          t.on_event (Printf.sprintf "audit sink %s: accepting records again" t.name)
        end;
        let line, hash = Audit_chain.seal ~prev:t.prev (t.prepare fields) in
        Queue.push ({ line; hash }, t.now ()) t.queue;
        t.queue_bytes <- t.queue_bytes + String.length line;
        t.prev <- hash;
        t.n_written <- t.n_written + 1;
        if Queue.length t.queue >= t.max_records || t.queue_bytes >= t.max_bytes then
          Lwt_condition.broadcast t.wake ();
        Ok ()

let take_batch t =
  let rec go acc n bytes =
    match Queue.peek_opt t.queue with
    | Some (e, _)
      when n < t.max_records && (n = 0 || bytes + String.length e.line <= t.max_bytes) ->
        ignore (Queue.pop t.queue);
        t.queue_bytes <- t.queue_bytes - String.length e.line;
        go (e :: acc) (n + 1) (bytes + String.length e.line)
    | _ -> Array.of_list (List.rev acc)
  in
  t.inflight <- go [] 0 0

let backoff t n =
  Float.min t.max_backoff (t.base_backoff *. (2. ** float_of_int n)) *. t.jitter ()

let short e = String.sub e.hash 0 16

(* Ships [t.inflight] with up to [max_attempts] attempts; only the records still
   pending are resent. On [Error], [t.inflight] holds what is left, in order. *)
let ship t =
  let rejected = ref None in
  let rec attempt n =
    let batch = t.inflight in
    Lwt.catch
      (fun () -> t.deliver batch)
      (fun e -> Lwt.return (Error ("transport error: " ^ Printexc.to_string e)))
    >>= fun r ->
    let last =
      match r with
      | Error m -> Some m
      | Ok results when Array.length results <> Array.length batch ->
          Some "transport returned a wrong number of results"
      | Ok results ->
          let rest = ref [] and why = ref None in
          Array.iteri
            (fun i e ->
              match results.(i) with
              | Delivered -> t.n_delivered <- t.n_delivered + 1
              | Rejected { reason; detail } ->
                  count_drop t reason 1;
                  if t.on_error = Config.Stream_fail_closed then begin
                    let msg =
                      Printf.sprintf "record rejected by destination (%s: %s)" reason
                        detail
                    in
                    rejected := Some msg;
                    t.failed <- true;
                    t.last_error <- Some msg
                  end;
                  t.on_event
                    (Printf.sprintf
                       "audit sink %s: record %s rejected by the destination (%s: %s); \
                        dropped"
                       t.name (short e) reason detail)
              | Retry m ->
                  rest := e :: !rest;
                  if !why = None then why := Some m)
            batch;
          t.inflight <- Array.of_list (List.rev !rest);
          if t.inflight = [||] then None else Some (Option.value ~default:"retry" !why)
    in
    match last with
    | None -> Lwt.return (Ok !rejected)
    | Some m ->
        if n + 1 >= t.max_attempts then Lwt.return (Error m)
        else begin
          t.n_retries <- t.n_retries + 1;
          Lwt_unix.sleep (backoff t n) >>= fun () -> attempt (n + 1)
        end
  in
  attempt 0

let flush_locked t =
  let rejected = ref None in
  let rec go () =
    if t.inflight = [||] then take_batch t;
    if t.inflight = [||] then begin
      (match !rejected with
      | Some err ->
          t.failed <- true;
          t.last_error <- Some err
      | None -> ());
      Lwt.return (Ok ())
    end
    else
      ship t >>= function
      | Ok batch_rej ->
          (match batch_rej with
          | Some err ->
              rejected := Some err;
              t.failed <- true;
              t.last_error <- Some err
          | None ->
              if t.failed && !rejected = None then begin
                t.on_event (Printf.sprintf "audit sink %s recovered" t.name);
                t.failed <- false;
                t.consecutive <- 0;
                t.last_error <- None
              end);
          go ()
      | Error m ->
          t.n_failures <- t.n_failures + 1;
          t.last_error <- Some m;
          if not t.failed then
            t.on_event
              (Printf.sprintf "audit sink %s: delivery failed (%d records queued): %s"
                 t.name (buffered t) m);
          t.failed <- true;
          t.next_retry <- t.now () +. backoff t t.consecutive;
          t.consecutive <- min 30 (t.consecutive + 1);
          Lwt.return (Error m)
  in
  go ()

let flush t = Lwt_mutex.with_lock t.lock (fun () -> flush_locked t)

let start t =
  if not t.running then begin
    t.running <- true;
    let tick = Float.max 0.01 (Float.min 0.5 (t.interval /. 2.)) in
    let rec loop () =
      if t.stopped then Lwt.return_unit
      else
        Lwt.pick [ Lwt_unix.sleep tick; Lwt_condition.wait t.wake ] >>= fun () ->
        if t.stopped then Lwt.return_unit
        else
          let work =
            if t.failed then t.now () >= t.next_retry && buffered t > 0
            else t.inflight <> [||] || due t
          in
          (if work then Lwt_mutex.with_lock t.lock (fun () -> flush_locked t >|= ignore)
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
  flush t >>= fun r ->
  Lwt.catch t.close_transport (fun _ -> Lwt.return_unit) >|= fun () -> r

let stats t =
  {
    records_written = t.n_written;
    records_delivered = t.n_delivered;
    records_dropped =
      List.sort compare (Hashtbl.fold (fun k v acc -> (k, v) :: acc) t.dropped []);
    delivery_failures = t.n_failures;
    retries = t.n_retries;
    write_rejections = t.n_rejected;
    buffered_records = buffered t;
    delivering = not t.failed;
    last_error = t.last_error;
    chain_head = t.prev;
  }

let metrics_text sinks =
  let b = Buffer.create 1024 in
  let esc s =
    String.concat "\\\""
      (String.split_on_char '"' (String.concat "\\\\" (String.split_on_char '\\' s)))
    |> String.split_on_char '\n' |> String.concat "\\n"
  in
  let labels s = Printf.sprintf "sink=\"%s\",type=\"%s\"" (esc s.name) (esc s.kind) in
  let header name typ help =
    Printf.bprintf b "# HELP %s %s\n# TYPE %s %s\n" name help name typ
  in
  let metric name typ help f =
    header name typ help;
    List.iter (fun s -> Printf.bprintf b "%s{%s} %d\n" name (labels s) (f s)) sinks
  in
  if sinks <> [] then begin
    let p = "haltsql_audit_stream_sink_" in
    metric (p ^ "healthy") "gauge" "1 when the streaming audit sink accepts writes."
      (fun s -> if healthy s then 1 else 0);
    metric (p ^ "delivering") "gauge" "0 while deliveries are failing." (fun s ->
        if s.failed then 0 else 1);
    metric (p ^ "buffered_records") "gauge" "Audit records queued, not yet delivered."
      buffered;
    metric (p ^ "records_written_total") "counter" "Audit records accepted and sealed."
      (fun s -> s.n_written);
    metric (p ^ "records_delivered_total") "counter" "Audit records delivered." (fun s ->
        s.n_delivered);
    header (p ^ "records_dropped_total") "counter"
      "Audit records dropped, by reason (mapping, too_large, on_error_drop).";
    List.iter
      (fun s ->
        let l =
          List.sort compare (Hashtbl.fold (fun k v acc -> (k, v) :: acc) s.dropped [])
        in
        List.iter
          (fun (reason, n) ->
            Printf.bprintf b "%srecords_dropped_total{%s,reason=\"%s\"} %d\n" p (labels s)
              (esc reason) n)
          l)
      sinks;
    metric (p ^ "delivery_failures_total")
      "counter" "Audit batches that failed every delivery attempt." (fun s ->
        s.n_failures);
    metric (p ^ "retries_total") "counter" "Extra delivery attempts." (fun s ->
        s.n_retries);
    metric (p ^ "rejected_writes_total") "counter"
      "Audit writes refused (sink unhealthy or buffer full)." (fun s -> s.n_rejected)
  end;
  Buffer.contents b
