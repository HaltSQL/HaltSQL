open Lwt.Infix
module Config = Haltsql_load.Config
module J = Otlp_json

(* ---- random ids ---- *)

let rng_ready = ref false

let random_bytes n =
  let gen () = Mirage_crypto_rng.generate n in
  if not !rng_ready then begin
    (try ignore (gen ())
     with Mirage_crypto_rng.Unseeded_generator -> Mirage_crypto_rng_unix.use_default ());
    rng_ready := true
  end;
  gen ()

let hex s =
  let b = Buffer.create (2 * String.length s) in
  String.iter (fun c -> Buffer.add_string b (Printf.sprintf "%02x" (Char.code c))) s;
  Buffer.contents b

let rec random_hex n =
  let h = hex (random_bytes n) in
  if String.for_all (fun c -> c = '0') h then random_hex n else h

(* ---- metric instruments ---- *)

type key = (string * string) list (* sorted label set *)

type hist = {
  counts : int array;
  mutable sum : float;
  mutable count : int;
  mutable hmin : float;
  mutable hmax : float;
}

type instrument =
  | I_counter of (key, int ref) Hashtbl.t
  | I_gauge of (key, float ref) Hashtbl.t
  | I_hist of float array * (key, hist) Hashtbl.t

type meta = { description : string; unit_ : string; inst : instrument }

type stats = {
  spans_queued : int;
  spans_exported : int;
  spans_dropped : int;
  batches_sent : int;
  export_failures : int;
  retries : int;
  metric_exports : int;
}

type t = {
  enabled : bool;
  traces : bool;
  metrics : bool;
  traces_uri : Uri.t;
  metrics_uri : Uri.t;
  headers : (string * string) list;
  gzip : bool;
  timeout : float;
  interval : float;
  max_queue : int;
  max_batch : int;
  max_retries : int;
  base_backoff : float;
  max_backoff : float;
  resource : J.attrs;
  scope : J.scope;
  queue : J.span Queue.t;
  instruments : (string, meta) Hashtbl.t;
  wake : unit Lwt_condition.t;
  lock : Lwt_mutex.t;
  on_error : string -> unit;
  now : unit -> float;
  start_ns : int64;
  mutable last_metrics : float;
  mutable running : bool;
  mutable stopped : bool;
  mutable n_exported : int;
  mutable n_dropped : int;
  mutable n_batches : int;
  mutable n_failures : int;
  mutable n_retries : int;
  mutable n_metric_exports : int;
}

let ns_of f = Int64.of_float (f *. 1e9)

let make ~enabled ~traces ~metrics ~base ~headers ~gzip ~timeout ~interval ~max_queue
    ~max_batch ~max_retries ~base_backoff ~max_backoff ~resource ~on_error ~now =
  let with_path p =
    let b = Uri.of_string base in
    let path = Uri.path b in
    let path =
      if String.length path > 0 && path.[String.length path - 1] = '/' then
        String.sub path 0 (String.length path - 1)
      else path
    in
    Uri.with_path b (path ^ p)
  in
  {
    enabled;
    traces;
    metrics;
    traces_uri = with_path "/v1/traces";
    metrics_uri = with_path "/v1/metrics";
    headers;
    gzip;
    timeout;
    interval;
    max_queue;
    max_batch;
    max_retries;
    base_backoff;
    max_backoff;
    resource;
    scope = { J.scope_name = "haltsql"; scope_version = "1" };
    queue = Queue.create ();
    instruments = Hashtbl.create 16;
    wake = Lwt_condition.create ();
    lock = Lwt_mutex.create ();
    on_error;
    now;
    start_ns = ns_of (now ());
    last_metrics = now ();
    running = false;
    stopped = false;
    n_exported = 0;
    n_dropped = 0;
    n_batches = 0;
    n_failures = 0;
    n_retries = 0;
    n_metric_exports = 0;
  }

let noop =
  make ~enabled:false ~traces:false ~metrics:false ~base:"http://127.0.0.1:4318"
    ~headers:[] ~gzip:false ~timeout:1. ~interval:3600. ~max_queue:0 ~max_batch:1
    ~max_retries:0 ~base_backoff:1. ~max_backoff:1. ~resource:[] ~on_error:ignore
    ~now:Unix.gettimeofday

let create ?(max_queue = 2048) ?(max_batch = 512) ?(gzip = false) ?(max_retries = 5)
    ?(base_backoff = 0.5) ?(max_backoff = 30.) ?(service_version = "unknown")
    ?(resource_attributes = []) ?(on_error = ignore) ?(now = Unix.gettimeofday)
    (c : Config.otlp) =
  let u = Uri.of_string c.otlp_endpoint in
  match (Uri.scheme u, Uri.host u) with
  | Some ("http" | "https"), Some h when h <> "" ->
      if max_queue < 1 || max_batch < 1 || max_retries < 0 then
        Error "telemetry: max_queue and max_batch must be >= 1, max_retries >= 0"
      else
        let host = try Unix.gethostname () with _ -> "unknown" in
        let resource =
          [
            ("service.name", J.String c.service_name);
            ("service.version", J.String service_version);
            ("telemetry.sdk.name", J.String "haltsql");
            ("telemetry.sdk.language", J.String "ocaml");
            ("host.name", J.String host);
          ]
          @ List.map (fun (k, v) -> (k, J.String v)) resource_attributes
        in
        Ok
          (make ~enabled:true ~traces:c.otlp_traces ~metrics:c.otlp_metrics
             ~base:c.otlp_endpoint ~headers:c.otlp_headers ~gzip
             ~timeout:(float_of_int c.timeout_seconds)
             ~interval:(float_of_int c.export_interval_seconds)
             ~max_queue ~max_batch ~max_retries ~base_backoff ~max_backoff ~resource
             ~on_error ~now)
  | _ -> Error "telemetry: otlp endpoint must be an http(s) URL"

let of_config ?gzip ?service_version ?on_error = function
  | None -> Ok noop
  | Some c -> create ?gzip ?service_version ?on_error c

let enabled t = t.enabled

let stats t =
  {
    spans_queued = Queue.length t.queue;
    spans_exported = t.n_exported;
    spans_dropped = t.n_dropped;
    batches_sent = t.n_batches;
    export_failures = t.n_failures;
    retries = t.n_retries;
    metric_exports = t.n_metric_exports;
  }

(* ---- Retry-After ---- *)

let months =
  [ "Jan"; "Feb"; "Mar"; "Apr"; "May"; "Jun"; "Jul"; "Aug"; "Sep"; "Oct"; "Nov"; "Dec" ]

let parse_retry_after ~now s =
  let s = String.trim s in
  if s <> "" && String.for_all (fun c -> c >= '0' && c <= '9') s then
    match int_of_string_opt s with Some n -> Some (float_of_int n) | None -> None
  else
    match String.split_on_char ' ' s |> List.filter (( <> ) "") with
    | [ _wd; dd; mon; yyyy; hms; "GMT" ] -> (
        let idx =
          let rec f i = function
            | [] -> None
            | m :: r -> if m = mon then Some (i + 1) else f (i + 1) r
          in
          f 0 months
        in
        match
          (int_of_string_opt dd, idx, int_of_string_opt yyyy, String.split_on_char ':' hms)
        with
        | Some d, Some m, Some y, [ hh; mm; ss ] -> (
            match (int_of_string_opt hh, int_of_string_opt mm, int_of_string_opt ss) with
            | Some hh, Some mm, Some ss -> (
                match Ptime.of_date_time ((y, m, d), ((hh, mm, ss), 0)) with
                | Some p -> Some (Float.max 0. (Ptime.to_float_s p -. now))
                | None -> None)
            | _ -> None)
        | _ -> None)
    | _ -> None

(* ---- transport ---- *)

type outcome =
  | Delivered of string
  | Retryable of string * float option
  | Permanent of string

let post t uri payload =
  let body, enc =
    if t.gzip then (Gzip.compress payload, [ ("content-encoding", "gzip") ])
    else (payload, [])
  in
  let headers =
    Cohttp.Header.of_list
      (List.filter
         (fun (k, _) ->
           let k = String.lowercase_ascii k in
           k <> "content-type" && k <> "content-encoding" && k <> "content-length")
         t.headers
      @ [ ("content-type", "application/json") ]
      @ enc)
  in
  let call () =
    Cohttp_lwt_unix.Client.call ~headers ~body:(Cohttp_lwt.Body.of_string body) `POST uri
    >>= fun (resp, rbody) ->
    Cohttp_lwt.Body.to_string rbody >|= fun rb ->
    `Resp
      ( Cohttp.Code.code_of_status (Cohttp.Response.status resp),
        Cohttp.Response.headers resp,
        rb )
  in
  Lwt.catch
    (fun () -> Lwt.pick [ call (); (Lwt_unix.sleep t.timeout >|= fun () -> `Timeout) ])
    (fun e -> Lwt.return (`Exn (Printexc.to_string e)))
  >|= function
  | `Resp (code, _, rb) when code >= 200 && code < 300 -> Delivered rb
  | `Resp (code, h, _)
    when code = 429 || code = 500 || code = 502 || code = 503 || code = 504 ->
      let ra =
        Option.bind
          (Cohttp.Header.get h "retry-after")
          (parse_retry_after ~now:(t.now ()))
      in
      Retryable (Printf.sprintf "HTTP %d" code, ra)
  | `Resp (code, _, _) -> Permanent (Printf.sprintf "HTTP %d" code)
  | `Timeout -> Retryable (Printf.sprintf "timeout after %.0fs" t.timeout, None)
  | `Exn m -> Retryable ("connection error: " ^ m, None)

let send t ~what uri payload =
  let rec attempt n =
    post t uri payload >>= function
    | Delivered rb -> Lwt.return (Ok rb)
    | Permanent m -> Lwt.return (Error m)
    | Retryable (m, ra) ->
        if n >= t.max_retries || (t.stopped && n > 0) then Lwt.return (Error m)
        else begin
          t.n_retries <- t.n_retries + 1;
          let backoff =
            Float.min t.max_backoff (t.base_backoff *. (2. ** float_of_int n))
          in
          let wait =
            match ra with Some r -> Float.min t.max_backoff r | None -> backoff
          in
          Lwt_unix.sleep wait >>= fun () -> attempt (n + 1)
        end
  in
  attempt 0 >|= function
  | Ok rb -> Ok rb
  | Error m ->
      t.n_failures <- t.n_failures + 1;
      t.on_error (Printf.sprintf "otlp %s export to %s failed: %s" what (Uri.path uri) m);
      Error m

(* ---- spans ---- *)

type span = {
  sp_trace_id : string;
  sp_span_id : string;
  sp_parent : string option;
  sp_name : string;
  sp_kind : J.span_kind;
  sp_start : int64;
  sp_flags : int;
  mutable sp_attrs : J.attrs;
  mutable sp_status : J.status;
  mutable sp_ended : bool;
}

let start_span t ?parent ?(kind = J.Internal) ?(attrs = []) name =
  let trace_id, parent_id, flags =
    match parent with
    | Some (p : Traceparent.t) -> (p.trace_id, Some p.parent_id, p.flags land 0xFF)
    | None -> ((if t.enabled then random_hex 16 else String.make 31 '0' ^ "1"), None, 1)
  in
  {
    sp_trace_id = trace_id;
    sp_span_id = (if t.enabled then random_hex 8 else String.make 15 '0' ^ "1");
    sp_parent = parent_id;
    sp_name = name;
    sp_kind = kind;
    sp_start = ns_of (t.now ());
    sp_flags = flags;
    sp_attrs = attrs;
    sp_status = J.Unset;
    sp_ended = false;
  }

let set_attribute sp k v = sp.sp_attrs <- (k, v) :: List.remove_assoc k sp.sp_attrs
let set_status sp s = sp.sp_status <- s

let traceparent sp =
  {
    Traceparent.trace_id = sp.sp_trace_id;
    parent_id = sp.sp_span_id;
    flags = sp.sp_flags;
  }

let span_trace_id sp = sp.sp_trace_id
let span_id sp = sp.sp_span_id

let end_span t sp =
  if not sp.sp_ended then begin
    sp.sp_ended <- true;
    if t.enabled && t.traces && sp.sp_flags land 1 = 1 then
      if Queue.length t.queue >= t.max_queue then t.n_dropped <- t.n_dropped + 1
      else begin
        Queue.push
          {
            J.trace_id = sp.sp_trace_id;
            span_id = sp.sp_span_id;
            parent_span_id = sp.sp_parent;
            name = sp.sp_name;
            kind = sp.sp_kind;
            start_ns = sp.sp_start;
            end_ns = ns_of (t.now ());
            attributes = List.rev sp.sp_attrs;
            status = sp.sp_status;
            flags = sp.sp_flags;
          }
          t.queue;
        if Queue.length t.queue >= t.max_batch then Lwt_condition.broadcast t.wake ()
      end
  end

let start_verify t ?traceparent () =
  let parent = Option.bind traceparent Traceparent.parse in
  start_span t ?parent ~kind:J.Server "haltsql.verify"

let end_verify t sp (v : Haltsql_core.Verdict.t) =
  let codes rs =
    List.map
      (fun (r : Haltsql_core.Reason.t) -> Haltsql_core.Reason.code_to_string r.code)
      rs
  in
  List.iter
    (fun (k, x) -> set_attribute sp k x)
    [
      ("haltsql.policy", J.String v.policy_name);
      ("haltsql.policy_version", J.String v.policy_version);
      ("haltsql.allowed", J.Bool v.allowed);
      ("haltsql.shadow", J.Bool (v.shadow_reasons <> []));
      ("haltsql.reason_codes", J.Strings (codes v.reasons @ codes v.shadow_reasons));
      ("db.system", J.String "postgresql");
      ("db.statement.sha256", J.String v.sql_sha256);
      ("haltsql.elapsed_us", J.Int v.elapsed_us);
    ];
  set_status sp J.Ok;
  end_span t sp

let end_verify_error t sp msg =
  set_status sp (J.Error msg);
  end_span t sp

(* ---- metrics ---- *)

let duration_buckets =
  [|
    0.0001; 0.00025; 0.0005; 0.001; 0.0025; 0.005; 0.01; 0.025; 0.05; 0.1; 0.25; 0.5; 1.0;
  |]

let key attrs = List.sort_uniq (fun (a, _) (b, _) -> compare a b) attrs

let instrument t name ~description ~unit_ mk =
  match Hashtbl.find_opt t.instruments name with
  | Some m -> m.inst
  | None ->
      let inst = mk () in
      Hashtbl.replace t.instruments name { description; unit_; inst };
      inst

let counter_add t ?(description = "") ?(unit_ = "1") ?(attrs = []) name n =
  if t.enabled && n >= 0 then
    match
      instrument t name ~description ~unit_ (fun () -> I_counter (Hashtbl.create 4))
    with
    | I_counter tbl -> (
        let k = key attrs in
        match Hashtbl.find_opt tbl k with
        | Some r -> r := !r + n
        | None -> Hashtbl.replace tbl k (ref n))
    | _ -> ()

let gauge_set t ?(description = "") ?(unit_ = "1") ?(attrs = []) name v =
  if t.enabled then
    match
      instrument t name ~description ~unit_ (fun () -> I_gauge (Hashtbl.create 4))
    with
    | I_gauge tbl -> Hashtbl.replace tbl (key attrs) (ref v)
    | _ -> ()

let histogram_record t ?(description = "") ?(unit_ = "s") ?(bounds = duration_buckets)
    ?(attrs = []) name v =
  if t.enabled then
    match
      instrument t name ~description ~unit_ (fun () ->
          I_hist (Array.copy bounds, Hashtbl.create 4))
    with
    | I_hist (bounds, tbl) ->
        let k = key attrs in
        let h =
          match Hashtbl.find_opt tbl k with
          | Some h -> h
          | None ->
              let h =
                {
                  counts = Array.make (Array.length bounds + 1) 0;
                  sum = 0.;
                  count = 0;
                  hmin = infinity;
                  hmax = neg_infinity;
                }
              in
              Hashtbl.replace tbl k h;
              h
        in
        (* OTLP buckets: (-inf, b0], (b0, b1], ..., (b_{n-1}, +inf) *)
        let i = ref 0 in
        while !i < Array.length bounds && v > bounds.(!i) do
          incr i
        done;
        h.counts.(!i) <- h.counts.(!i) + 1;
        h.sum <- h.sum +. v;
        h.count <- h.count + 1;
        h.hmin <- Float.min h.hmin v;
        h.hmax <- Float.max h.hmax v
    | _ -> ()

let observe_verify t ~policy ~result ~codes ~seconds =
  counter_add t ~description:"Verify requests by policy and result."
    ~attrs:[ ("policy", policy); ("result", result) ]
    "haltsql_verify_total" 1;
  List.iter
    (fun code ->
      counter_add t ~description:"Denial (or shadow denial) reasons by code."
        ~attrs:[ ("code", code) ]
        "haltsql_reasons_total" 1)
    codes;
  histogram_record t ~description:"Time spent verifying one SQL string." ~unit_:"s"
    "haltsql_verify_duration_seconds" seconds

let observe_reload t ~ok =
  counter_add t ~description:"Policy reload attempts by result."
    ~attrs:[ ("result", if ok then "success" else "error") ]
    "haltsql_policy_reload_total" 1

let observe_http t ~route ~status =
  counter_add t ~description:"HTTP requests by route and status."
    ~attrs:[ ("route", route); ("status", string_of_int status) ]
    "haltsql_http_requests_total" 1

let observe_audit_error t =
  counter_add t ~description:"Audit sink write failures." "haltsql_audit_errors_total" 1

let set_policies_loaded t n =
  gauge_set t ~description:"Number of policies currently loaded."
    "haltsql_policies_loaded" (float_of_int n)

let jattrs k = List.map (fun (a, b) -> (a, J.String b)) k

let metrics_snapshot t =
  let named = Hashtbl.fold (fun n m acc -> (n, m) :: acc) t.instruments [] in
  let named =
    if t.enabled then
      ( "haltsql_otlp_spans_dropped_total",
        {
          description =
            "Spans dropped by the OTLP exporter (queue full or export failed).";
          unit_ = "1";
          inst =
            (let h = Hashtbl.create 1 in
             Hashtbl.replace h [] (ref t.n_dropped);
             I_counter h);
        } )
      :: named
    else named
  in
  List.sort (fun (a, _) (b, _) -> compare a b) named
  |> List.map (fun (name, m) ->
      let sorted tbl =
        Hashtbl.fold (fun k v acc -> (k, v) :: acc) tbl [] |> List.sort compare
      in
      match m.inst with
      | I_counter tbl ->
          J.Sum
            {
              name;
              description = m.description;
              unit_ = m.unit_;
              points = List.map (fun (k, r) -> (jattrs k, !r)) (sorted tbl);
            }
      | I_gauge tbl ->
          J.Gauge
            {
              name;
              description = m.description;
              unit_ = m.unit_;
              points = List.map (fun (k, r) -> (jattrs k, !r)) (sorted tbl);
            }
      | I_hist (bounds, tbl) ->
          let pts =
            Hashtbl.fold (fun k v acc -> (k, v) :: acc) tbl []
            |> List.sort (fun (a, _) (b, _) -> compare a b)
          in
          J.Histogram
            {
              name;
              description = m.description;
              unit_ = m.unit_;
              bounds;
              points =
                List.map
                  (fun (k, h) ->
                    {
                      J.h_attrs = jattrs k;
                      bucket_counts = Array.copy h.counts;
                      h_sum = h.sum;
                      h_count = h.count;
                      h_min = (if h.count > 0 then Some h.hmin else None);
                      h_max = (if h.count > 0 then Some h.hmax else None);
                    })
                  pts;
            })

(* ---- export loop ---- *)

let take_batch t =
  let rec go n acc =
    if n = 0 || Queue.is_empty t.queue then List.rev acc
    else go (n - 1) (Queue.pop t.queue :: acc)
  in
  go t.max_batch []

let export_spans t =
  let rec loop () =
    match take_batch t with
    | [] -> Lwt.return_unit
    | batch -> (
        let payload =
          Yojson.Safe.to_string
            (J.traces_request ~resource:t.resource ~scope:t.scope batch)
        in
        send t ~what:"traces" t.traces_uri payload >>= function
        | Ok _ ->
            t.n_exported <- t.n_exported + List.length batch;
            t.n_batches <- t.n_batches + 1;
            loop ()
        | Error _ ->
            (* Drop the batch rather than grow without bound; never block requests. *)
            t.n_dropped <- t.n_dropped + List.length batch;
            loop ())
  in
  loop ()

let export_metrics t =
  t.last_metrics <- t.now ();
  let snap = metrics_snapshot t in
  if snap = [] then Lwt.return_unit
  else
    let payload =
      Yojson.Safe.to_string
        (J.metrics_request ~resource:t.resource ~scope:t.scope ~start_ns:t.start_ns
           ~time_ns:(ns_of (t.now ()))
           snap)
    in
    send t ~what:"metrics" t.metrics_uri payload >|= function
    | Ok _ -> t.n_metric_exports <- t.n_metric_exports + 1
    | Error _ -> ()

let export t ~force_metrics =
  Lwt_mutex.with_lock t.lock (fun () ->
      Lwt.catch
        (fun () ->
          (if t.traces then export_spans t else Lwt.return_unit) >>= fun () ->
          if t.metrics && (force_metrics || t.now () -. t.last_metrics >= t.interval) then
            export_metrics t
          else Lwt.return_unit)
        (fun e ->
          t.on_error ("otlp export failed: " ^ Printexc.to_string e);
          Lwt.return_unit))

let flush t = if t.enabled then export t ~force_metrics:true else Lwt.return_unit

let start t =
  if t.enabled && not t.running then begin
    t.running <- true;
    let rec loop () =
      if t.stopped then Lwt.return_unit
      else
        Lwt.pick [ Lwt_unix.sleep t.interval; Lwt_condition.wait t.wake ] >>= fun () ->
        if t.stopped then Lwt.return_unit else export t ~force_metrics:false >>= loop
    in
    Lwt.async loop
  end

let shutdown t =
  if not t.enabled then Lwt.return_unit
  else begin
    t.stopped <- true;
    Lwt_condition.broadcast t.wake ();
    flush t
  end
