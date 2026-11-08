(* In-process Prometheus metrics (text exposition format 0.0.4). The server
   runs on a single Lwt thread, so plain mutable tables suffice. *)

let verify_total : (string * string, int) Hashtbl.t = Hashtbl.create 16
let reasons_total : (string, int) Hashtbl.t = Hashtbl.create 16
let reload_total : (string, int) Hashtbl.t = Hashtbl.create 4
let http_total : (string * int, int) Hashtbl.t = Hashtbl.create 16
let audit_errors = ref 0

(* (method, result): method token|oidc|mtls|anonymous|none, result ok|rejected|unavailable *)
let auth_total : (string * string, int) Hashtbl.t = Hashtbl.create 8
let tls_reload_total : (string, int) Hashtbl.t = Hashtbl.create 2

let buckets =
  [|
    0.0001; 0.00025; 0.0005; 0.001; 0.0025; 0.005; 0.01; 0.025; 0.05; 0.1; 0.25; 0.5; 1.0;
  |]

let bucket_counts = Array.make (Array.length buckets) 0
let duration_sum = ref 0.
let duration_count = ref 0

let incr tbl key =
  Hashtbl.replace tbl key (1 + Option.value (Hashtbl.find_opt tbl key) ~default:0)

let reset () =
  Hashtbl.reset verify_total;
  Hashtbl.reset reasons_total;
  Hashtbl.reset reload_total;
  Hashtbl.reset http_total;
  Hashtbl.reset auth_total;
  Hashtbl.reset tls_reload_total;
  audit_errors := 0;
  Array.fill bucket_counts 0 (Array.length bucket_counts) 0;
  duration_sum := 0.;
  duration_count := 0

(* result: "allowed" | "denied" | "shadow_denied" *)
let observe_verify ~policy ~result ~codes ~seconds =
  incr verify_total (policy, result);
  List.iter (incr reasons_total) codes;
  Array.iteri
    (fun i le -> if seconds <= le then bucket_counts.(i) <- bucket_counts.(i) + 1)
    buckets;
  duration_sum := !duration_sum +. seconds;
  Stdlib.incr duration_count;
  Telemetry.Exporter.observe_verify (Telemetry.exporter ()) ~policy ~result ~codes
    ~seconds

let observe_reload ~ok =
  incr reload_total (if ok then "success" else "error");
  Telemetry.Exporter.observe_reload (Telemetry.exporter ()) ~ok

let observe_http ~path ~status =
  incr http_total (path, status);
  Telemetry.Exporter.observe_http (Telemetry.exporter ()) ~route:path ~status

let observe_audit_error () =
  Stdlib.incr audit_errors;
  Telemetry.Exporter.observe_audit_error (Telemetry.exporter ())

let set_policies_loaded n =
  Telemetry.Exporter.set_policies_loaded (Telemetry.exporter ()) n

let observe_auth ~meth ~result = incr auth_total (meth, result)
let observe_tls_reload ~ok = incr tls_reload_total (if ok then "success" else "error")

let escape_label s =
  let b = Buffer.create (String.length s) in
  String.iter
    (function
      | '\\' -> Buffer.add_string b "\\\\"
      | '"' -> Buffer.add_string b "\\\""
      | '\n' -> Buffer.add_string b "\\n"
      | c -> Buffer.add_char b c)
    s;
  Buffer.contents b

let float_str f =
  if Float.is_integer f && Float.abs f < 1e15 then Printf.sprintf "%.0f" f
  else Printf.sprintf "%.9g" f

let sorted tbl = Hashtbl.fold (fun k v acc -> (k, v) :: acc) tbl [] |> List.sort compare

let render ~version ~pg ~policies_loaded =
  let b = Buffer.create 2048 in
  let p fmt = Printf.bprintf b fmt in
  let header name typ help = p "# HELP %s %s\n# TYPE %s %s\n" name help name typ in
  header "haltsql_build_info" "gauge" "Build information.";
  p "haltsql_build_info{version=\"%s\",pg=\"%s\"} 1\n" (escape_label version)
    (escape_label pg);
  header "haltsql_policies_loaded" "gauge" "Number of policies currently loaded.";
  p "haltsql_policies_loaded %d\n" policies_loaded;
  header "haltsql_verify_total" "counter" "Verify requests by policy and result.";
  List.iter
    (fun ((policy, result), n) ->
      p "haltsql_verify_total{policy=\"%s\",result=\"%s\"} %d\n" (escape_label policy)
        (escape_label result) n)
    (sorted verify_total);
  header "haltsql_reasons_total" "counter" "Denial (or shadow denial) reasons by code.";
  List.iter
    (fun (code, n) -> p "haltsql_reasons_total{code=\"%s\"} %d\n" (escape_label code) n)
    (sorted reasons_total);
  header "haltsql_verify_duration_seconds" "histogram"
    "Time spent verifying one SQL string.";
  Array.iteri
    (fun i le ->
      p "haltsql_verify_duration_seconds_bucket{le=\"%s\"} %d\n" (float_str le)
        bucket_counts.(i))
    buckets;
  p "haltsql_verify_duration_seconds_bucket{le=\"+Inf\"} %d\n" !duration_count;
  p "haltsql_verify_duration_seconds_sum %s\n" (float_str !duration_sum);
  p "haltsql_verify_duration_seconds_count %d\n" !duration_count;
  header "haltsql_policy_reload_total" "counter" "Policy reload attempts by result.";
  List.iter
    (fun (r, n) -> p "haltsql_policy_reload_total{result=\"%s\"} %d\n" (escape_label r) n)
    (sorted reload_total);
  header "haltsql_audit_errors_total" "counter" "Audit sink write failures.";
  p "haltsql_audit_errors_total %d\n" !audit_errors;
  header "haltsql_http_requests_total" "counter" "HTTP requests by route and status.";
  List.iter
    (fun ((path, status), n) ->
      p "haltsql_http_requests_total{route=\"%s\",status=\"%d\"} %d\n" (escape_label path)
        status n)
    (sorted http_total);
  header "haltsql_auth_total" "counter"
    "Caller authentication attempts by method and result.";
  List.iter
    (fun ((m, r), n) ->
      p "haltsql_auth_total{method=\"%s\",result=\"%s\"} %d\n" (escape_label m)
        (escape_label r) n)
    (sorted auth_total);
  header "haltsql_tls_reload_total" "counter" "TLS certificate reload attempts by result.";
  List.iter
    (fun (r, n) -> p "haltsql_tls_reload_total{result=\"%s\"} %d\n" (escape_label r) n)
    (sorted tls_reload_total);
  Buffer.contents b
