(* Fleet: polls every configured verifier's /v1/admin/status, /readyz and /metrics,
   derives a per-verifier state, aggregates bundles, audit sinks and OPA, and restarts
   verifiers through the Kubernetes API. Owner: PR console/03-fleet. See
   docs/console/api.md#fleet.

   The latest document ([GET /api/v1/fleet] shape) is read with [snapshot]. A short
   in-memory history of metric samples per verifier (the last [fleet.history_size] polls)
   gives request rates, OPA decision and error counts, and buffered-record peaks.

   At most [fleet.max_concurrent_probes] verifiers are probed at once, and a verifier that
   stays unreachable is probed less often (exponential backoff, at most every 9th poll).
   *)

open Lwt.Syntax
module C = Console_config

let log level fmt =
  Printf.ksprintf
    (fun m ->
      Printf.eprintf "{\"ts\":%S,\"level\":%S,\"component\":\"fleet\",\"msg\":%s}\n%!"
        (Api.iso8601 (Unix.gettimeofday ()))
        level
        (Yojson.Safe.to_string (`String m)))
    fmt

(* ---- probes ---- *)

type 'a probe =
  | Got of 'a  (** a usable answer *)
  | Status of int  (** an HTTP answer we cannot use (e.g. 401, 404, 500) *)
  | Failed of string  (** no HTTP answer: connection error or timeout *)

let responded = function Got _ | Status _ -> true | Failed _ -> false

(* How one poll reaches one verifier: TLS trust ([verifiers[].ca_file] or the system
   store), the probe timeout and the admin token resolved for this poll. *)
type conn = {
  tls : Haltsql_cloud.Http.ctx;
  timeout : float;
  token : string option;
  now : unit -> float;  (** clock for sample timestamps *)
}

let http_get (c : conn) ?token url =
  let headers =
    ("accept", "application/json, text/plain")
    :: (match token with Some t -> [ ("authorization", "Bearer " ^ t) ] | None -> [])
  in
  Lwt.catch
    (fun () ->
      Haltsql_cloud.Http.request ~ctx:c.tls ~timeout:c.timeout
        ~max_body:(4 * 1024 * 1024)
        ~headers `GET (Uri.of_string url))
    (fun exn -> Lwt.return (Error (Printexc.to_string exn)))

let json_of s = try Some (Yojson.Safe.from_string s) with _ -> None

(* ---- redaction ---- *)

(* Bundle source ids are raw URLs for https sources, and the fleet document is readable
   by every role: a presigned URL or a [?token=] query must not leak through it. Every
   [scheme://...] run in [s] loses its query, fragment and userinfo. *)
let redact_urls s =
  let n = String.length s in
  let b = Buffer.create n in
  let is_scheme_char c =
    match c with
    | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '+' | '-' | '.' -> true
    | _ -> false
  in
  let is_end c =
    match c with ' ' | '\t' | '\n' | '\r' | '"' | '\'' | '<' | '>' -> true | _ -> false
  in
  let rec find_sep i =
    if i + 3 > n then None
    else if String.sub s i 3 = "://" then Some i
    else find_sep (i + 1)
  in
  let rec go pos =
    match find_sep pos with
    | None -> Buffer.add_string b (String.sub s pos (n - pos))
    | Some sep ->
        (* the URL runs from the scheme's first character to the next delimiter *)
        let start = ref sep in
        while !start > pos && is_scheme_char s.[!start - 1] do
          decr start
        done;
        let stop = ref (sep + 3) in
        while !stop < n && not (is_end s.[!stop]) do
          incr stop
        done;
        Buffer.add_string b (String.sub s pos (sep + 3 - pos));
        let rest = String.sub s (sep + 3) (!stop - sep - 3) in
        let authority_end =
          match String.index_opt rest '/' with Some i -> i | None -> String.length rest
        in
        let rest =
          if authority_end = 0 then rest
          else
            match String.rindex_from_opt rest (authority_end - 1) '@' with
            | Some i ->
                "<redacted>@" ^ String.sub rest (i + 1) (String.length rest - i - 1)
            | None -> rest
        in
        let cut =
          match (String.index_opt rest '?', String.index_opt rest '#') with
          | Some a, Some h -> Some (min a h)
          | Some a, None -> Some a
          | None, Some h -> Some h
          | None, None -> None
        in
        (match cut with
        | Some i -> Buffer.add_string b (String.sub rest 0 i ^ "?<redacted>")
        | None -> Buffer.add_string b rest);
        go !stop
  in
  go 0;
  Buffer.contents b

let redact_json = function `String s -> `String (redact_urls s) | j -> j

let admin_status (c : conn) (v : C.verifier) =
  let+ r = http_get c ?token:c.token (v.v_url ^ "/v1/admin/status") in
  match r with
  | Error e -> Failed e
  | Ok { status = 200; body; _ } -> (
      match json_of body with
      | Some (`Assoc _ as j) -> Got j
      | _ -> Failed "admin status is not a JSON object")
  | Ok { status; _ } -> Status status

let readyz (c : conn) (v : C.verifier) =
  let+ r = http_get c (v.v_url ^ "/readyz") in
  match r with
  | Error e -> Failed e
  | Ok { status = (200 | 503) as status; body; _ } ->
      Got (status, Option.value (json_of body) ~default:`Null)
  | Ok { status; _ } -> Status status

(* The sample time is when this verifier's metrics arrived, not when the slowest probe
   of the poll finished. *)
let metrics (c : conn) (v : C.verifier) =
  let url = Option.value v.v_metrics_url ~default:(v.v_url ^ "/metrics") in
  (* The admin token only goes to the verifier's own origin, never to a separate
     metrics host. *)
  let origin u =
    let u = Uri.of_string u in
    (Uri.scheme u, Uri.host u, Uri.port u)
  in
  let token = if origin url = origin v.v_url then c.token else None in
  let+ r = http_get c ?token url in
  match r with
  | Error e -> Failed e
  | Ok { status = 200; body; _ } -> Got (c.now (), Prom.parse body)
  | Ok { status; _ } -> Status status

(* haltsql-proxy serves PostgreSQL only (no HTTP endpoints): a TCP connect to its
   address is the liveness check when its url is not http(s). *)
let tcp_check ~timeout url =
  let u = Uri.of_string url in
  match (Uri.host u, Uri.port u) with
  | Some host, port ->
      let port = Option.value port ~default:5432 in
      Lwt.catch
        (fun () ->
          Lwt_unix.with_timeout timeout (fun () ->
              let* addrs =
                Lwt_unix.getaddrinfo host (string_of_int port)
                  [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ]
              in
              match addrs with
              | [] -> Lwt.return (Error "host does not resolve")
              | a :: _ ->
                  let fd = Lwt_unix.socket a.Unix.ai_family Unix.SOCK_STREAM 0 in
                  Lwt.finalize
                    (fun () ->
                      let+ () = Lwt_unix.connect fd a.Unix.ai_addr in
                      Ok ())
                    (fun () -> Lwt_unix.close fd)))
        (function
          | Lwt_unix.Timeout -> Lwt.return (Error "connection timed out")
          | Unix.Unix_error (e, _, _) -> Lwt.return (Error (Unix.error_message e))
          | exn -> Lwt.return (Error (Printexc.to_string exn)))
  | None, _ -> Lwt.return (Error "url has no host")

let is_http url =
  match Uri.scheme (Uri.of_string url) with Some ("http" | "https") -> true | _ -> false

(* ---- metrics history ---- *)

(* What one poll's /metrics contributes to the history. *)
type sample = {
  at : float;
  verify_total : float option;  (** sum of haltsql_verify_total *)
  opa : (string * float) list;  (** haltsql_opa_decisions_total by outcome *)
  external_policy : float option;  (** haltsql_reasons_total for code E_EXTERNAL_POLICY *)
  buffered : (string * float) list;  (** buffered records by sink name *)
  connections : float option;
}

let sample_of ~at samples =
  let opa =
    List.filter_map
      (fun (s : Prom.sample) ->
        Option.map (fun o -> (o, s.value)) (Prom.label s "outcome"))
      (Prom.select samples "haltsql_opa_decisions_total")
  in
  let buffered =
    List.filter_map
      (fun (s : Prom.sample) -> Option.map (fun n -> (n, s.value)) (Prom.label s "sink"))
      (Prom.select samples "haltsql_audit_sink_buffered_records"
      @ Prom.select samples "haltsql_audit_stream_sink_buffered_records")
  in
  {
    at;
    verify_total = Prom.sum samples "haltsql_verify_total";
    opa;
    external_policy =
      Prom.sum ~labels:[ ("code", "E_EXTERNAL_POLICY") ] samples "haltsql_reasons_total";
    buffered;
    connections = Prom.sum samples "haltsql_http_open_connections";
  }

(* Per-console state, in the Ctx registry under a private key: history by verifier
   name, newest first, and the last fleet document. *)
type state = {
  history : (string, sample list) Hashtbl.t;
  backoff : (string, backoff) Hashtbl.t;  (** unreachable verifiers, by name *)
  mutable doc : Yojson.Safe.t option;
}

and backoff = {
  failures : int;  (** consecutive unreachable polls *)
  mutable skip : int;  (** polls left before the next probe *)
  last_error : string;
}

let key : state Ctx.Key.t = Ctx.Key.create "fleet"

let state_of (ctx : Ctx.t) =
  match Ctx.get ctx key with
  | Some s -> s
  | None ->
      let s = { history = Hashtbl.create 8; backoff = Hashtbl.create 8; doc = None } in
      Ctx.set ctx key s;
      s

(** The last fleet document ([GET /api/v1/fleet] shape), [None] before the first poll. *)
let snapshot (ctx : Ctx.t) = (state_of ctx).doc

(** For tests only: replaces the stored fleet document without polling. *)
module Testing = struct
  let set_snapshot (ctx : Ctx.t) doc = (state_of ctx).doc <- doc
end

let rec take n = function
  | [] -> []
  | x :: t -> if n <= 0 then [] else x :: take (n - 1) t

let record_sample ~size st name s =
  let h = Option.value (Hashtbl.find_opt st.history name) ~default:[] in
  Hashtbl.replace st.history name (take size (s :: h))

(* Counter increase over the history (newest first), treating a decrease as a counter
   reset (the new value is then the increase), like Prometheus [increase]. *)
let increase (f : sample -> float option) history =
  let values = List.filter_map f (List.rev history) in
  match values with
  | [] -> None
  | first :: rest ->
      let total, _ =
        List.fold_left
          (fun (acc, prev) v -> ((acc +. if v >= prev then v -. prev else v), v))
          (0., first) rest
      in
      Some total

let window_seconds history =
  match (history, List.rev history) with
  | newest :: _, oldest :: _ -> newest.at -. oldest.at
  | _ -> 0.

let opa_outcome o (s : sample) = List.assoc_opt o s.opa

let opa_errors (s : sample) =
  match (opa_outcome "error_allowed" s, opa_outcome "error_denied" s) with
  | None, None -> if s.opa = [] then None else Some 0.
  | a, b -> Some (Option.value a ~default:0. +. Option.value b ~default:0.)

(* ---- JSON helpers ---- *)

let mem name j = Option.value (Api.member name j) ~default:`Null
let str name j = match mem name j with `String s -> Some s | _ -> None
let to_int f = int_of_float (Float.round f)

let int_or_null = function
  | `Int i -> `Int i
  | `Intlit _ as i -> i
  | `Float f -> `Int (to_int f)
  | _ -> `Null

let pick names j = `Assoc (List.map (fun n -> (n, mem n j)) names)

(* ---- one verifier ---- *)

type polled = {
  v : C.verifier;
  status : Yojson.Safe.t probe;
  ready : (int * Yojson.Safe.t) probe;
  prom : (float * Prom.sample list) probe;  (** arrival time, samples *)
  tcp : (unit, string) result option;  (** proxy without HTTP endpoints *)
  setup_error : string option;
      (** the console could not prepare the probe (token or CA), so admin status was not
          asked *)
  retry_in : int option;  (** not probed this poll (backoff); polls until the next probe *)
}

let failed_all ?setup_error ?retry_in v e =
  {
    v;
    status = Failed e;
    ready = Failed e;
    prom = Failed e;
    tcp = None;
    setup_error;
    retry_in;
  }

(* The admin token for this poll: re-resolved from its placeholder (the resolver caches
   provider values for a few minutes), so a rotated token is used without a restart. *)
let token_for (ctx : Ctx.t) (v : C.verifier) =
  match v.v_token_ref with
  | None -> Lwt.return (Ok v.v_token)
  | Some template -> (
      let+ r = C.resolve ctx.config template in
      match r with Ok t -> Ok (Some t) | Error e -> Error ("token: " ^ e))

let tls_for (v : C.verifier) =
  match v.v_ca_file with
  | None -> Lwt.return (Ok Haltsql_cloud.Http.default_ctx)
  | Some f -> (
      let+ r = Haltsql_cloud.Http.ctx_of_ca_file f in
      match r with Ok c -> Ok c | Error e -> Error ("ca_file: " ^ e))

let poll_verifier ?now (ctx : Ctx.t) (v : C.verifier) =
  let timeout = ctx.config.fleet_probe_timeout in
  if v.v_kind = C.Proxy && not (is_http v.v_url) then
    let+ tcp = tcp_check ~timeout v.v_url in
    {
      v;
      status = Status 404;
      ready = Status 404;
      prom = Status 404;
      tcp = Some tcp;
      setup_error = None;
      retry_in = None;
    }
  else
    let* tls = tls_for v in
    match tls with
    | Error e -> Lwt.return (failed_all ~setup_error:e v e)
    | Ok tls ->
        let* token = token_for ctx v in
        let token, setup_error =
          match token with Ok t -> (t, None) | Error e -> (None, Some e)
        in
        let now = match now with Some t -> fun () -> t | None -> Ctx.now in
        let c = { tls; timeout; token; now } in
        let* status =
          match setup_error with
          | Some e -> Lwt.return (Failed e)
          | None -> admin_status c v
        and* ready = readyz c v
        and* prom = metrics c v in
        Lwt.return { v; status; ready; prom; tcp = None; setup_error; retry_in = None }

let reachable p =
  match p.tcp with
  | Some r -> Result.is_ok r
  | None -> responded p.status || responded p.ready || responded p.prom

let first_failure p =
  match p.tcp with
  | Some (Error e) -> Some e
  | _ -> (
      match (p.status, p.ready, p.prom) with
      | Failed e, _, _ | _, Failed e, _ | _, _, Failed e -> Some e
      | _ -> None)

let status_json p = match p.status with Got j -> Some j | _ -> None

type sink_view = {
  s_name : string;
  s_type : string;
  s_healthy : bool;
  s_buffered : float option;
}

let sink_state s =
  match (s.s_healthy, s.s_buffered) with
  | false, Some b when b > 0. -> "buffering"
  | false, _ -> "failing"
  | true, Some b when b > 0. -> "buffering"
  | true, _ -> "healthy"

let sinks_of p (latest : sample option) =
  let buffered name =
    match latest with Some s -> List.assoc_opt name s.buffered | None -> None
  in
  match status_json p with
  | Some j -> (
      match mem "audit_sinks" j with
      | `List l ->
          List.filter_map
            (fun s ->
              match str "name" s with
              | None -> None
              | Some name ->
                  Some
                    {
                      s_name = name;
                      s_type = Option.value (str "type" s) ~default:"unknown";
                      s_healthy = (match mem "healthy" s with `Bool b -> b | _ -> true);
                      s_buffered = buffered name;
                    })
            l
      | _ -> [])
  | None -> []

let unhealthy_from_readyz p =
  match p.ready with
  | Got (_, j) -> (
      match mem "unhealthy_audit_sinks" j with
      | `List l -> List.filter_map (function `String s -> Some s | _ -> None) l
      | _ -> [])
  | _ -> []

let bundle_json b =
  let cur = mem "current" b in
  `Assoc
    [
      ("source", redact_json (mem "source" b));
      ("bundle", mem "bundle" cur);
      ("version", mem "version" cur);
      ("signed_by", mem "signed_by" cur);
      ("revision", mem "revision" cur);
      ("checks", mem "checks" b);
      ("last_success", mem "last_success" b);
      ("last_error", redact_json (mem "last_error" b));
    ]

(** Every bundle source the verifier reports, in its order. *)
let bundles_of j =
  match mem "bundle_sources" j with `List l -> List.map bundle_json l | _ -> []

(** The first bundle source ([verifiers[].bundle], kept for compatibility). *)
let bundle_of j = match bundles_of j with b :: _ -> b | [] -> `Null

type derived = {
  state : string;
  note : string;
  error : string option;
  unhealthy : string list;
  sinks : sink_view list;
}

let derive p latest =
  let kind = p.v.v_kind in
  let sinks = sinks_of p latest in
  let unhealthy =
    List.sort_uniq compare
      (unhealthy_from_readyz p
      @ List.filter_map (fun s -> if s.s_healthy then None else Some s.s_name) sinks)
  in
  let buffered_total =
    List.fold_left (fun acc s -> acc +. Option.value s.s_buffered ~default:0.) 0. sinks
  in
  let status_error =
    match p.status with
    | Status 404 -> None
    | Status ((401 | 403) as c) ->
        Some
          (Printf.sprintf
             "admin status: HTTP %d (list the console's token in server.admin.callers)" c)
    | Status c -> Some (Printf.sprintf "admin status: HTTP %d" c)
    | Failed e when reachable p -> Some ("admin status: " ^ e)
    | _ -> None
  in
  let status_error =
    match p.setup_error with
    | Some e -> Some ("admin status: " ^ e)
    | None -> status_error
  in
  if not (reachable p) then
    let e = Option.value (first_failure p) ~default:"no answer" in
    let e =
      match p.retry_in with
      | Some n ->
          Printf.sprintf "%s (backing off: next probe in %d %s)" e n
            (if n = 1 then "poll" else "polls")
      | None -> e
    in
    {
      state = "unreachable";
      note = Printf.sprintf "No answer from %s." p.v.v_url;
      error = Some e;
      unhealthy = [];
      sinks = [];
    }
  else if unhealthy <> [] || buffered_total > 0. then
    let note =
      match unhealthy with
      | [] -> Printf.sprintf "Audit sinks are buffering %.0f records." buffered_total
      | l ->
          Printf.sprintf "Audit %s %s unhealthy%s."
            (if List.length l = 1 then "sink" else "sinks")
            (String.concat ", " l ^ if List.length l = 1 then " is" else " are")
            (if buffered_total > 0. then
               Printf.sprintf "; %.0f records buffered" buffered_total
             else "")
    in
    { state = "buffering"; note; error = status_error; unhealthy; sinks }
  else
    let not_ready =
      match p.ready with
      | Got (503, j) ->
          Some
            (if mem "draining" j = `Bool true then "Draining: shutting down."
             else if mem "policies" j = `Int 0 then "Not ready: no policy is loaded."
             else "Not ready (readyz answered 503).")
      | Status c when c <> 404 -> Some (Printf.sprintf "readyz answered HTTP %d." c)
      | _ -> None
    in
    match not_ready with
    | Some note -> { state = "not_ready"; note; error = status_error; unhealthy; sinks }
    | None ->
        let restart_pending =
          match status_json p with
          | Some j -> mem "audit_restart_pending" j = `Bool true
          | None -> false
        in
        if restart_pending then
          {
            state = "restart_pending";
            note =
              "The last reload changed audit.sinks; records keep going to the running \
               sinks until a restart.";
            error = status_error;
            unhealthy;
            sinks;
          }
        else
          let note =
            match (status_json p, p.tcp) with
            | _, Some _ ->
                "Accepting connections (haltsql-proxy exposes no HTTP status; state is \
                 from a TCP check)."
            | Some j, _ ->
                let n = match mem "policies" j with `List l -> List.length l | _ -> 0 in
                let one b =
                  match (str "bundle" b, str "version" b) with
                  | Some name, Some ver -> Some (Printf.sprintf "%s %s" name ver)
                  | None, Some ver -> Some ver
                  | _ -> None
                in
                let bundle =
                  match List.filter_map one (bundles_of j) with
                  | [] -> ""
                  | [ b ] -> ", bundle " ^ b
                  | l -> ", bundles " ^ String.concat ", " l
                in
                Printf.sprintf "Ready: %d %s%s." n
                  (if n = 1 then "policy" else "policies")
                  bundle
            | None, None -> (
                match (p.ready, p.status, kind) with
                | Got _, Status 404, C.Server ->
                    "Ready (the admin API is disabled: enable server.admin for details)."
                | Got _, _, _ -> "Ready (no admin status available)."
                | _ -> "Reachable; this verifier exposes no admin status or readiness.")
          in
          { state = "ready"; note; error = status_error; unhealthy; sinks }

let verifier_json p ~history =
  let latest = match history with s :: _ -> Some s | [] -> None in
  let fresh =
    (* the history entry belongs to this poll only when metrics answered *)
    match p.prom with
    | Got _ -> latest
    | _ -> None
  in
  let d = derive p fresh in
  let st = status_json p in
  let from_status name = match st with Some j -> mem name j | None -> `Null in
  let rate =
    match (fresh, history) with
    | Some cur, _ :: prev :: _ -> (
        match (cur.verify_total, prev.verify_total) with
        | Some c, Some pv when cur.at > prev.at ->
            let inc = if c >= pv then c -. pv else c in
            `Float (Float.round (inc /. (cur.at -. prev.at) *. 10.) /. 10.)
        | _ -> `Null)
    | _ -> `Null
  in
  let opa_configured =
    match st with Some j -> `Bool (mem "opa" j <> `Null) | None -> `Null
  in
  let opa_timeouts =
    match fresh with
    | Some _ -> (
        match increase opa_errors history with
        | Some f -> `Int (to_int f)
        | None -> `Int 0)
    | None -> `Null
  in
  let ext_denials =
    match fresh with
    | Some _ -> (
        match increase (fun s -> s.external_policy) history with
        | Some f -> `Int (to_int f)
        | None -> `Int 0)
    | None -> `Null
  in
  let policies =
    match from_status "policies" with
    | `List l -> `List (List.map (pick [ "name"; "version"; "mode"; "origin" ]) l)
    | _ -> `List []
  in
  let buffered_total =
    match fresh with
    | Some s when s.buffered <> [] ->
        `Int (to_int (List.fold_left (fun a (_, b) -> a +. b) 0. s.buffered))
    | Some _ -> `Int 0
    | None -> `Null
  in
  `Assoc
    [
      ("name", `String p.v.v_name);
      ("kind", `String (C.verifier_kind_to_string p.v.v_kind));
      ("location", Api.opt_string p.v.v_location);
      ("url", `String p.v.v_url);
      ("state", `String d.state);
      ("version", from_status "version");
      ("uptime_seconds", int_or_null (from_status "uptime_seconds"));
      ("config_generation", int_or_null (from_status "config_generation"));
      ("policies", policies);
      ("bundle", match st with Some j -> bundle_of j | None -> `Null);
      ("bundles", `List (match st with Some j -> bundles_of j | None -> []));
      ( "sinks",
        `List
          (List.map
             (fun s ->
               `Assoc
                 [
                   ("name", `String s.s_name);
                   ("type", `String s.s_type);
                   ("healthy", `Bool s.s_healthy);
                   ( "buffered_records",
                     match s.s_buffered with Some b -> `Int (to_int b) | None -> `Null );
                 ])
             d.sinks) );
      ("unhealthy_sinks", Api.strings d.unhealthy);
      ("buffered_records", buffered_total);
      ( "opa",
        `Assoc
          [
            ("configured", opa_configured);
            ("timeouts", opa_timeouts);
            ("external_policy_denials", ext_denials);
          ] );
      ( "restart_pending",
        match from_status "audit_restart_pending" with
        | `Bool b -> `Bool b
        | _ -> `Bool false );
      ( "connections",
        match fresh with
        | Some { connections = Some c; _ } -> `Int (to_int c)
        | _ -> `Null );
      ("verifies_per_second", rate);
      ("note", `String d.note);
      ("error", Api.opt_string d.error);
    ]

(* ---- aggregates ---- *)

(* Bundles grouped by source; in sync when every verifier serving the source reports the
   same version and revision. *)
let bundles_json polled =
  let entries =
    List.concat_map
      (fun p ->
        match status_json p with
        | Some j -> (
            match mem "bundle_sources" j with
            | `List l ->
                List.filter_map
                  (fun b ->
                    match str "source" b with
                    | None -> None
                    | Some src ->
                        let src = redact_urls src in
                        let cur = mem "current" b in
                        Some
                          ( src,
                            p.v.v_name,
                            (str "version" cur, str "revision" cur),
                            str "signed_by" cur ))
                  l
            | _ -> [])
        | None -> [])
      polled
  in
  let sources = List.sort_uniq compare (List.map (fun (s, _, _, _) -> s) entries) in
  List.map
    (fun src ->
      let mine = List.filter (fun (s, _, _, _) -> s = src) entries in
      let keys = List.sort_uniq compare (List.map (fun (_, _, k, _) -> k) mine) in
      let groups =
        List.map
          (fun k ->
            let members = List.filter (fun (_, _, k', _) -> k' = k) mine in
            let signed = List.find_map (fun (_, _, _, sb) -> sb) members in
            (k, signed, List.map (fun (_, n, _, _) -> n) members))
          keys
        (* majority first *)
        |> List.stable_sort (fun (_, _, a) (_, _, b) ->
            compare (List.length b) (List.length a))
      in
      let (version, revision), signed_by, _ = List.hd groups in
      let in_sync = List.length groups = 1 && version <> None in
      `Assoc
        [
          ("source", `String src);
          ("version", Api.opt_string version);
          ("signed_by", Api.opt_string signed_by);
          ("revision", Api.opt_string revision);
          ("verifiers", `Int (List.length mine));
          ("in_sync", `Bool in_sync);
          ( "versions",
            `List
              (List.map
                 (fun ((v, r), sb, names) ->
                   `Assoc
                     [
                       ("version", Api.opt_string v);
                       ("revision", Api.opt_string r);
                       ("signed_by", Api.opt_string sb);
                       ("verifiers", Api.strings names);
                     ])
                 groups) );
        ])
    sources

let state_rank = function "failing" -> 2 | "buffering" -> 1 | _ -> 0

(* Audit sinks grouped by target (the sink name the verifiers report). *)
let sinks_json st polled_with_sinks =
  let all =
    List.concat_map
      (fun (p, sinks) -> List.map (fun s -> (p.v.C.v_name, s)) sinks)
      polled_with_sinks
  in
  let targets = List.sort_uniq compare (List.map (fun (_, s) -> s.s_name) all) in
  List.map
    (fun target ->
      let mine = List.filter (fun (_, s) -> s.s_name = target) all in
      let state =
        List.fold_left
          (fun acc (_, s) ->
            let x = sink_state s in
            if state_rank x > state_rank acc then x else acc)
          "healthy" mine
      in
      let buffered =
        List.fold_left
          (fun a (_, s) -> a +. Option.value s.s_buffered ~default:0.)
          0. mine
      in
      let peak =
        List.fold_left
          (fun acc (vname, _) ->
            let h = Option.value (Hashtbl.find_opt st.history vname) ~default:[] in
            List.fold_left
              (fun acc s ->
                match List.assoc_opt target s.buffered with
                | Some b -> Float.max acc b
                | None -> acc)
              acc h)
          0. mine
      in
      `Assoc
        [
          ("type", `String (snd (List.hd mine)).s_type);
          ("target", `String target);
          ("state", `String state);
          ("verifiers", `Int (List.length mine));
          ("buffered_records", `Int (to_int buffered));
          ("peak_buffered_records", `Int (to_int peak));
          ( "unhealthy_verifiers",
            Api.strings
              (List.filter_map
                 (fun (n, s) -> if sink_state s = "healthy" then None else Some n)
                 mine) );
        ])
    targets

let opa_outcomes = [ "allowed"; "denied"; "error_denied"; "error_allowed"; "skipped" ]
let opa_fields = [ "decision_path"; "host"; "timeout_ms"; "on_error" ]

(* OPA settings grouped like bundles: one entry per distinct setting, majority first, so
   drift between verifiers is visible. The top-level fields are the majority's. *)
let opa_json st polled =
  let confs =
    List.filter_map
      (fun p ->
        Option.bind (status_json p) (fun j ->
            match mem "opa" j with
            | `Null -> None
            | o -> Some (pick opa_fields o, p.v.C.v_name)))
      polled
  in
  let groups =
    List.sort_uniq compare (List.map fst confs)
    |> List.map (fun c ->
        (c, List.filter_map (fun (c', n) -> if c' = c then Some n else None) confs))
    |> List.stable_sort (fun (_, a) (_, b) -> compare (List.length b) (List.length a))
  in
  let conf = match groups with (c, _) :: _ -> Some c | [] -> None in
  let histories =
    List.map
      (fun p -> Option.value (Hashtbl.find_opt st.history p.v.C.v_name) ~default:[])
      polled
  in
  let decisions =
    List.map
      (fun o ->
        let total =
          List.fold_left
            (fun acc h -> acc +. Option.value (increase (opa_outcome o) h) ~default:0.)
            0. histories
        in
        (o, `Int (to_int total)))
      opa_outcomes
  in
  let window =
    List.fold_left (fun acc h -> Float.max acc (window_seconds h)) 0. histories
  in
  let c name = match conf with Some o -> mem name o | None -> `Null in
  `Assoc
    [
      ("configured", `Bool (conf <> None));
      ("decision_path", c "decision_path");
      ("endpoint", c "host");
      ("timeout_ms", c "timeout_ms");
      ("on_error", c "on_error");
      ("in_sync", `Bool (List.length groups <= 1));
      ( "configs",
        `List
          (List.map
             (fun (o, names) ->
               `Assoc
                 [
                   ("decision_path", mem "decision_path" o);
                   ("endpoint", mem "host" o);
                   ("timeout_ms", mem "timeout_ms" o);
                   ("on_error", mem "on_error" o);
                   ("verifiers", Api.strings names);
                 ])
             groups) );
      ("decisions", `Assoc decisions);
      ("window_seconds", `Int (to_int window));
    ]

let empty () =
  `Assoc
    [
      ("updated", `Null);
      ("config_generation", `Null);
      ("verifiers", `List []);
      ("bundles", `List []);
      ("sinks", `List []);
      ( "opa",
        opa_json { history = Hashtbl.create 1; backoff = Hashtbl.create 1; doc = None } []
      );
    ]

(* ---- polling ---- *)

(** Polls every verifier once and stores the document (read with [snapshot]). *)
let max_skip = 8

(* Probes [v] unless it is backing off, and updates its backoff: after [n] consecutive
   unreachable polls it is skipped for [min (2^(n-1) - 1) max_skip] polls, so one blip
   costs nothing and a dead verifier is probed at most every [max_skip + 1] polls. *)
let probe_with_backoff ?now ctx st (v : C.verifier) =
  match Hashtbl.find_opt st.backoff v.v_name with
  | Some b when b.skip > 0 ->
      b.skip <- b.skip - 1;
      Lwt.return (failed_all ~retry_in:(b.skip + 1) v b.last_error)
  | prev ->
      let+ p = poll_verifier ?now ctx v in
      (match (reachable p, p.setup_error) with
      | true, _ | false, Some _ -> Hashtbl.remove st.backoff v.v_name
      | false, None ->
          let failures = match prev with Some b -> b.failures + 1 | None -> 1 in
          let skip = min ((1 lsl min (failures - 1) 10) - 1) max_skip in
          Hashtbl.replace st.backoff v.v_name
            {
              failures;
              skip;
              last_error = Option.value (first_failure p) ~default:"no answer";
            });
      p

let poll_once ?now (ctx : Ctx.t) =
  let st = state_of ctx in
  (* at most [fleet.max_concurrent_probes] verifiers in flight (3 requests each) *)
  let slots =
    Lwt_pool.create (max 1 ctx.config.fleet_max_concurrent) (fun () -> Lwt.return_unit)
  in
  let* polled =
    Lwt_list.map_p
      (fun v -> Lwt_pool.use slots (fun () -> probe_with_backoff ?now ctx st v))
      ctx.config.verifiers
  in
  let now = match now with Some t -> t | None -> Ctx.now () in
  List.iter
    (fun p ->
      match p.prom with
      | Got (at, samples) ->
          record_sample ~size:ctx.config.fleet_history_size st p.v.C.v_name
            (sample_of ~at samples)
      | _ -> ())
    polled;
  let hist p = Option.value (Hashtbl.find_opt st.history p.v.C.v_name) ~default:[] in
  let verifiers = List.map (fun p -> verifier_json p ~history:(hist p)) polled in
  let with_sinks =
    List.map
      (fun p ->
        let fresh = match (p.prom, hist p) with Got _, s :: _ -> Some s | _ -> None in
        (p, if reachable p then sinks_of p fresh else []))
      polled
  in
  let generation =
    List.fold_left
      (fun acc p ->
        match Option.map (mem "config_generation") (status_json p) with
        | Some (`Int g) -> ( match acc with Some a when a >= g -> acc | _ -> Some g)
        | _ -> acc)
      None polled
  in
  let doc =
    `Assoc
      [
        ("updated", `String (Api.iso8601 now));
        ("config_generation", Api.opt_int generation);
        ("verifiers", `List verifiers);
        ("bundles", `List (bundles_json polled));
        ("sinks", `List (sinks_json st with_sinks));
        ("opa", opa_json st polled);
      ]
  in
  st.doc <- Some doc;
  Lwt.return doc

let start (ctx : Ctx.t) : unit Lwt.t =
  if ctx.config.verifiers = [] then Lwt.return_unit
  else
    let period = float_of_int (max 1 ctx.config.fleet_poll_seconds) in
    (* +-10% jitter, so consoles (and verifiers' metrics scrapes) do not stay in lock-step *)
    let rng = Random.State.make_self_init () in
    let jittered () = period *. (0.9 +. Random.State.float rng 0.2) in
    let rec loop () =
      let* () =
        Lwt.catch
          (fun () ->
            let+ _ = poll_once ctx in
            ())
          (fun exn ->
            log "error" "fleet poll failed: %s" (Printexc.to_string exn);
            Lwt.return_unit)
      in
      let* () = Lwt_unix.sleep (jittered ()) in
      loop ()
    in
    loop ()

(* ---- restart ---- *)

let restart ctx (p : Ctx.principal) (r : Router.req) =
  let* body = Router.json_body r in
  let reason = Ctx.require ~body p r.http Rbac.Restart_verifiers in
  let reason =
    match reason with
    | Some _ -> reason
    | None -> (
        (* restarts always need a reason, even for roles granted the permission outright *)
        match Ctx.reason_of ~body r.http with
        | Some _ as x -> x
        | None ->
            Api.fail `Forbidden "REASON_REQUIRED"
              "restart_verifiers needs a reason (x-haltsql-reason header or reason field)"
        )
  in
  let name = Router.param r "name" in
  let v =
    match
      List.find_opt (fun (v : C.verifier) -> v.v_name = name) ctx.Ctx.config.verifiers
    with
    | Some v -> v
    | None -> Api.not_found "no verifier named %s" name
  in
  let k =
    match ctx.config.kubernetes with
    | Some k -> k
    | None -> Api.not_configured "restarts need fleet.kubernetes in the console config"
  in
  let w =
    match v.v_workload with
    | None -> Api.not_configured "verifier %s has no workload configured" name
    | Some s -> (
        match K8s.parse_workload s with
        | Some w -> w
        | None ->
            Api.not_configured
              "verifier %s: workload must be deployment/<name> or statefulset/<name>" name
        )
  in
  let workload = K8s.workload_to_string w in
  let restarted_at = Api.iso8601 (Ctx.now ()) in
  let detail extra =
    `Assoc
      ([ ("workload", `String workload); ("namespace", `String k.k_namespace) ] @ extra)
  in
  (* Audit first: the intent is durably logged before the PATCH, so a rollout never
     happens without a trace. If this write fails the restart is refused (fail closed). *)
  let* () =
    Activity.log ctx p ?reason ~action:"fleet.restart_requested" ~target:name
      ~detail:
        (detail [ ("restarted_at", `String restarted_at); ("result", `String "pending") ])
      ()
  in
  let* result = K8s.restart k w ~restarted_at in
  let outcome_detail =
    match result with
    | Ok K8s.Rolled_out ->
        [ ("restarted_at", `String restarted_at); ("result", `String "ok") ]
    | Ok (K8s.No_rollout why) ->
        [
          ("restarted_at", `String restarted_at);
          ("result", `String "no_rollout");
          ("warning", `String why);
        ]
    | Error (K8s.Config e | K8s.Upstream e) ->
        [ ("result", `String "error"); ("error", `String e) ]
  in
  let* () =
    Activity.log ctx p ?reason ~action:"fleet.restart" ~target:name
      ~detail:(detail outcome_detail) ()
  in
  match result with
  | Ok outcome ->
      Api.json
        (`Assoc
           ([
              ("verifier", `String name);
              ("workload", `String workload);
              ("restarted_at", `String restarted_at);
              ( "result",
                `String
                  (match outcome with
                  | K8s.Rolled_out -> "ok"
                  | No_rollout _ -> "no_rollout") );
            ]
           @
           match outcome with
           | K8s.No_rollout why -> [ ("warning", `String why) ]
           | Rolled_out -> []))
  | Error (K8s.Config e) -> Api.not_configured "restart of %s: %s" workload e
  | Error (K8s.Upstream e) -> Api.upstream "restart of %s failed: %s" workload e

let routes : Router.route list =
  [
    Router.get "/api/v1/fleet" (fun ctx _p _r ->
        Api.json (match snapshot ctx with Some f -> f | None -> empty ()));
    Router.post "/api/v1/fleet/:name/restart" restart;
  ]
