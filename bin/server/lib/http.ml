(* HTTP routing and handlers for haltsql-server. *)

open Lwt.Syntax
open Haltsql
module S = Cohttp_lwt_unix.Server

(* ---- request ids ---- *)

let rng = lazy (Random.State.make_self_init ())

let uuid_v4 () =
  let st = Lazy.force rng in
  let b = Bytes.init 16 (fun _ -> Char.chr (Random.State.int st 256)) in
  Bytes.set b 6 (Char.chr (Char.code (Bytes.get b 6) land 0x0f lor 0x40));
  Bytes.set b 8 (Char.chr (Char.code (Bytes.get b 8) land 0x3f lor 0x80));
  let h =
    Bytes.to_seq b
    |> Seq.map (fun c -> Printf.sprintf "%02x" (Char.code c))
    |> List.of_seq
  in
  let s = String.concat "" h in
  Printf.sprintf "%s-%s-%s-%s-%s" (String.sub s 0 8) (String.sub s 8 4)
    (String.sub s 12 4) (String.sub s 16 4) (String.sub s 20 12)

(* Accept a caller-supplied X-Request-Id only if it is short and safe. *)
let valid_request_id s =
  let n = String.length s in
  n > 0 && n <= 128
  && String.for_all
       (function
         | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '-' | '_' | '.' | ':' -> true
         | _ -> false)
       s

(* ---- responses ---- *)

let json_headers rid =
  Cohttp.Header.of_list
    [
      ("content-type", "application/json");
      ("x-request-id", rid);
      ("cache-control", "no-store");
    ]

let respond ?(extra = []) ~rid status (body : Yojson.Safe.t) =
  let headers = Cohttp.Header.add_list (json_headers rid) extra in
  S.respond_string ~headers ~status ~body:(Yojson.Safe.to_string body ^ "\n") ()

let error ?extra ~rid status code message =
  respond ?extra ~rid status
    (`Assoc [ ("error", `Assoc [ ("code", `String code); ("message", `String message) ]) ])

let text ~rid ?(content_type = "text/plain; charset=utf-8") status body =
  let headers =
    Cohttp.Header.of_list [ ("content-type", content_type); ("x-request-id", rid) ]
  in
  S.respond_string ~headers ~status ~body ()

(* ---- body reading with a size cap ---- *)

exception Too_large

let read_body ~max (req : Cohttp.Request.t) body =
  let declared =
    match Cohttp.Header.get (Cohttp.Request.headers req) "content-length" with
    | Some s -> int_of_string_opt (String.trim s)
    | None -> None
  in
  match declared with
  | Some n when n > max -> Lwt.return_error `Too_large
  | _ ->
      let buf = Buffer.create 1024 in
      Lwt.catch
        (fun () ->
          let* () =
            Lwt_stream.iter
              (fun chunk ->
                if Buffer.length buf + String.length chunk > max then raise Too_large;
                Buffer.add_string buf chunk)
              (Cohttp_lwt.Body.to_stream body)
          in
          Lwt.return_ok (Buffer.contents buf))
        (function Too_large -> Lwt.return_error `Too_large | e -> Lwt.reraise e)

(* ---- caller resolution ----

   Order: a verified client certificate mapped to an mTLS identity; then the
   bearer token: a JWT whose issuer matches a configured OIDC provider is
   verified as such, anything else is checked against the static token
   hashes. Callers with an authenticated context (OIDC claims, mTLS static
   context) may only add the request-body context fields they are allowed. *)

(* What authenticated the caller; server.admin.callers match on this, never on the
   display name. *)
type identity =
  | Id_token of string  (** token name *)
  | Id_oidc of string  (** provider name *)
  | Id_mtls of Config.mtls_match  (** the matched identity's selector *)
  | Id_anonymous

type caller = {
  identity : identity;
  caller_name : string;
  caller_type : string;  (** token | oidc | mtls | anonymous *)
  subject : string option;  (** OIDC sub / SPIFFE id / certificate CN *)
  pinned : string option;
  auth_context : (Context.t * string list) option;
      (** authenticated context and the body fields still allowed; [None]: the body
          supplies the whole context (static tokens, anonymous) *)
}

type auth_failure =
  | Unauthenticated of string  (** 401 *)
  | Auth_unavailable of string  (** 503: e.g. the IdP's keys cannot be fetched *)

let bearer_token header =
  match header with
  | None -> `Missing
  | Some h ->
      let h = String.trim h in
      let prefix = "bearer " in
      let lp = String.length prefix in
      if String.length h <= lp || String.lowercase_ascii (String.sub h 0 lp) <> prefix
      then `Invalid
      else
        let t = String.trim (String.sub h lp (String.length h - lp)) in
        if t = "" then `Invalid else `Token t

let static_caller (st : State.t) header =
  match Auth.authenticate st.snap.tokens header with
  | Auth.Token t ->
      Metrics.observe_auth ~meth:"token" ~result:"ok";
      Ok
        {
          identity = Id_token t.token_name;
          caller_name = t.token_name;
          caller_type = "token";
          subject = None;
          pinned = Some t.token_policy;
          auth_context = None;
        }
  | Auth.Missing when st.snap.allow_unauthenticated ->
      Metrics.observe_auth ~meth:"anonymous" ~result:"ok";
      Ok
        {
          identity = Id_anonymous;
          caller_name = "anonymous";
          caller_type = "anonymous";
          subject = None;
          pinned = None;
          auth_context = None;
        }
  | Auth.Missing ->
      Metrics.observe_auth ~meth:"none" ~result:"rejected";
      Error (Unauthenticated "missing bearer token")
  | Auth.Invalid ->
      Metrics.observe_auth ~meth:"token" ~result:"rejected";
      Error (Unauthenticated "invalid bearer token")

let resolve_caller (st : State.t) (conn : Conn.t) req =
  let mtls_identity =
    match conn.peer with
    | Some peer when st.snap.mtls <> [] -> (
        match Haltsql_auth.Mtls.find_identity st.snap.mtls peer with
        | Some id -> Some (peer, id)
        | None -> None)
    | _ -> None
  in
  match mtls_identity with
  | Some (peer, id) ->
      Metrics.observe_auth ~meth:"mtls" ~result:"ok";
      let subject = Haltsql_auth.Mtls.subject peer in
      Lwt.return_ok
        {
          identity = Id_mtls id.mtls_match;
          caller_name = "mtls:" ^ subject;
          caller_type = "mtls";
          subject = Some subject;
          pinned = Some id.mtls_policy;
          auth_context = Some (id.mtls_context, id.mtls_request_context_fields);
        }
  | None -> (
      let header = Cohttp.Header.get (Cohttp.Request.headers req) "authorization" in
      if Option.is_some conn.peer && st.snap.mtls <> [] && Option.is_none header then (
        Metrics.observe_auth ~meth:"mtls" ~result:"rejected";
        Lwt.return_error
          (Unauthenticated "client certificate does not match any configured identity"))
      else
        match bearer_token header with
        | `Token tok when not (Haltsql_auth.Oidc_client.is_empty st.snap.oidc) -> (
            let* r = Haltsql_auth.Oidc_client.authenticate st.snap.oidc tok in
            match r with
            | `Not_applicable -> Lwt.return (static_caller st header)
            | `Verified (id : Haltsql_auth.Oidc.identity) ->
                Metrics.observe_auth ~meth:"oidc" ~result:"ok";
                Lwt.return_ok
                  {
                    identity = Id_oidc id.provider;
                    caller_name = "oidc:" ^ id.provider;
                    caller_type = "oidc";
                    subject = id.subject;
                    pinned = Some id.policy;
                    auth_context = Some (id.context, id.request_context_fields);
                  }
            | `Rejected (Haltsql_auth.Jwt.Keys_unavailable _ as e) ->
                Metrics.observe_auth ~meth:"oidc" ~result:"unavailable";
                Lwt.return_error (Auth_unavailable (Haltsql_auth.Jwt.error_to_string e))
            | `Rejected e ->
                Metrics.observe_auth ~meth:"oidc" ~result:"rejected";
                Log.info "oidc token rejected"
                  ~fields:
                    [
                      ("reason", `String (Haltsql_auth.Jwt.error_code e));
                      ("remote", `String conn.remote);
                    ];
                Lwt.return_error (Unauthenticated (Haltsql_auth.Jwt.error_to_string e)))
        | _ -> Lwt.return (static_caller st header))

let unauthorized ~rid msg =
  error ~rid
    ~extra:[ ("www-authenticate", "Bearer realm=\"haltsql\"") ]
    `Unauthorized "UNAUTHORIZED" msg

let auth_error ~rid = function
  | Unauthenticated msg -> unauthorized ~rid msg
  | Auth_unavailable msg ->
      error ~rid
        ~extra:[ ("retry-after", "5") ]
        `Service_unavailable "AUTH_UNAVAILABLE" msg

(* ---- OPA (opa in the config): asked only after HaltSQL allowed ---- *)

let opa_check (st : State.t) ~caller ~(policy : Policy.t) ~ctx (verdict : Verdict.t) =
  match st.snap.opa with
  | None -> Lwt.return verdict
  | Some cfg ->
      let t0 = Unix.gettimeofday () in
      let* verdict, outcome =
        Haltsql_opa.Opa.enforce ~code:Reason.E_EXTERNAL_POLICY ~mode:policy.mode ~cfg
          ~caller:{ caller_name = caller.caller_name; caller_type = caller.caller_type }
          ~context:ctx verdict
      in
      let label = Haltsql_opa.Opa.outcome_label outcome in
      Metrics.observe_opa ~outcome:label ~seconds:(Unix.gettimeofday () -. t0);
      (match outcome with
      | Haltsql_opa.Opa.Failed_open e | Haltsql_opa.Opa.Failed_closed e ->
          Log.warn "opa check failed"
            ~fields:[ ("outcome", `String label); ("error", `String e) ]
      | Haltsql_opa.Opa.Skipped | Haltsql_opa.Opa.Allowed | Haltsql_opa.Opa.Denied _ -> ());
      Lwt.return verdict

(* ---- /v1/verify ---- *)

type verify_req = { sql : string; context : Yojson.Safe.t; policy : string option }

let parse_verify_req s =
  match Yojson.Safe.from_string s with
  | exception Yojson.Json_error e -> Error ("body is not valid JSON: " ^ e)
  | `Assoc kv -> (
      let unknown =
        List.filter (fun (k, _) -> not (List.mem k [ "sql"; "context"; "policy" ])) kv
      in
      if unknown <> [] then
        Error
          (Printf.sprintf "unknown field(s): %s (allowed: sql, context, policy)"
             (String.concat ", " (List.map fst unknown)))
      else
        let sql = List.assoc_opt "sql" kv in
        let context = Option.value (List.assoc_opt "context" kv) ~default:(`Assoc []) in
        let policy = List.assoc_opt "policy" kv in
        match (sql, context, policy) with
        | None, _, _ -> Error "\"sql\" is required"
        | Some (`String _), (`Assoc _ | `Null), (None | Some `Null | Some (`String _)) ->
            let sql = match sql with Some (`String s) -> s | _ -> assert false in
            let policy = match policy with Some (`String p) -> Some p | _ -> None in
            let context = match context with `Null -> `Assoc [] | c -> c in
            Ok { sql; context; policy }
        | Some (`String _), (`Assoc _ | `Null), Some _ ->
            Error "\"policy\" must be a string"
        | Some (`String _), _, _ -> Error "\"context\" must be an object"
        | Some _, _, _ -> Error "\"sql\" must be a string")
  | _ -> Error "body must be a JSON object"

let audit_record (st : State.t) ~rid ~caller ~(verdict : Verdict.t) ~sql =
  let fields =
    Audit.record_fields
      ~ts:(Log.rfc3339 (Unix.gettimeofday ()))
      ~request_id:rid ~caller:caller.caller_name ~caller_type:caller.caller_type
      ~subject:caller.subject ~verdict ~sql ~log_raw_sql:st.cfg.log_raw_sql
  in
  let failures =
    List.filter_map
      (fun (sink : Audit.sink) ->
        match Audit.deliver sink fields with
        | Audit.Written -> None
        | Audit.Buffered ->
            Metrics.observe_audit_error ();
            Log.warn "audit sink write failed; record buffered"
              ~fields:[ ("sink", `String sink.name); ("request_id", `String rid) ];
            None
        | Audit.Failed e -> Some (sink.name, e))
      st.sinks
  in
  List.iter
    (fun (name, e) ->
      Metrics.observe_audit_error ();
      Log.error "audit sink write failed; failing request closed"
        ~fields:
          [ ("sink", `String name); ("error", `String e); ("request_id", `String rid) ])
    failures;
  if failures = [] then
    Admin_report.observe_verdict st.report ~caller:caller.caller_name
      ~caller_type:caller.caller_type
      ~sql:(if st.cfg.log_raw_sql then Some sql else None)
      verdict;
  failures = []

let handle_verify_inner (st : State.t) ~conn ~rid ~on_verdict req body =
  let* c = resolve_caller st conn req in
  match c with
  | Error e -> auth_error ~rid e
  | Ok caller -> (
      let* b = read_body ~max:st.cfg.max_request_bytes req body in
      match b with
      | Error `Too_large ->
          error ~rid
            ~extra:[ ("connection", "close") ]
            `Request_entity_too_large "PAYLOAD_TOO_LARGE"
            (Printf.sprintf "request body exceeds %d bytes" st.cfg.max_request_bytes)
      | Ok s -> (
          match parse_verify_req s with
          | Error m -> error ~rid `Bad_request "BAD_REQUEST" m
          | Ok r -> (
              let policy_name =
                match (caller.pinned, r.policy) with
                | Some pinned, Some requested when requested <> pinned -> Error `Forbidden
                | Some pinned, _ -> Ok pinned
                | None, Some requested -> Ok requested
                | None, None -> (
                    match State.default_policy st with
                    | Some n -> Ok n
                    | None -> Error `No_default)
              in
              match policy_name with
              | Error `Forbidden ->
                  error ~rid `Forbidden "FORBIDDEN"
                    (Printf.sprintf "this %s caller is pinned to a different policy"
                       caller.caller_type)
              | Error `No_default when st.snap.policies = [] ->
                  error ~rid `Service_unavailable "NOT_READY" "no policy is loaded"
              | Error `No_default ->
                  error ~rid `Not_found "POLICY_NOT_FOUND"
                    "no policy specified and no default_policy configured"
              | Ok name -> (
                  let ctx =
                    match (Context.of_json r.context, caller.auth_context) with
                    | Error e, _ -> Error (`Bad e)
                    | Ok body, None -> Ok body
                    | Ok body, Some (authenticated, allowed) -> (
                        match
                          Haltsql_auth.Request_context.merge ~authenticated ~allowed ~body
                        with
                        | Ok c -> Ok c
                        | Error fields -> Error (`Not_allowed fields))
                  in
                  match (State.find_policy st name, ctx) with
                  | None, _ when caller.pinned <> None ->
                      error ~rid `Service_unavailable "POLICY_UNAVAILABLE"
                        (Printf.sprintf "policy %S pinned to this token is not loaded"
                           name)
                  | None, _ ->
                      error ~rid `Not_found "POLICY_NOT_FOUND"
                        (Printf.sprintf "unknown policy %S" name)
                  | Some _, Error (`Bad e) ->
                      error ~rid `Bad_request "BAD_REQUEST" ("invalid context: " ^ e)
                  | Some _, Error (`Not_allowed fields) ->
                      error ~rid `Forbidden "CONTEXT_NOT_ALLOWED"
                        (Printf.sprintf
                           "context field(s) %s may not be supplied in the request for \
                            this %s caller (the authenticated identity provides the \
                            context)"
                           (String.concat ", " fields) caller.caller_type)
                  | Some policy, Ok ctx ->
                      let t0 = Unix.gettimeofday () in
                      let verdict = Haltsql.verify policy ctx r.sql in
                      let seconds = Unix.gettimeofday () -. t0 in
                      let* verdict = opa_check st ~caller ~policy ~ctx verdict in
                      on_verdict verdict;
                      let result =
                        if not verdict.allowed then "denied"
                        else if verdict.shadow_reasons <> [] then "shadow_denied"
                        else "allowed"
                      in
                      Metrics.observe_verify ~policy:name ~result ~seconds
                        ~codes:
                          (List.map
                             (fun (x : Reason.t) -> Reason.code_to_string x.code)
                             (verdict.reasons @ verdict.shadow_reasons));
                      if audit_record st ~rid ~caller ~verdict ~sql:r.sql then
                        respond ~rid `OK (Verdict.to_json verdict)
                      else
                        error ~rid `Service_unavailable "AUDIT_UNAVAILABLE"
                          "the audit log could not be written; request denied (fail \
                           closed)"))))

(* One OTLP span per verify request (a no-op without telemetry.otlp). The span
   carries the SQL hash, never the SQL. An incoming W3C traceparent is honoured. *)
let handle_verify (st : State.t) ~conn ~rid req body =
  let module E = Telemetry.Exporter in
  let exp = Telemetry.exporter () in
  let span =
    E.start_verify exp
      ?traceparent:(Cohttp.Header.get (Cohttp.Request.headers req) "traceparent")
      ()
  in
  let verdict = ref None in
  Lwt.catch
    (fun () ->
      let* resp, b =
        handle_verify_inner st ~conn ~rid
          ~on_verdict:(fun v -> verdict := Some v)
          req body
      in
      let status = Cohttp.Code.code_of_status (Cohttp.Response.status resp) in
      (match !verdict with
      | Some v when status = 200 -> E.end_verify exp span v
      | _ -> E.end_verify_error exp span (Printf.sprintf "HTTP %d" status));
      Lwt.return (resp, b))
    (fun e ->
      E.end_verify_error exp span "internal error";
      Lwt.reraise e)

(* ---- other endpoints ---- *)

let handle_policies (st : State.t) ~conn ~rid req =
  let* c = resolve_caller st conn req in
  match c with
  | Error e -> auth_error ~rid e
  | Ok caller ->
      let visible =
        match caller.pinned with
        | Some p -> List.filter (fun (n, _) -> n = p) st.snap.policies
        | None -> st.snap.policies
      in
      respond ~rid `OK
        (`Assoc
           [
             ( "policies",
               `List
                 (List.map
                    (fun (n, (p : Policy.t)) ->
                      `Assoc
                        [
                          ("name", `String n);
                          ("version", `String p.version);
                          ( "mode",
                            `String
                              (match p.mode with
                              | Policy.Enforce -> "enforce"
                              | Policy.Shadow -> "shadow") );
                        ])
                    visible) );
             ( "default",
               match (caller.pinned, State.default_policy st) with
               | None, Some d -> `String d
               | _ -> `Null );
           ])

(* ---- admin API (server.admin) ----

   404 while server.admin is disabled (the routes do not exist). Otherwise the
   caller must authenticate (401) and match one of server.admin.callers (403).
   Matching uses the identity that authenticated the caller: a token name, an
   OIDC provider, or the selector of the matched mTLS identity. Anonymous callers
   never match. *)

let oidc_admin_matches spec ~provider ~subject ~pinned =
  if String.equal spec provider then true
  else
    let n = String.length provider and m = String.length spec in
    if m > n + 1 && String.sub spec 0 n = provider && (spec.[n] = ':' || spec.[n] = '/')
    then
      let qual = String.sub spec (n + 1) (m - n - 1) in
      subject = Some qual || pinned = Some qual
    else false

let is_admin (admin : Config.admin) (c : caller) =
  List.exists
    (fun (a : Config.admin_caller) ->
      match (a, c.identity) with
      | Config.Admin_token n, Id_token t -> String.equal n t
      | Config.Admin_oidc p, Id_oidc q ->
          oidc_admin_matches p ~provider:q ~subject:c.subject ~pinned:c.pinned
      | Config.Admin_mtls m, Id_mtls k -> m = k
      | (Config.Admin_token _ | Config.Admin_oidc _ | Config.Admin_mtls _), _ -> false)
    admin.admin_callers

let with_admin (st : State.t) ~conn ~rid ~endpoint req k =
  if not st.snap.admin.admin_enabled then begin
    Metrics.observe_admin ~endpoint ~result:"disabled";
    error ~rid `Not_found "NOT_FOUND" "the admin API is disabled (server.admin)"
  end
  else
    let* c = resolve_caller st conn req in
    match c with
    | Error e ->
        Metrics.observe_admin ~endpoint ~result:"unauthenticated";
        auth_error ~rid e
    | Ok caller when caller.identity = Id_anonymous ->
        Metrics.observe_admin ~endpoint ~result:"unauthenticated";
        unauthorized ~rid "the admin API requires an authenticated caller"
    | Ok caller when not (is_admin st.snap.admin caller) ->
        Metrics.observe_admin ~endpoint ~result:"forbidden";
        Log.info "admin request refused"
          ~fields:
            [
              ("request_id", `String rid);
              ("caller", `String caller.caller_name);
              ("endpoint", `String endpoint);
            ];
        error ~rid `Forbidden "FORBIDDEN"
          "this caller is not listed in server.admin.callers"
    | Ok caller ->
        Metrics.observe_admin ~endpoint ~result:"ok";
        k caller

let handle_admin_report (st : State.t) ~conn ~rid req =
  with_admin st ~conn ~rid ~endpoint:"report" req (fun _caller ->
      let status, body =
        Admin_report.handle st.report ~policies:st.snap.policies
          ~query:(Uri.query (Cohttp.Request.uri req))
      in
      respond ~rid (Cohttp.Code.status_of_code status) body)

let policy_origin (st : State.t) name =
  if List.exists (fun (_, ps) -> List.mem_assoc name ps) st.remote then "bundle_source"
  else if List.mem_assoc name st.cfg.policies then "config"
  else "bundle_or_file"

let handle_admin_status (st : State.t) ~conn ~rid req =
  with_admin st ~conn ~rid ~endpoint:"status" req (fun _caller ->
      let now = Unix.gettimeofday () in
      let sink_json (s : Audit.sink) =
        `Assoc
          [
            ("name", `String s.name);
            ("type", `String (Audit.kind s));
            ("healthy", `Bool (Audit.healthy s));
          ]
      in
      let opa =
        match st.snap.opa with
        | None -> `Null
        | Some o ->
            `Assoc
              [
                ( "host",
                  match Uri.host (Uri.of_string o.opa_url) with
                  | Some h -> `String h
                  | None -> `Null );
                ("decision_path", `String o.decision_path);
                ("timeout_ms", `Int o.opa_timeout_ms);
                ( "on_error",
                  `String
                    (match o.opa_on_error with
                    | Config.Opa_deny -> "deny"
                    | Config.Opa_allow_haltsql_verdict -> "allow_haltsql_verdict") );
              ]
      in
      respond ~rid `OK
        (`Assoc
           [
             ("version", `String Haltsql.version);
             ("started", `String (Log.rfc3339 st.started));
             ("uptime_seconds", `Int (int_of_float (now -. st.started)));
             ("config_generation", `Int st.generation);
             ( "default_policy",
               match State.default_policy st with Some d -> `String d | None -> `Null );
             ( "policies",
               `List
                 (List.map
                    (fun (n, (p : Policy.t)) ->
                      `Assoc
                        [
                          ("name", `String n);
                          ("version", `String p.version);
                          ( "mode",
                            `String
                              (match p.mode with
                              | Policy.Enforce -> "enforce"
                              | Policy.Shadow -> "shadow") );
                          ("origin", `String (policy_origin st n));
                        ])
                    st.snap.policies) );
             ( "bundle_sources",
               `List (List.map Bundle_sources.status_json st.bundle_sources) );
             ("audit_sinks", `List (List.map sink_json st.sinks));
             ("audit_restart_pending", `Bool st.audit_restart_pending);
             ("opa", opa);
             ( "report",
               `Assoc
                 [
                   ("tracked_queries", `Int (Admin_report.tracked_queries st.report));
                   ("evicted_queries", `Int (Admin_report.evicted st.report));
                   ("sampled_out", `Int (Admin_report.sampled_out st.report));
                 ] );
           ]))

let routes =
  [
    ("/v1/admin/report", [ `GET ]);
    ("/v1/admin/status", [ `GET ]);
    ("/v1/verify", [ `POST ]);
    ("/healthz", [ `GET; `HEAD ]);
    ("/readyz", [ `GET; `HEAD ]);
    ("/metrics", [ `GET ]);
    ("/v1/policies", [ `GET ]);
  ]

let health_routes = [ "/healthz"; "/readyz" ]

let callback ?(health_only = false) (st : State.t) ((conn : Conn.t), _)
    (req : Cohttp.Request.t) body =
  let t0 = Unix.gettimeofday () in
  let rid =
    match Cohttp.Header.get (Cohttp.Request.headers req) "x-request-id" with
    | Some r when valid_request_id r -> r
    | _ -> uuid_v4 ()
  in
  let path = Uri.path (Cohttp.Request.uri req) in
  let meth = Cohttp.Request.meth req in
  let* resp, rbody =
    Lwt.catch
      (fun () ->
        match (meth, path) with
        | _, p when health_only && not (List.mem p health_routes) ->
            error ~rid `Not_found "NOT_FOUND" ("no route for " ^ p)
        | `POST, "/v1/verify" -> handle_verify st ~conn ~rid req body
        | (`GET | `HEAD), "/healthz" ->
            respond ~rid `OK (`Assoc [ ("status", `String "ok") ])
        | (`GET | `HEAD), "/readyz" ->
            let n = List.length st.snap.policies in
            let unhealthy =
              List.filter_map
                (fun (s : Audit.sink) ->
                  if Audit.healthy s then None else Some (`String s.name))
                st.sinks
            in
            if unhealthy <> [] then
              respond ~rid `Service_unavailable
                (`Assoc
                   [
                     ("status", `String "not_ready");
                     ("policies", `Int n);
                     ("unhealthy_audit_sinks", `List unhealthy);
                   ])
            else if n > 0 then
              respond ~rid `OK
                (`Assoc [ ("status", `String "ready"); ("policies", `Int n) ])
            else
              respond ~rid `Service_unavailable
                (`Assoc [ ("status", `String "not_ready"); ("policies", `Int 0) ])
        | `GET, "/metrics" when st.cfg.metrics ->
            text ~rid ~content_type:"text/plain; version=0.0.4; charset=utf-8" `OK
              (Metrics.render ~version:Haltsql.version ~pg:Pg_parse.postgres_version
                 ~policies_loaded:(List.length st.snap.policies)
              ^ Haltsql_cloud.Object_sink.metrics_text (Audit.object_sinks st.sinks)
              ^ Haltsql_siem.Siem.metrics_text (Audit.stream_sinks st.sinks)
              ^ Bundle_sources.metrics_text st.bundle_sources)
        | `GET, "/v1/policies" -> handle_policies st ~conn ~rid req
        | `GET, "/v1/admin/report" -> handle_admin_report st ~conn ~rid req
        | `GET, "/v1/admin/status" -> handle_admin_status st ~conn ~rid req
        | _, p when p <> "/metrics" || st.cfg.metrics -> (
            match List.assoc_opt p routes with
            | Some ms ->
                error ~rid
                  ~extra:
                    [
                      ( "allow",
                        String.concat ", " (List.map Cohttp.Code.string_of_method ms) );
                    ]
                  `Method_not_allowed "METHOD_NOT_ALLOWED"
                  (Printf.sprintf "%s is not allowed on %s"
                     (Cohttp.Code.string_of_method meth)
                     p)
            | None -> error ~rid `Not_found "NOT_FOUND" ("no route for " ^ p))
        | _ -> error ~rid `Not_found "NOT_FOUND" ("no route for " ^ path))
      (fun e ->
        Log.error "internal error handling request"
          ~fields:
            [ ("request_id", `String rid); ("error", `String (Printexc.to_string e)) ];
        error ~rid `Internal_server_error "INTERNAL" "internal server error")
  in
  let status = Cohttp.Code.code_of_status (Cohttp.Response.status resp) in
  let route = if List.mem_assoc path routes then path else "other" in
  Metrics.observe_http ~path:route ~status;
  let log =
    if List.mem path [ "/healthz"; "/readyz"; "/metrics" ] then Log.debug else Log.info
  in
  log "request"
    ~fields:
      [
        ("request_id", `String rid);
        ("method", `String (Cohttp.Code.string_of_method meth));
        ("path", `String path);
        ("status", `Int status);
        ( "duration_ms",
          `Float (Float.round ((Unix.gettimeofday () -. t0) *. 1e6) /. 1000.) );
      ];
  Lwt.return (resp, rbody)
