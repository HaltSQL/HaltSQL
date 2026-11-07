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

(* ---- caller resolution ---- *)

type caller = { caller_name : string; pinned : string option }

let resolve_caller (st : State.t) req =
  let header = Cohttp.Header.get (Cohttp.Request.headers req) "authorization" in
  match Auth.authenticate st.snap.tokens header with
  | Auth.Token t -> Ok { caller_name = t.token_name; pinned = Some t.token_policy }
  | Auth.Missing when st.cfg.allow_unauthenticated ->
      Ok { caller_name = "anonymous"; pinned = None }
  | Auth.Missing -> Error "missing bearer token"
  | Auth.Invalid -> Error "invalid bearer token"

let unauthorized ~rid msg =
  error ~rid
    ~extra:[ ("www-authenticate", "Bearer realm=\"haltsql\"") ]
    `Unauthorized "UNAUTHORIZED" msg

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
      ~request_id:rid ~caller:caller.caller_name ~verdict ~sql
      ~log_raw_sql:st.cfg.log_raw_sql
  in
  let failures =
    List.filter_map
      (fun (sink : Audit.sink) ->
        match Audit.append sink fields with
        | () -> None
        | exception Unix.Unix_error (e, _, _) -> Some (sink.name, Unix.error_message e)
        | exception Sys_error e -> Some (sink.name, e))
      st.sinks
  in
  List.iter
    (fun (name, e) ->
      incr Metrics.audit_errors;
      Log.error "audit sink write failed; failing request closed"
        ~fields:
          [ ("sink", `String name); ("error", `String e); ("request_id", `String rid) ])
    failures;
  failures = []

let handle_verify (st : State.t) ~rid req body =
  match resolve_caller st req with
  | Error msg -> unauthorized ~rid msg
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
                    "this token is pinned to a different policy"
              | Error `No_default when st.snap.policies = [] ->
                  error ~rid `Service_unavailable "NOT_READY" "no policy is loaded"
              | Error `No_default ->
                  error ~rid `Not_found "POLICY_NOT_FOUND"
                    "no policy specified and no default_policy configured"
              | Ok name -> (
                  match (State.find_policy st name, Context.of_json r.context) with
                  | None, _ when caller.pinned <> None ->
                      error ~rid `Service_unavailable "POLICY_UNAVAILABLE"
                        (Printf.sprintf "policy %S pinned to this token is not loaded"
                           name)
                  | None, _ ->
                      error ~rid `Not_found "POLICY_NOT_FOUND"
                        (Printf.sprintf "unknown policy %S" name)
                  | Some _, Error e ->
                      error ~rid `Bad_request "BAD_REQUEST" ("invalid context: " ^ e)
                  | Some policy, Ok ctx ->
                      let t0 = Unix.gettimeofday () in
                      let verdict = Haltsql.verify policy ctx r.sql in
                      let seconds = Unix.gettimeofday () -. t0 in
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

(* ---- other endpoints ---- *)

let handle_policies (st : State.t) ~rid req =
  match resolve_caller st req with
  | Error msg -> unauthorized ~rid msg
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

let routes =
  [
    ("/v1/verify", [ `POST ]);
    ("/healthz", [ `GET; `HEAD ]);
    ("/readyz", [ `GET; `HEAD ]);
    ("/metrics", [ `GET ]);
    ("/v1/policies", [ `GET ]);
  ]

let callback (st : State.t) _conn (req : Cohttp.Request.t) body =
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
        | `POST, "/v1/verify" -> handle_verify st ~rid req body
        | (`GET | `HEAD), "/healthz" ->
            respond ~rid `OK (`Assoc [ ("status", `String "ok") ])
        | (`GET | `HEAD), "/readyz" ->
            let n = List.length st.snap.policies in
            if n > 0 then
              respond ~rid `OK
                (`Assoc [ ("status", `String "ready"); ("policies", `Int n) ])
            else
              respond ~rid `Service_unavailable
                (`Assoc [ ("status", `String "not_ready"); ("policies", `Int 0) ])
        | `GET, "/metrics" when st.cfg.metrics ->
            text ~rid ~content_type:"text/plain; version=0.0.4; charset=utf-8" `OK
              (Metrics.render ~version:Haltsql.version ~pg:Pg_parse.postgres_version
                 ~policies_loaded:(List.length st.snap.policies))
        | `GET, "/v1/policies" -> handle_policies st ~rid req
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
