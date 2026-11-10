(* Queries search, one record with its decision trail, raw SQL, chain of custody.
   Owner: PR console/02-records. See docs/console/api.md "Queries and records". *)

open Lwt.Syntax

let log level fmt =
  Printf.ksprintf
    (fun m ->
      Printf.eprintf "{\"ts\":%S,\"level\":%S,\"component\":\"records\",\"msg\":%s}\n%!"
        (Api.iso8601 (Unix.gettimeofday ()))
        level
        (Yojson.Safe.to_string (`String m)))
    fmt

let nonempty = function Some s when String.trim s <> "" -> Some s | _ -> None

(* ---- GET /api/v1/queries ---- *)

let time_param req name =
  match nonempty (Api.query req name) with
  | None -> None
  | Some s -> (
      match Api.parse_time s with
      | Some t -> Some t
      | None -> Api.bad_request "%s is not RFC 3339" name)

let filter_of_request req : Index.filter =
  let q name = nonempty (Api.query req name) in
  let outcome =
    match q "outcome" with
    | None -> None
    | Some o -> (
        match Index.outcome_of_string o with
        | Some o -> Some o
        | None -> Api.bad_request "outcome must be one of allowed, denied, shadow_denied")
  in
  (* Explicit since/until win; range applies only when given (no time filter otherwise,
     so a request id older than a day can still be found). *)
  let since, until =
    match (time_param req "since", time_param req "until", q "range") with
    | None, None, None -> (None, None)
    | s, u, None -> (s, u)
    | s, u, Some _ ->
        let r = Api.range req in
        ((match s with Some _ -> s | None -> Some r.since), u)
  in
  (match (since, until) with
  | Some s, Some u when s > u -> Api.bad_request "since is after until"
  | _ -> ());
  {
    q = q "q";
    caller = q "caller";
    policy = q "policy";
    outcome;
    code = q "code";
    table = q "table";
    fingerprint = q "fingerprint";
    verifier = q "verifier";
    since;
    until;
  }

(* /api/v1/queries pages by offset, not with [Api.page_desc]: index entries have no
   globally unique, monotonic key ([seq] is per verifier), so there is no stable keyset
   cursor. The cursor is a base64url offset into the newest-first result; a page fetched
   while records arrive can repeat entries from the previous page. *)
let offset_cursor req =
  match Api.query req "cursor" with
  | None | Some "" -> 0
  | Some c -> (
      match Haltsql_auth.B64url.decode c with
      | Ok s -> (
          match int_of_string_opt s with
          | Some n when n >= 0 -> n
          | _ -> Api.bad_request "invalid cursor")
      | Error _ -> Api.bad_request "invalid cursor")

let rec drop n l =
  if n <= 0 then l else match l with [] -> [] | _ :: t -> drop (n - 1) t

let queries ctx p (r : Router.req) =
  let _ = Ctx.require p r.http Rbac.Search_queries in
  let f = filter_of_request r.http in
  let off = offset_cursor r.http and lim = Api.limit r.http in
  let index = ctx.Ctx.index in
  let items = drop off (Index.search ~limit:(off + lim) index f) in
  let total = Index.count index f in
  let next =
    if off + lim < total then `String (Api.encode_cursor (off + lim)) else `Null
  in
  Api.json
    (`Assoc
       [
         ("records", `List (List.map Index.entry_to_json items));
         ("next_cursor", next);
         ("total", `Int total);
       ])

(* ---- GET /api/v1/records/{id} ---- *)

let find (ctx : Ctx.t) id =
  match Index.find ctx.index id with
  | Some e -> e
  | None -> Api.not_found "no record %s in the retention window" id

let policy_json (ctx : Ctx.t) (e : Index.entry) : Yojson.Safe.t =
  let r = e.record in
  (* The bundle the record's verifier serves, from the last fleet snapshot. *)
  let bundle =
    match Fleet.snapshot ctx with
    | None -> `Null
    | Some f -> (
        match Api.member "verifiers" f with
        | Some (`List vs) -> (
            match
              List.find_opt (fun v -> Api.member "name" v = Some (`String e.verifier)) vs
            with
            | Some v -> (
                match Api.member "bundle" v with
                | Some (`Assoc _ as b) -> (
                    let s k =
                      match Api.member k b with Some (`String x) -> Some x | _ -> None
                    in
                    match (s "bundle", s "version") with
                    | Some n, Some ver -> `String (n ^ " " ^ ver)
                    | Some n, None -> `String n
                    | None, Some ver -> `String ver
                    | None, None -> `Null)
                | _ -> `Null)
            | None -> `Null)
        | _ -> `Null)
  in
  let loaded = Policy_set.find ctx r.policy in
  `Assoc
    [
      ("name", `String r.policy);
      ("version", Api.opt_string r.policy_version);
      ("bundle", bundle);
      ( "loaded_version",
        match loaded with Some p -> `String p.Haltsql.Policy.version | None -> `Null );
    ]

let record_detail (ctx : Ctx.t) ?(force = false) (e : Index.entry) =
  let reverified = Trail.reverify (Policy_set.get ctx) e in
  let reasons = Trail.reasons ?reverified e.record in
  let policy = Policy_set.find ctx e.record.policy in
  let trail = Trail.compute ?policy ?reverified e.record reasons in
  `Assoc
    [
      ("record", Index.entry_to_json e);
      ("trail", `List (List.map Trail.step_to_json trail));
      ( "trail_source",
        `String (match reverified with Some _ -> "reverified" | None -> "codes") );
      ("reasons", `List (List.map Trail.reason_to_json reasons));
      ("policy", policy_json ctx e);
      ("custody", Chain.custody ctx ~force e);
    ]

let record ctx p (r : Router.req) =
  let _ = Ctx.require p r.http Rbac.Search_queries in
  let e = find ctx (Router.param r "id") in
  Api.json (record_detail ctx e)

(* ---- GET /api/v1/records/{id}/sql ---- *)

let sql ctx p (r : Router.req) =
  let reason = Ctx.require p r.http Rbac.See_raw_sql in
  let id = Router.param r "id" in
  let e = find ctx id in
  match Index.raw_sql e with
  | None -> Api.not_found "record %s has no raw SQL (the producer did not log it)" id
  | Some s ->
      let* () =
        Activity.log ctx p ?reason ~action:"record.view_sql" ~target:id
          ~detail:
            (`Assoc
               [
                 ("verifier", `String e.verifier);
                 ("policy", `String e.record.policy);
                 ("sql_sha256", Api.opt_string e.record.sql_sha256);
               ])
          ()
      in
      Api.json (`Assoc [ ("sql", `String s); ("logged", `Bool true) ])

(* ---- POST /api/v1/records/{id}/verify-chain ---- *)

let verify_chain ctx p (r : Router.req) =
  let* body = Router.json_body r in
  let reason = Ctx.require ~body p r.http Rbac.Search_queries in
  let id = Router.param r "id" in
  let e = find ctx id in
  let result = Chain.get ~force:true ctx.index e.verifier in
  Chain.publish ctx [ result ];
  let custody = Chain.custody ctx e in
  let* () =
    Activity.log ctx p ?reason ~action:"record.verify_chain" ~target:id
      ~detail:
        (`Assoc
           [
             ("verifier", `String e.verifier);
             ( "chain_state",
               Option.value (Api.member "chain_state" custody) ~default:`Null );
           ])
      ()
  in
  Api.json custody

let routes : Router.route list =
  [
    Router.get "/api/v1/queries" queries;
    Router.get "/api/v1/records/:id" record;
    Router.get "/api/v1/records/:id/sql" sql;
    Router.post "/api/v1/records/:id/verify-chain" verify_chain;
  ]

(** Recomputes [Chain.status] for every verifier every 5 minutes (the first check shortly
    after startup, once ingestion has had a chance to run). *)
let start (ctx : Ctx.t) : unit Lwt.t =
  let rec loop delay =
    let* () = Lwt_unix.sleep delay in
    (try Chain.check_all ctx
     with e -> log "error" "chain verification failed: %s" (Printexc.to_string e));
    loop 300.
  in
  loop (float_of_int (max 5 (2 * ctx.config.audit.poll_seconds)))
