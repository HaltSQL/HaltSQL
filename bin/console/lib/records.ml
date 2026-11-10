(* Queries search, one record with its decision trail, raw SQL, chain of custody.
   Owner: PR console/02-records. See docs/console/api.md "Queries and records". *)

open Lwt.Syntax

let log level fmt = Ingest.log_component "records" level fmt
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

(* /api/v1/queries pages by keyset: the cursor is the [(ts, request_id)] of the last
   record returned, and the next page is what sorts after it in the newest-first order
   (equal timestamps: most recently added first). Records that arrive between pages sort
   before the cursor, so they never shift a later page. Each page walks only the minute
   buckets from the cursor back until it has [limit + 1] matches; [total] is counted on
   the first page only (later pages return [null]), as counting a filtered search walks
   the whole window. *)
let encode_cursor (e : Index.entry) =
  Haltsql_auth.B64url.encode (Printf.sprintf "%h|%s" e.ts e.request_id)

let decode_cursor req =
  match Api.query req "cursor" with
  | None | Some "" -> None
  | Some c -> (
      let bad () = Api.bad_request "invalid cursor" in
      match Haltsql_auth.B64url.decode c with
      | Error _ -> bad ()
      | Ok s -> (
          match String.index_opt s '|' with
          | None -> bad ()
          | Some i -> (
              match float_of_string_opt (String.sub s 0 i) with
              | Some ts when Float.is_finite ts ->
                  Some (ts, String.sub s (i + 1) (String.length s - i - 1))
              | _ -> bad ())))

(* The page after [(ts, id)]: entries with [ts' <= ts], minus those that sort before or
   at the cursor (the leading entries with [ts' = ts], up to [id]). If the cursor's
   record has left the index, every entry at [ts] is treated as already returned. *)
let page_after index (f : Index.filter) ~ts ~id ~lim =
  let until =
    match f.until with Some u -> Float.min u (Float.succ ts) | None -> Float.succ ts
  in
  let f = { f with until = Some until } in
  let rec attempt n =
    let res = Index.search ~limit:n index f in
    let rec skip = function
      | (e : Index.entry) :: rest when e.ts = ts ->
          if e.request_id = id then Some rest else skip rest
      | _ -> None
    in
    let rec drop_ts = function
      | (e : Index.entry) :: rest when e.ts = ts -> drop_ts rest
      | l -> l
    in
    match skip res with
    | Some rest -> rest
    | None ->
        if List.length res = n && List.for_all (fun (e : Index.entry) -> e.ts = ts) res
        then attempt (2 * n)
        else drop_ts res
  in
  let rec take k = function x :: r when k > 0 -> x :: take (k - 1) r | _ -> [] in
  take (lim + 1) (attempt (lim + 64))

let queries ctx p (r : Router.req) =
  let _ = Ctx.require p r.http Rbac.Search_queries in
  let f = filter_of_request r.http in
  let lim = Api.limit r.http in
  let index = ctx.Ctx.index in
  let cursor = decode_cursor r.http in
  let found =
    match cursor with
    | None -> Index.search ~limit:(lim + 1) index f
    | Some (ts, id) -> page_after index f ~ts ~id ~lim
  in
  let items = List.filteri (fun i _ -> i < lim) found in
  let next =
    match (List.length found > lim, List.rev items) with
    | true, last :: _ -> `String (encode_cursor last)
    | _ -> `Null
  in
  let total = match cursor with None -> `Int (Index.count index f) | Some _ -> `Null in
  Api.json
    (`Assoc
       [
         ("records", `List (List.map Index.entry_to_json items));
         ("next_cursor", next);
         ("total", total);
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

(* Re-verification names the objects behind each code, and its messages can quote SQL
   literals (e.g. the other tenant's value in E_TENANT_MISMATCH). They are returned only
   with [~full:true] (the caller checked [see_raw_sql] and logged the view); otherwise each
   reason keeps its code and rule with the generic description. *)
let record_detail (ctx : Ctx.t) ?(full = false) (e : Index.entry) =
  let reverified = Trail.reverify (Policy_set.get ctx) e in
  let reasons = Trail.reasons ?reverified ~redact:(not full) e.record in
  let policy = Policy_set.find ctx e.record.policy in
  let trail = Trail.compute ?policy ?reverified e.record reasons in
  `Assoc
    [
      ("record", Index.entry_to_json e);
      ("trail", `List (List.map Trail.step_to_json trail));
      ( "trail_source",
        `String (match reverified with Some _ -> "reverified" | None -> "codes") );
      ( "reasons_detail",
        `String
          (match reverified with
          | None -> "codes"
          | Some _ -> if full then "full" else "redacted") );
      ("reasons", `List (List.map Trail.reason_to_json reasons));
      ("policy", policy_json ctx e);
      ("custody", Chain.custody ctx e);
    ]

let record ctx p (r : Router.req) =
  let _ = Ctx.require p r.http Rbac.Search_queries in
  let id = Router.param r "id" in
  match Api.query r.http "details" with
  | None | Some "" -> Api.json (record_detail ctx (find ctx id))
  | Some "full" ->
      let reason = Ctx.require p r.http Rbac.See_raw_sql in
      let e = find ctx id in
      let* () =
        Activity.log ctx p ?reason ~action:"record.view_details" ~target:id
          ~detail:
            (`Assoc
               [ ("verifier", `String e.verifier); ("policy", `String e.record.policy) ])
          ()
      in
      Api.json (record_detail ctx ~full:true e)
  | Some _ -> Api.bad_request "details must be full"

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
  let* result = Chain.reverify ctx e.verifier in
  Chain.publish ctx [ result ];
  let custody = Chain.custody_json ctx result e in
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

(** Refreshes [Chain.status] for every verifier every [audit.chain_check_seconds] (the
    first check shortly after startup, once ingestion has had a chance to run). The check
    is incremental, so it costs only the records added since the last one. *)
let start (ctx : Ctx.t) : unit Lwt.t =
  let rec loop delay =
    let* () = Lwt_unix.sleep delay in
    (try Chain.check_all ctx
     with e -> log "error" "chain verification failed: %s" (Printexc.to_string e));
    loop (float_of_int (max 1 ctx.config.audit.chain_check_seconds))
  in
  loop (float_of_int (max 5 (2 * ctx.config.audit.poll_seconds)))
