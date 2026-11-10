(* Signals: detectors run every 30 s over the index and the fleet snapshot (see
   [Detectors]); this module gives detections stable ids, merges re-detections into the
   same signal, closes signals whose condition cleared 30 minutes ago, keeps human
   workflow state (status, assignee, case) in the Store collection [signals], and serves
   the signals API and caller pause. See docs/console/api.md#signals. *)

open Lwt.Syntax
module R = Haltsql_report.Record

let interval = 30.
let resolve_after = 1800.
let forget_after = 7. *. 86400.
let collection = "signals"

type live = {
  id : string;
  mutable d : Detectors.detection;
  mutable last_active : float;  (** last run in which the condition held *)
  mutable auto_resolved : bool;
}

type state = {
  sigs : (string, live) Hashtbl.t;
  mutable opa_samples : (float * int) list;
      (** (time, fleet OPA error total), newest first *)
}

(* Detector output lives in memory, per console (keyed by state dir so several consoles
   in one process, as in tests, do not share it). *)
let states : (string, state) Hashtbl.t = Hashtbl.create 2

let state (ctx : Ctx.t) =
  let k = Store.dir ctx.store in
  match Hashtbl.find_opt states k with
  | Some s -> s
  | None ->
      let s = { sigs = Hashtbl.create 16; opa_samples = [] } in
      Hashtbl.replace states k s;
      s

let settings (ctx : Ctx.t) = Detectors.settings_of_json ctx.config.signals

(* ---- workflow (Store) ---- *)

let workflow (ctx : Ctx.t) id = Store.get ctx.store collection id

let wstr k w =
  match Option.bind w (Api.member k) with Some (`String s) -> Some s | _ -> None

let human_status ctx id = wstr "status" (workflow ctx id)

let status ctx (l : live) =
  match human_status ctx l.id with
  | Some s -> s
  | None -> if l.auto_resolved then "resolved" else "open"

let to_json ctx (l : live) : Yojson.Safe.t =
  let d = l.d and w = workflow ctx l.id in
  `Assoc
    [
      ("id", `String l.id);
      ("kind", `String d.kind);
      ("severity", `String d.severity);
      ("status", `String (status ctx l));
      ("title", `String d.title);
      ("body", `String d.body);
      ("first_seen", `String (Api.iso8601 d.first_seen));
      ("last_seen", `String (Api.iso8601 d.last_seen));
      ("caller", Api.opt_string d.caller);
      ("policy", Api.opt_string d.policy);
      ("policy_version", Api.opt_string d.policy_version);
      ("verifier", Api.opt_string d.verifier);
      ("assignee", Api.opt_string (wstr "assignee" w));
      ("case_id", Api.opt_string (wstr "case_id" w));
      ( "link",
        `Assoc
          [
            ("kind", `String d.link_kind);
            ("target", `String (if d.link_target = "" then l.id else d.link_target));
          ] );
      ("facts", d.facts);
    ]

(* ---- running the detectors ---- *)

let find_active ctx st (d : Detectors.detection) =
  Hashtbl.fold
    (fun _ l acc ->
      if l.d.kind = d.kind && l.d.subject = d.subject && status ctx l <> "resolved" then
        match acc with Some a when a.last_active >= l.last_active -> acc | _ -> Some l
      else acc)
    st.sigs None

(* After a restart detector output is gone; reuse the id of an unresolved signal whose
   workflow state was persisted, so assignee and case stay attached. *)
let persisted_id ctx (d : Detectors.detection) =
  List.find_map
    (fun (id, w) ->
      let w = Some w in
      if
        wstr "kind" w = Some d.kind
        && wstr "subject" w = Some d.subject
        && wstr "status" w <> Some "resolved"
      then Some id
      else None)
    (Store.list ctx.Ctx.store collection)

let merge (old : Detectors.detection) (d : Detectors.detection) =
  { d with first_seen = Float.min old.first_seen d.first_seen; bucket = old.bucket }

let alert (l : live) =
  {
    Notify.id = l.id;
    severity = l.d.severity;
    title = l.d.title;
    body = l.d.body;
    kind = l.d.kind;
    subject = l.d.subject;
  }

let opa_delta s st ~now total =
  match total with
  | None ->
      st.opa_samples <- [];
      None
  | Some t ->
      st.opa_samples <-
        (now, t)
        :: List.filter (fun (at, _) -> now -. at <= s.Detectors.opa_window) st.opa_samples;
      let oldest = List.fold_left (fun _ x -> Some x) None st.opa_samples in
      Option.map (fun (_, t0) -> max 0 (t - t0)) oldest

(** One detector pass. Returns the signals created in this pass (new high ones are also
    sent to Slack and PagerDuty, best effort, without blocking). *)
let run_once ?(now = Ctx.now ()) (ctx : Ctx.t) =
  let st = state ctx in
  let s = settings ctx in
  let horizon = now -. 86400. -. Detectors.longest_window s in
  let inp =
    {
      Detectors.now;
      recent = Index.between ctx.index ~since:horizon ~until:(now +. 1.);
      index = ctx.index;
      fleet = ctx.fleet;
      chain_status = ctx.chain_status;
      agents = ctx.config.agents;
      policies = ctx.policies;
      opa_error_delta = opa_delta s st ~now (Detectors.opa_error_total ctx.fleet);
    }
  in
  let created = ref [] in
  List.iter
    (fun (d : Detectors.detection) ->
      match find_active ctx st d with
      | Some l ->
          l.d <- merge l.d d;
          l.last_active <- now;
          l.auto_resolved <- false
      | None -> (
          let fresh, id =
            match persisted_id ctx d with
            | Some id -> (false, id)
            | None ->
                (* A human-resolved signal with the same id stays resolved; a recurrence
                   in the same bucket gets a suffixed id. *)
                let base = Detectors.id d in
                let rec pick n =
                  let id = if n = 1 then base else Printf.sprintf "%s_%d" base n in
                  match Hashtbl.find_opt st.sigs id with
                  | Some _ when human_status ctx id = Some "resolved" -> pick (n + 1)
                  | _ -> id
                in
                (true, pick 1)
          in
          match Hashtbl.find_opt st.sigs id with
          | Some l ->
              l.d <- merge l.d d;
              l.last_active <- now;
              l.auto_resolved <- false
          | None ->
              let l = { id; d; last_active = now; auto_resolved = false } in
              Hashtbl.replace st.sigs id l;
              if fresh then created := l :: !created))
    (Detectors.run s inp);
  Hashtbl.iter
    (fun _ l ->
      if l.last_active < now && now -. l.last_active >= resolve_after then
        l.auto_resolved <- true)
    st.sigs;
  (* Forget signals that cleared more than a week ago (their workflow stays in Store). *)
  Hashtbl.filter_map_inplace
    (fun _ l ->
      if l.auto_resolved && now -. l.last_active > forget_after then None else Some l)
    st.sigs;
  let created = List.rev !created in
  List.iter
    (fun l ->
      if l.d.severity = "high" then
        Lwt.async (fun () ->
            Lwt.catch
              (fun () -> Notify.signal ctx.config (alert l))
              (fun _ -> Lwt.return_unit)))
    created;
  created

let start (ctx : Ctx.t) : unit Lwt.t =
  let rec loop () =
    (try ignore (run_once ctx)
     with exn ->
       Notify.log "error" "signals: detector pass failed: %s" (Printexc.to_string exn));
    let* () = Lwt_unix.sleep interval in
    loop ()
  in
  loop ()

(* ---- queries for other modules ---- *)

let all ctx = Hashtbl.fold (fun _ l acc -> l :: acc) (state ctx).sigs []
let find ctx id = Hashtbl.find_opt (state ctx).sigs id

let sorted ls =
  List.sort
    (fun a b ->
      match
        compare
          (Detectors.severity_rank b.d.severity)
          (Detectors.severity_rank a.d.severity)
      with
      | 0 -> compare b.d.last_seen a.d.last_seen
      | c -> c)
    ls

(** Counts of unresolved signals, for Overview. *)
let counts ctx =
  let open_ = List.filter (fun l -> status ctx l <> "resolved") (all ctx) in
  let sev s = List.length (List.filter (fun l -> l.d.severity = s) open_) in
  `Assoc
    [
      ("open", `Int (List.length open_));
      ("high", `Int (sev "high"));
      ("medium", `Int (sev "medium"));
      ("low", `Int (sev "low"));
    ]

let exists ctx id = find ctx id <> None || workflow ctx id <> None
let case_of ctx id = wstr "case_id" (workflow ctx id)

let seed_workflow (l : live option) =
  match l with
  | Some l -> [ ("kind", `String l.d.kind); ("subject", `String l.d.subject) ]
  | None -> []

let set_fields ctx id fields =
  let l = find ctx id in
  Store.update ctx.Ctx.store collection id (fun w ->
      let base = match w with Some (`Assoc a) -> a | _ -> seed_workflow l in
      let base =
        List.fold_left (fun acc (k, v) -> (k, v) :: List.remove_assoc k acc) base fields
      in
      Some (`Assoc base))

(** Links a signal to a case (called by [Cases]). *)
let set_case ctx id case_id =
  let* _ = set_fields ctx id [ ("case_id", `String case_id) ] in
  Lwt.return_unit

(* ---- investigation ---- *)

let stage_of codes =
  let has p = List.exists (fun c -> String.starts_with ~prefix:p c) codes in
  if codes = [] then `Null
  else
    `String
      (if
         has "E_PARSE" || has "E_EMPTY" || has "E_MULTI_STATEMENT"
         || List.mem "E_LIMIT" codes
       then "parse"
       else if has "E_TENANT_" || has "E_CONTEXT_MISSING" || has "E_PARAM_UNBOUND" then
         "tenancy"
       else if
         has "E_TABLE_" || has "E_COLUMN_" || has "E_STATEMENT_KIND" || has "E_WRITE"
       then "tables"
       else if has "E_LIMIT_" then "limit"
       else if has "E_FUNCTION_" || has "E_OPERATOR_" || has "E_CAST_" then "functions"
       else if has "E_EXTERNAL_POLICY" then "opa"
       else "verdict")

(** A normalized shape of a statement: string and numeric literals become [?], comments
    are dropped and whitespace collapsed. *)
let shape_of_sql sql =
  let n = String.length sql in
  let b = Buffer.create n in
  let ident c =
    match c with 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' | '$' -> true | _ -> false
  in
  let last () = if Buffer.length b = 0 then ' ' else Buffer.nth b (Buffer.length b - 1) in
  let space () = if last () <> ' ' then Buffer.add_char b ' ' in
  let rec go i =
    if i >= n then ()
    else
      let c = sql.[i] in
      if c = '\'' then (
        let rec close j =
          if j >= n then n
          else if sql.[j] = '\'' then
            if j + 1 < n && sql.[j + 1] = '\'' then close (j + 2) else j
          else close (j + 1)
        in
        Buffer.add_char b '?';
        go (close (i + 1) + 1))
      else if c = '"' then (
        let j =
          match String.index_from_opt sql (i + 1) '"' with Some j -> j | None -> n - 1
        in
        Buffer.add_string b (String.sub sql i (j - i + 1));
        go (j + 1))
      else if c = '-' && i + 1 < n && sql.[i + 1] = '-' then (
        let j = match String.index_from_opt sql i '\n' with Some j -> j | None -> n in
        space ();
        go j)
      else if c = '/' && i + 1 < n && sql.[i + 1] = '*' then (
        let rec close j =
          if j + 1 >= n then n
          else if sql.[j] = '*' && sql.[j + 1] = '/' then j + 2
          else close (j + 1)
        in
        space ();
        go (close (i + 2)))
      else if c >= '0' && c <= '9' && not (ident (last ())) then (
        let rec num j =
          if j < n && match sql.[j] with '0' .. '9' | '.' -> true | _ -> false then
            num (j + 1)
          else j
        in
        Buffer.add_char b '?';
        go (num i))
      else if c = ' ' || c = '\n' || c = '\t' || c = '\r' then (
        space ();
        go (i + 1))
      else (
        Buffer.add_char b c;
        go (i + 1))
  in
  go 0;
  String.trim (Buffer.contents b)

let take n l = List.filteri (fun i _ -> i < n) l

let timeline entries ~since ~until =
  let w = 60. in
  let start = Detectors.floor_to w since in
  let nb = max 1 (int_of_float (Float.ceil ((until -. start) /. w))) in
  let a = Array.make nb (0, 0, 0) in
  List.iter
    (fun (e : Index.entry) ->
      let i = int_of_float ((e.ts -. start) /. w) in
      if i >= 0 && i < nb then
        let x, y, z = a.(i) in
        a.(i) <-
          (match e.record.outcome with
          | R.Allowed -> (x + 1, y, z)
          | R.Denied -> (x, y + 1, z)
          | R.Shadow_denied -> (x, y, z + 1)))
    entries;
  `Assoc
    [
      ("bucket_seconds", `Int 60);
      ( "series",
        `List
          (Array.to_list
             (Array.mapi
                (fun i (x, y, z) ->
                  `Assoc
                    [
                      ("start", `String (Api.iso8601 (start +. (float_of_int i *. w))));
                      ("allowed", `Int x);
                      ("denied", `Int y);
                      ("shadow_denied", `Int z);
                    ])
                a)) );
    ]

let shapes entries =
  Detectors.group_by (fun (e : Index.entry) -> R.fingerprint_key e.record) entries
  |> List.map (fun (key, es) ->
      let codes =
        List.fold_left
          (fun acc (e : Index.entry) ->
            acc @ List.filter (fun c -> not (List.mem c acc)) e.record.codes)
          [] es
      in
      let example =
        match List.find_map Index.raw_sql es with
        | Some sql -> shape_of_sql sql
        | None -> key
      in
      ( List.length es,
        `Assoc
          [
            ("fingerprint", `String key);
            ("example_shape", `String example);
            ("count", `Int (List.length es));
            ("stopped_at", stage_of codes);
            ("codes", Api.strings codes);
            ( "request_ids",
              Api.strings (take 20 (List.map (fun (e : Index.entry) -> e.request_id) es))
            );
          ] ))
  |> List.stable_sort (fun (a, _) (b, _) -> compare b a)
  |> List.map snd

let investigation (ctx : Ctx.t) (l : live) =
  let d = l.d in
  let in_scope (e : Index.entry) =
    match (d.caller, d.policy, d.verifier) with
    | Some c, _, _ -> e.record.caller = c
    | None, Some p, _ -> e.record.policy = p
    | None, None, Some v -> e.verifier = v
    | None, None, None -> true
  in
  let around =
    Index.between ctx.index ~since:(d.first_seen -. 900.) ~until:(d.last_seen +. 900.)
    |> List.filter in_scope
  in
  let relevant =
    List.filter
      (fun (e : Index.entry) ->
        e.ts >= d.first_seen && e.ts <= d.last_seen && Detectors.relevant d.kind e)
      around
  in
  let caller =
    match d.caller with
    | None -> `Null
    | Some c ->
        let usual =
          Index.between ctx.index ~since:(d.first_seen -. 86400.) ~until:d.first_seen
          |> List.filter (fun (e : Index.entry) -> e.record.caller = c)
        in
        let n = List.length usual in
        let denied = List.length (List.filter Detectors.is_denied usual) in
        let policy =
          match
            Detectors.most_common
              (List.map
                 (fun (e : Index.entry) -> e.record.policy)
                 (if usual = [] then around else usual))
          with
          | Some p -> Some p
          | None -> d.policy
        in
        `Assoc
          [
            ("id", `String c);
            ( "agent",
              Api.opt_string
                (Option.map
                   (fun (a : Console_config.agent) -> a.a_name)
                   (Detectors.agent_for ctx.config.agents c)) );
            ("policy", Api.opt_string policy);
            ("usual_per_minute", `Float (float_of_int n /. 1440.));
            ( "usual_deny_rate",
              `Float (if n = 0 then 0. else float_of_int denied /. float_of_int n) );
          ]
  in
  `Assoc
    [
      ("signal", to_json ctx l);
      ( "timeline",
        timeline around ~since:(d.first_seen -. 900.) ~until:(d.last_seen +. 900.) );
      ("shapes", `List (shapes relevant));
      ("caller", caller);
      ( "request_ids",
        Api.strings (take 200 (List.map (fun (e : Index.entry) -> e.request_id) relevant))
      );
    ]

(* ---- routes ---- *)

let statuses = [ "open"; "investigating"; "contained"; "resolved"; "acknowledged" ]

let list_signals ctx _p (r : Router.req) =
  let want = Option.value (Router.query r "status") ~default:"open" in
  if want <> "open" && want <> "all" then Api.bad_request "status must be open or all";
  let ls = all ctx in
  let ls =
    if want = "all" then ls else List.filter (fun l -> status ctx l <> "resolved") ls
  in
  Api.json (`Assoc [ ("signals", `List (List.map (to_json ctx) (sorted ls))) ])

let get_signal ctx p (r : Router.req) =
  let id = Router.param r "id" in
  match find ctx id with
  | None -> Api.not_found "no signal %s" id
  | Some l ->
      let* () = Activity.log ctx p ~action:"signal.view" ~target:id () in
      Api.json (investigation ctx l)

let update_signal ctx p (r : Router.req) =
  let id = Router.param r "id" in
  let* body = Router.json_body r in
  let _ = Ctx.require ~body p r.http Rbac.Write_cases in
  if not (exists ctx id) then Api.not_found "no signal %s" id;
  let status = Api.str_field "status" body in
  let assignee =
    match Api.member "assignee" body with
    | None -> None
    | Some `Null -> Some `Null
    | Some (`String s) when String.trim s <> "" -> Some (`String s)
    | Some _ -> Api.bad_request "field assignee must be a non-empty string or null"
  in
  (match status with
  | Some s when not (List.mem s statuses) ->
      Api.bad_request "status must be one of %s" (String.concat ", " statuses)
  | Some "acknowledged" -> (
      match find ctx id with
      | Some l when l.d.severity <> "low" ->
          Api.bad_request "acknowledged is only for low signals"
      | _ -> ())
  | _ -> ());
  if status = None && assignee = None then Api.bad_request "send status or assignee";
  let fields =
    (match status with Some s -> [ ("status", `String s) ] | None -> [])
    @ (match assignee with Some a -> [ ("assignee", a) ] | None -> [])
    @ [
        ("updated", `String (Api.iso8601 (Ctx.now ()))); ("updated_by", `String p.Ctx.id);
      ]
  in
  let* _ = set_fields ctx id fields in
  let* () =
    Activity.log ctx p ~action:"signal.update" ~target:id
      ~detail:
        (`Assoc
           ((match status with Some s -> [ ("status", `String s) ] | None -> [])
           @ match assignee with Some a -> [ ("assignee", a) ] | None -> []))
      ()
  in
  match find ctx id with
  | Some l -> Api.json (to_json ctx l)
  | None ->
      Api.json
        (`Assoc
           (("id", `String id)
           :: (match workflow ctx id with Some (`Assoc a) -> a | _ -> [])))

let pause_caller ctx p (r : Router.req) =
  let caller = Router.param r "caller" in
  let* body = Router.json_body r in
  let reason = Ctx.require ~body p r.http Rbac.Pause_caller in
  let minutes = Api.int_field "minutes" body in
  (match minutes with
  | Some m when m < 1 || m > 10080 -> Api.bad_request "minutes must be in 1..10080"
  | _ -> ());
  let* () =
    Activity.log ctx p ?reason ~action:"caller.pause_requested" ~target:caller
      ~detail:
        (`Assoc
           [ ("minutes", Api.opt_int minutes); ("outcome", `String "not_implemented") ])
      ()
  in
  Api.not_implemented
    "verifiers do not yet consume a signed deny list, so the console cannot pause %s; \
     revoke the caller's token or identity at the identity provider instead"
    caller

let routes : Router.route list =
  [
    Router.get "/api/v1/signals" list_signals;
    Router.get "/api/v1/signals/:id" get_signal;
    Router.post "/api/v1/signals/:id" update_signal;
    Router.post "/api/v1/callers/:caller/pause" pause_caller;
  ]
