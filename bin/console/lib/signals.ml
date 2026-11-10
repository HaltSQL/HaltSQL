(* Signals: detectors run every [signals.interval_seconds] (default 30 s) over the index
   and the fleet snapshot (see [Detectors]); this module gives detections stable ids,
   merges re-detections into the same signal, closes signals whose condition cleared
   [resolve_after] ago, keeps human workflow state (status, assignee, case) plus a
   snapshot of the signal in the Store collection [signals], and serves the signals API
   and caller pause. See docs/console/api.md#signals. *)

open Lwt.Syntax
module R = Haltsql_report.Record
module D = Detectors

let collection = "signals"

type live = {
  id : string;
  mutable d : D.detection;
  mutable last_active : float;  (** last run in which the condition held *)
  mutable auto_resolved : bool;
}

type state = {
  sigs : (string, live) Hashtbl.t;
  mutable opa_samples : (float * int) list;
      (** (time, fleet OPA error total), newest first *)
  caller_first_seen : (string, float) Hashtbl.t;
      (** earliest record per caller (for new_caller), updated incrementally *)
  mutable first_seen_scan : (float * float option) option;
      (** when the index was last scanned in full, and its oldest record then *)
  reverify_cache : (string, (string * string list) list) Hashtbl.t;
  mutable reverify_policies : (string * Haltsql.Policy.t) list;
      (** the policy set the cache was filled with (compared physically) *)
  mutable writes : unit Lwt.t list;  (** workflow writes started by detector passes *)
}

(* Detector output lives in memory, per console, in the Ctx registry under a private
   key. *)
let key : state Ctx.Key.t = Ctx.Key.create "signals"

let state (ctx : Ctx.t) =
  match Ctx.get ctx key with
  | Some s -> s
  | None ->
      let s =
        {
          sigs = Hashtbl.create 16;
          opa_samples = [];
          caller_first_seen = Hashtbl.create 64;
          first_seen_scan = None;
          reverify_cache = Hashtbl.create 64;
          reverify_policies = [];
          writes = [];
        }
      in
      Ctx.set ctx key s;
      s

let settings (ctx : Ctx.t) = D.settings_of_json ctx.config.signals

(* ---- snapshots ---- *)

let detection_to_json (d : D.detection) : Yojson.Safe.t =
  let opt = Api.opt_string in
  `Assoc
    [
      ("kind", `String (D.kind_to_string d.kind));
      ("subject", `String d.subject);
      ("slug", `String d.slug);
      ("bucket", `Float d.bucket);
      ("severity", `String (D.severity_to_string d.severity));
      ("title", `String d.title);
      ("body", `String d.body);
      ("first_seen", `Float d.first_seen);
      ("last_seen", `Float d.last_seen);
      ("caller", opt d.caller);
      ("policy", opt d.policy);
      ("policy_version", opt d.policy_version);
      ("verifier", opt d.verifier);
      ("link_kind", `String d.link_kind);
      ("link_target", `String d.link_target);
      ("facts", d.facts);
    ]

let detection_of_json (j : Yojson.Safe.t) : D.detection option =
  let s k = match Api.member k j with Some (`String v) -> Some v | _ -> None in
  let f k = Option.bind (Api.member k j) D.num in
  match
    ( Option.bind (s "kind") D.kind_of_string,
      Option.bind (s "severity") D.severity_of_string,
      s "subject",
      f "first_seen",
      f "last_seen" )
  with
  | Some kind, Some severity, Some subject, Some first_seen, Some last_seen ->
      let str k = Option.value (s k) ~default:"" in
      Some
        {
          D.kind;
          subject;
          slug = str "slug";
          bucket = Option.value (f "bucket") ~default:first_seen;
          severity;
          title = str "title";
          body = str "body";
          first_seen;
          last_seen;
          caller = s "caller";
          policy = s "policy";
          policy_version = s "policy_version";
          verifier = s "verifier";
          link_kind = str "link_kind";
          link_target = str "link_target";
          facts = Option.value (Api.member "facts" j) ~default:(`Assoc []);
        }
  | _ -> None

(* ---- workflow (Store) ---- *)

let workflow (ctx : Ctx.t) id = Store.get ctx.store collection id

let wstr k w =
  match Option.bind w (Api.member k) with Some (`String s) -> Some s | _ -> None

let human_status ctx id = wstr "status" (workflow ctx id)

(** A signal known only from its persisted snapshot (after a restart, or once it left
    memory): resolved when its doc says it closed. *)
let live_of_doc id (w : Yojson.Safe.t) =
  match Option.bind (Api.member "signal" w) detection_of_json with
  | None -> None
  | Some d ->
      Some
        {
          id;
          d;
          last_active = d.last_seen;
          auto_resolved = wstr "closed_at" (Some w) <> None;
        }

let status ctx (l : live) =
  match human_status ctx l.id with
  | Some s -> s
  | None -> if l.auto_resolved then "resolved" else "open"

let to_json ctx (l : live) : Yojson.Safe.t =
  let d = l.d and w = workflow ctx l.id in
  `Assoc
    [
      ("id", `String l.id);
      ("kind", `String (D.kind_to_string d.kind));
      ("severity", `String (D.severity_to_string d.severity));
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

let set_assoc fields a =
  List.fold_left (fun acc (k, v) -> (k, v) :: List.remove_assoc k acc) a fields

(* Store writes started by a detector pass: tracked so [flush] (and the background loop)
   can wait for them; a failure is logged, never raised into the pass. *)
let track st name p =
  let p =
    Lwt.catch
      (fun () -> p)
      (fun exn ->
        Notify.log "error" "signals: %s failed: %s" name (Printexc.to_string exn);
        Lwt.return_unit)
  in
  st.writes <- p :: List.filter (fun w -> Lwt.state w = Lwt.Sleep) st.writes

(** Waits for the workflow writes started by earlier detector passes. *)
let flush ctx =
  let st = state ctx in
  let ws = st.writes in
  st.writes <- [];
  Lwt.join ws

(* Updates an existing workflow doc (never creates one). *)
let update_doc ctx id f =
  Store.update ctx.Ctx.store collection id (function
    | Some (`Assoc a) -> Some (`Assoc (f a))
    | other -> other)

(* ---- running the detectors ---- *)

let find_active ctx st (d : D.detection) =
  Hashtbl.fold
    (fun _ l acc ->
      if l.d.kind = d.kind && l.d.subject = d.subject && status ctx l <> "resolved" then
        match acc with Some a when a.last_active >= l.last_active -> acc | _ -> Some l
      else acc)
    st.sigs None

let case_resolved (ctx : Ctx.t) w =
  match wstr "case_id" w with
  | None -> false
  | Some c -> (
      match Store.get ctx.store "cases" c with
      | Some doc -> Api.member "status" doc = Some (`String "resolved")
      | None -> false)

(* Workflow docs with no live entry, grouped by (kind, subject), in insertion order: one
   fold per pass instead of one per detection. *)
let detached_docs ctx st =
  let tbl = Hashtbl.create 16 in
  let order = ref [] in
  Store.iter ctx.Ctx.store collection (fun id w ->
      if not (Hashtbl.mem st.sigs id) then (
        order := (id, w) :: !order;
        match (wstr "kind" (Some w), wstr "subject" (Some w)) with
        | Some k, Some s ->
            Hashtbl.replace tbl (k, s)
              ((id, w) :: Option.value (Hashtbl.find_opt tbl (k, s)) ~default:[])
        | _ -> ()));
  Hashtbl.filter_map_inplace (fun _ l -> Some (List.rev l)) tbl;
  (tbl, List.rev !order)

(* After a restart detector output is gone: reuse the id of a signal whose workflow was
   persisted and is still open, so assignee and case stay attached. Mirrors [find_active]:
   a doc is open when a person set a status other than resolved, or set none and the
   signal never auto-resolved ([closed_at]); a doc whose linked case is resolved is
   closed too. *)
let reattachable ctx w =
  let w = Some w in
  (match wstr "status" w with
    | Some s -> s <> "resolved"
    | None -> wstr "closed_at" w = None)
  && not (case_resolved ctx w)

let merge (old : D.detection) (d : D.detection) =
  { d with first_seen = Float.min old.first_seen d.first_seen; bucket = old.bucket }

let alert (l : live) =
  {
    Notify.id = l.id;
    severity = D.severity_to_string l.d.severity;
    title = l.d.title;
    body = l.d.body;
    kind = D.kind_to_string l.d.kind;
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
        :: List.filter (fun (at, _) -> now -. at <= s.D.opa_window) st.opa_samples;
      let oldest = List.fold_left (fun _ x -> Some x) None st.opa_samples in
      Option.map (fun (_, t0) -> max 0 (t - t0)) oldest

(* The index is scanned in full for first-seen times only on the first pass, hourly, or
   when older records appeared (a warm start); otherwise the pass's recent records keep
   the table current. *)
let first_seen_rescan_every = 3600.

let refresh_first_seen (ctx : Ctx.t) st ~now recent =
  let oldest = Index.oldest ctx.index in
  let full =
    match st.first_seen_scan with
    | None -> true
    | Some (at, o) -> (
        now -. at >= first_seen_rescan_every
        || now < at
        ||
        match (oldest, o) with
        | Some x, Some y -> x < y
        | Some _, None -> true
        | _ -> false)
  in
  if full then (
    Hashtbl.reset st.caller_first_seen;
    Index.iter ctx.index (fun e -> D.track_first_seen st.caller_first_seen [ e ]);
    st.first_seen_scan <- Some (now, oldest))
  else D.track_first_seen st.caller_first_seen recent

let max_reverify_cache = 100_000

let prepare ~now (ctx : Ctx.t) =
  let st = state ctx in
  let s = settings ctx in
  let horizon = now -. 86400. -. D.longest_window s in
  let recent = Index.between ctx.index ~since:horizon ~until:(now +. 1.) in
  refresh_first_seen ctx st ~now recent;
  let policies = Policy_set.get ctx in
  if
    policies != st.reverify_policies
    || Hashtbl.length st.reverify_cache > max_reverify_cache
  then (
    Hashtbl.reset st.reverify_cache;
    st.reverify_policies <- policies);
  let fleet = Fleet.snapshot ctx in
  let inp =
    D.make_input ~caller_first_seen:st.caller_first_seen ~reverify_cache:st.reverify_cache
      ~now ~recent ~index:ctx.index ~fleet ~chain_status:(Chain.status ctx)
      ~agents:ctx.config.agents ~policies
      ~opa_error_delta:(opa_delta s st ~now (D.opa_error_total fleet))
      ()
  in
  (st, s, inp)

let notify_async (ctx : Ctx.t) s f =
  Lwt.async (fun () ->
      Lwt.catch
        (fun () -> f ~timeout:s.D.notify_timeout ctx.config)
        (fun _ -> Lwt.return_unit))

(* A fresh id: the detection's id, suffixed when that id is already taken by a live
   signal or a persisted workflow (a recurrence after the first episode resolved). *)
let fresh_id ctx st d =
  let base = D.id d in
  let rec pick n =
    let id = if n = 1 then base else Printf.sprintf "%s_%d" base n in
    if Hashtbl.mem st.sigs id || workflow ctx id <> None then pick (n + 1) else id
  in
  pick 1

(* Applies one pass's detections. Returns the signals created (new episodes; a signal
   re-attached to its persisted workflow after a restart is not new). *)
let apply (ctx : Ctx.t) st s ~now detections =
  let docs, detached = detached_docs ctx st in
  let created = ref [] in
  let close_doc (l : live) =
    if workflow ctx l.id <> None then
      track st "closing a signal"
        (let* _ =
           update_doc ctx l.id
             (set_assoc
                [
                  ("closed_at", `String (Api.iso8601 now));
                  ("signal", detection_to_json l.d);
                ])
         in
         Lwt.return_unit)
  in
  List.iter
    (fun (d : D.detection) ->
      match find_active ctx st d with
      | Some l ->
          if l.auto_resolved then (
            (* a person kept it open (status set): it absorbs the recurrence *)
            l.auto_resolved <- false;
            if workflow ctx l.id <> None then
              track st "reopening a signal"
                (let* _ = update_doc ctx l.id (List.remove_assoc "closed_at") in
                 Lwt.return_unit));
          l.d <- merge l.d d;
          l.last_active <- now
      | None -> (
          let key = (D.kind_to_string d.kind, d.subject) in
          let candidates = Option.value (Hashtbl.find_opt docs key) ~default:[] in
          match List.find_opt (fun (_, w) -> reattachable ctx w) candidates with
          | Some (id, w) ->
              Hashtbl.replace docs key (List.filter (fun (i, _) -> i <> id) candidates);
              let d =
                match Option.bind (Api.member "signal" w) detection_of_json with
                | Some old -> merge old d
                | None -> d
              in
              Hashtbl.replace st.sigs id
                { id; d; last_active = now; auto_resolved = false }
          | None ->
              let id = fresh_id ctx st d in
              let l = { id; d; last_active = now; auto_resolved = false } in
              Hashtbl.replace st.sigs id l;
              created := l :: !created))
    detections;
  let resolved = ref [] in
  Hashtbl.iter
    (fun _ l ->
      if
        (not l.auto_resolved) && l.last_active < now
        && now -. l.last_active >= s.D.resolve_after
      then (
        l.auto_resolved <- true;
        resolved := l :: !resolved))
    st.sigs;
  List.iter
    (fun l ->
      close_doc l;
      if l.d.severity = D.High && human_status ctx l.id = None then
        notify_async ctx s (fun ~timeout cfg -> Notify.resolve ~timeout cfg (alert l)))
    !resolved;
  (* Persisted workflows nobody re-detected (e.g. the condition cleared while the console
     was down) close once [resolve_after] has passed since their last sighting and since
     this console started. *)
  List.iter
    (fun (id, w) ->
      if (not (Hashtbl.mem st.sigs id)) && wstr "closed_at" (Some w) = None then
        let last_seen =
          match Option.bind (Api.member "signal" w) detection_of_json with
          | Some d -> d.last_seen
          | None -> neg_infinity
        in
        if now -. Float.max last_seen ctx.started >= s.D.resolve_after then
          track st "closing a signal"
            (let* _ =
               update_doc ctx id (set_assoc [ ("closed_at", `String (Api.iso8601 now)) ])
             in
             Lwt.return_unit))
    detached;
  (* Forget signals that cleared long ago (their workflow and snapshot stay in Store). *)
  Hashtbl.filter_map_inplace
    (fun _ l ->
      if l.auto_resolved && now -. l.last_active > s.D.forget_after then None else Some l)
    st.sigs;
  let created = List.rev !created in
  List.iter
    (fun l ->
      if l.d.severity = D.High then
        notify_async ctx s (fun ~timeout cfg -> Notify.signal ~timeout cfg (alert l)))
    created;
  created

(** One detector pass, synchronously (tests; the background loop uses {!run_once_lwt}).
    Returns the signals created in this pass (new high ones are also sent to Slack and
    PagerDuty, best effort, without blocking). Workflow writes it starts are awaited by
    {!flush}. *)
let run_once ?(now = Ctx.now ()) (ctx : Ctx.t) =
  let st, s, inp = prepare ~now ctx in
  apply ctx st s ~now (D.run s inp)

(** {!run_once}, yielding to the Lwt loop between detectors, then waiting for the pass's
    workflow writes. *)
let run_once_lwt ?(now = Ctx.now ()) (ctx : Ctx.t) =
  let st, s, inp = prepare ~now ctx in
  let* ds = D.run_lwt s inp in
  let created = apply ctx st s ~now ds in
  let+ () = flush ctx in
  created

let start (ctx : Ctx.t) : unit Lwt.t =
  let rec loop () =
    let* () =
      Lwt.catch
        (fun () ->
          let+ _ = run_once_lwt ctx in
          ())
        (fun exn ->
          Notify.log "error" "signals: detector pass failed: %s" (Printexc.to_string exn);
          Lwt.return_unit)
    in
    let* () = Lwt_unix.sleep (settings ctx).interval in
    loop ()
  in
  loop ()

(* ---- queries for other modules ---- *)

(** Signals in memory (detector output). *)
let all ctx = Hashtbl.fold (fun _ l acc -> l :: acc) (state ctx).sigs []

(** A signal by id: in memory, else rebuilt from its persisted snapshot. *)
let find ctx id =
  match Hashtbl.find_opt (state ctx).sigs id with
  | Some l -> Some l
  | None -> Option.bind (workflow ctx id) (live_of_doc id)

(** Every signal: in memory plus those known only from their persisted snapshot. *)
let listing (ctx : Ctx.t) =
  let st = state ctx in
  Store.fold ctx.store collection
    (fun id w acc ->
      if Hashtbl.mem st.sigs id then acc
      else match live_of_doc id w with Some l -> l :: acc | None -> acc)
    (all ctx)

let sorted ls =
  List.sort
    (fun a b ->
      match compare (D.severity_rank b.d.severity) (D.severity_rank a.d.severity) with
      | 0 -> (
          match compare b.d.last_seen a.d.last_seen with 0 -> compare a.id b.id | c -> c)
      | c -> c)
    ls

(** Counts of unresolved signals, for Overview. *)
let counts ctx =
  let open_ = List.filter (fun l -> status ctx l <> "resolved") (listing ctx) in
  let sev s = List.length (List.filter (fun l -> l.d.severity = s) open_) in
  `Assoc
    [
      ("open", `Int (List.length open_));
      ("high", `Int (sev D.High));
      ("medium", `Int (sev D.Medium));
      ("low", `Int (sev D.Low));
    ]

let exists ctx id = find ctx id <> None || workflow ctx id <> None
let case_of ctx id = wstr "case_id" (workflow ctx id)

let set_fields ctx id fields =
  let l = find ctx id in
  let snapshot =
    match Hashtbl.find_opt (state ctx).sigs id with
    | Some l -> [ ("signal", detection_to_json l.d) ]
    | None -> []
  in
  Store.update ctx.Ctx.store collection id (fun w ->
      let base =
        match (w, l) with
        | Some (`Assoc a), _ -> a
        | _, Some l ->
            [
              ("kind", `String (D.kind_to_string l.d.kind));
              ("subject", `String l.d.subject);
            ]
        | _ -> []
      in
      Some (`Assoc (set_assoc (snapshot @ fields) base)))

(** Links a signal to a case (called by [Cases]). *)
let set_case ctx id case_id =
  let* _ = set_fields ctx id [ ("case_id", `String case_id) ] in
  Lwt.return_unit

(** Raises 403 before the body is read when no role of [p] has [perm] at all (a "with a
    reason" grant still needs the body, for its reason). *)
let precheck (p : Ctx.principal) (req : Cohttp.Request.t) perm =
  if Rbac.grant_union p.roles perm = Rbac.No then ignore (Ctx.require p req perm)

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

(* ---- statement shapes ---- *)

type token = Text of string | Lit | Space

let is_ident_start c =
  match c with 'a' .. 'z' | 'A' .. 'Z' | '_' | '\128' .. '\255' -> true | _ -> false

let is_ident_char c =
  is_ident_start c || match c with '0' .. '9' | '$' -> true | _ -> false

exception Unshapeable

(* A lexer for the PostgreSQL literal and comment syntax (scan.l): standard '...' strings
   ('' escapes), E'...' (backslash escapes), U&'...', B'...', X'...', N'...',
   $tag$...$tag$ dollar quotes, numbers (including 0x.., 1e-3, 1_000), -- and nested
   /* */ comments, and "..." identifiers. Anything it cannot classify raises
   [Unshapeable], so nothing is copied that might be part of a literal. *)
let lex sql =
  let n = String.length sql in
  let toks = ref [] in
  let push t = toks := t :: !toks in
  let prev_ident i = i > 0 && is_ident_char sql.[i - 1] in
  (* end (exclusive) of a quoted string whose opening quote is at [i] *)
  let close_quoted ~backslash i =
    let rec go j =
      if j >= n then raise Unshapeable
      else if backslash && sql.[j] = '\\' then go (j + 2)
      else if sql.[j] = '\'' then
        if j + 1 < n && sql.[j + 1] = '\'' then go (j + 2) else j + 1
      else go (j + 1)
    in
    go (i + 1)
  in
  let starts_with_at i p =
    let m = String.length p in
    i + m <= n && String.lowercase_ascii (String.sub sql i m) = p
  in
  let rec go i =
    if i >= n then ()
    else
      let c = sql.[i] in
      if c = ' ' || c = '\n' || c = '\t' || c = '\r' || c = '\012' then (
        push Space;
        go (i + 1))
      else if c = '-' && i + 1 < n && sql.[i + 1] = '-' then (
        push Space;
        go (match String.index_from_opt sql i '\n' with Some j -> j | None -> n))
      else if c = '/' && i + 1 < n && sql.[i + 1] = '*' then (
        let rec close j depth =
          if j + 1 >= n then raise Unshapeable
          else if sql.[j] = '*' && sql.[j + 1] = '/' then
            if depth = 1 then j + 2 else close (j + 2) (depth - 1)
          else if sql.[j] = '/' && sql.[j + 1] = '*' then close (j + 2) (depth + 1)
          else close (j + 1) depth
        in
        push Space;
        go (close (i + 2) 1))
      else if c = '\'' then (
        push Lit;
        go (close_quoted ~backslash:false i))
      else if
        (not (prev_ident i)) && (c = 'e' || c = 'E') && i + 1 < n && sql.[i + 1] = '\''
      then (
        push Lit;
        go (close_quoted ~backslash:true (i + 1)))
      else if
        (not (prev_ident i))
        && (match c with 'b' | 'B' | 'x' | 'X' | 'n' | 'N' -> true | _ -> false)
        && i + 1 < n
        && sql.[i + 1] = '\''
      then (
        push Lit;
        go (close_quoted ~backslash:false (i + 1)))
      else if (not (prev_ident i)) && starts_with_at i "u&'" then (
        push Lit;
        go (close_quoted ~backslash:false (i + 2)))
      else if (not (prev_ident i)) && starts_with_at i "u&\"" then
        (* a Unicode-escaped identifier: kept like a quoted identifier *)
        match String.index_from_opt sql (i + 3) '"' with
        | Some j ->
            push (Text (String.sub sql i (j - i + 1)));
            go (j + 1)
        | None -> raise Unshapeable
      else if c = '"' then (
        let rec close j =
          if j >= n then raise Unshapeable
          else if sql.[j] = '"' then
            if j + 1 < n && sql.[j + 1] = '"' then close (j + 2) else j
          else close (j + 1)
        in
        let j = close (i + 1) in
        push (Text (String.sub sql i (j - i + 1)));
        go (j + 1))
      else if c = '$' && not (prev_ident i) then (
        if i + 1 < n && sql.[i + 1] >= '0' && sql.[i + 1] <= '9' then (
          (* a positional parameter *)
          let rec num j =
            if j < n && sql.[j] >= '0' && sql.[j] <= '9' then num (j + 1) else j
          in
          let j = num (i + 1) in
          if j < n && is_ident_char sql.[j] then raise Unshapeable;
          push (Text (String.sub sql i (j - i)));
          go j)
        else
          (* $tag$ ... $tag$ with an empty or identifier tag (no $ inside) *)
          let rec tag_end j =
            if j >= n then raise Unshapeable
            else if sql.[j] = '$' then j
            else if
              (j = i + 1 && is_ident_start sql.[j]) || (j > i + 1 && is_ident_char sql.[j])
            then tag_end (j + 1)
            else raise Unshapeable
          in
          let t = tag_end (i + 1) in
          let delim = String.sub sql i (t - i + 1) in
          let m = String.length delim in
          let rec find j =
            if j + m > n then raise Unshapeable
            else if String.sub sql j m = delim then j + m
            else find (j + 1)
          in
          push Lit;
          go (find (t + 1)))
      else if
        ((c >= '0' && c <= '9')
        || (c = '.' && i + 1 < n && sql.[i + 1] >= '0' && sql.[i + 1] <= '9'))
        && not (prev_ident i)
      then (
        let rec num j =
          if j >= n then j
          else
            match sql.[j] with
            | '0' .. '9' | 'a' .. 'z' | 'A' .. 'Z' | '_' | '.' -> num (j + 1)
            | ('+' | '-') when sql.[j - 1] = 'e' || sql.[j - 1] = 'E' -> num (j + 1)
            | _ -> j
        in
        push Lit;
        go (num i))
      else if is_ident_start c then (
        let rec ident j = if j < n && is_ident_char sql.[j] then ident (j + 1) else j in
        let j = ident i in
        push (Text (String.sub sql i (j - i)));
        go j)
      else if c = '$' || c = '\\' || c = '\000' then raise Unshapeable
      else (
        push (Text (String.make 1 c));
        go (i + 1))
  in
  go 0;
  List.rev !toks

let render ~lit toks =
  let b = Buffer.create 64 in
  let space () =
    if Buffer.length b > 0 && Buffer.nth b (Buffer.length b - 1) <> ' ' then
      Buffer.add_char b ' '
  in
  List.iter
    (function
      | Space -> space ()
      | Lit -> Buffer.add_string b lit
      | Text t -> Buffer.add_string b t)
    toks;
  String.trim (Buffer.contents b)

(** A normalized shape of a statement: every literal (strings in any quoting, numbers)
    becomes [?], comments are dropped and whitespace collapsed. [None] when the statement
    does not parse or the shape cannot be shown safely: the lexer must agree with
    PostgreSQL, checked by comparing libpg_query fingerprints (which ignore constant
    values) of the statement and of its shape with every literal written as [0]. The
    caller then shows the fingerprint instead, so no literal text ever leaks. *)
let shape_of_sql sql =
  match Haltsql.Pg_parse.fingerprint sql with
  | None -> None
  | Some fp -> (
      match lex sql with
      | exception Unshapeable -> None
      | toks ->
          if Haltsql.Pg_parse.fingerprint (render ~lit:"0" toks) = Some fp then
            Some (render ~lit:"?" toks)
          else None)

let take n l = List.filteri (fun i _ -> i < n) l

let timeline entries ~since ~until =
  let bucket, series = D.series entries ~since ~until ~bucket:60 in
  `Assoc [ ("bucket_seconds", `Int bucket); ("series", `List series) ]

let shapes entries =
  D.group_by (fun (e : Index.entry) -> R.fingerprint_key e.record) entries
  |> List.map (fun (key, es) ->
      let codes =
        let seen = Hashtbl.create 8 in
        List.concat_map
          (fun (e : Index.entry) ->
            List.filter
              (fun c ->
                if Hashtbl.mem seen c then false
                else (
                  Hashtbl.add seen c ();
                  true))
              e.record.codes)
          es
      in
      let example =
        match Option.bind (List.find_map Index.raw_sql es) shape_of_sql with
        | Some shape -> shape
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

(** How far back an investigation looks from the signal's last sighting. *)
let investigation_span = 86400.

let investigation (ctx : Ctx.t) (l : live) =
  let d = l.d in
  let since = Float.max (d.first_seen -. 900.) (d.last_seen -. investigation_span) in
  let until = d.last_seen +. 900. in
  let in_scope (e : Index.entry) =
    match (d.caller, d.policy, d.verifier) with
    | Some c, _, _ -> e.record.caller = c
    | None, Some p, _ -> e.record.policy = p
    | None, None, Some v -> e.verifier = v
    | None, None, None -> true
  in
  let around = Index.between ctx.index ~since ~until |> List.filter in_scope in
  let relevant =
    List.filter
      (fun (e : Index.entry) ->
        e.ts >= d.first_seen && e.ts <= d.last_seen && D.relevant d.kind e)
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
        let denied = List.length (List.filter D.is_denied usual) in
        let policy =
          match
            D.most_common
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
                   (D.agent_for ctx.config.agents c)) );
            ("policy", Api.opt_string policy);
            ("usual_per_minute", `Float (float_of_int n /. 1440.));
            ( "usual_deny_rate",
              `Float (if n = 0 then 0. else float_of_int denied /. float_of_int n) );
          ]
  in
  `Assoc
    [
      ("signal", to_json ctx l);
      ("timeline", timeline around ~since ~until);
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
  let ls = listing ctx in
  let ls =
    if want = "all" then ls else List.filter (fun l -> status ctx l <> "resolved") ls
  in
  (* Keyset over the sorted list: the key is the distance from the end, so the cursor is
     an opaque position. *)
  let ls = sorted ls in
  let n = List.length ls in
  let page, next, _ =
    Api.page_desc r.http ~key:fst (List.mapi (fun i l -> (n - i, l)) ls)
  in
  Api.json
    (`Assoc
       [
         ("signals", `List (List.map (fun (_, l) -> to_json ctx l) page));
         ("next_cursor", next);
       ])

let get_signal ctx p (r : Router.req) =
  let id = Router.param r "id" in
  match find ctx id with
  | None -> Api.not_found "no signal %s" id
  | Some l ->
      let* () = Activity.log ctx p ~action:"signal.view" ~target:id () in
      Api.json (investigation ctx l)

let update_signal ctx p (r : Router.req) =
  let id = Router.param r "id" in
  precheck p r.http Rbac.Write_cases;
  let* body = Router.json_body r in
  let _ = Ctx.require ~body p r.http Rbac.Write_cases in
  if not (exists ctx id) then Api.not_found "no signal %s" id;
  let was_resolved = Option.map (status ctx) (find ctx id) = Some "resolved" in
  let status = Api.str_field "status" body in
  let assignee =
    match Api.member "assignee" body with
    | None -> None
    | Some `Null -> Some `Null
    | Some (`String s) when String.trim s <> "" && String.length s <= 320 ->
        Some (`String s)
    | Some _ ->
        Api.bad_request
          "field assignee must be a non-empty string of at most 320 bytes, or null"
  in
  (match status with
  | Some s when not (List.mem s statuses) ->
      Api.bad_request "status must be one of %s" (String.concat ", " statuses)
  | Some "acknowledged" -> (
      match find ctx id with
      | Some l when l.d.severity <> D.Low ->
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
  (* A person resolving a high signal also resolves its PagerDuty incident. *)
  (match (status, find ctx id) with
  | Some "resolved", Some l when l.d.severity = D.High && not was_resolved ->
      notify_async ctx (settings ctx) (fun ~timeout cfg ->
          Notify.resolve ~timeout cfg (alert l))
  | _ -> ());
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
  precheck p r.http Rbac.Pause_caller;
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
