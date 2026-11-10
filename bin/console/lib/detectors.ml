(* Signal detectors: pure functions from the record index, the fleet snapshot and the
   chain status to a list of detections. [Signals] turns detections into signals with
   stable ids and human workflow state. See docs/console/api.md#signals. *)

module R = Haltsql_report.Record

(* ---- settings (config.signals) ---- *)

type settings = {
  ct_window : float;  (** cross_tenant sliding window, seconds *)
  ct_min : int;  (** cross_tenant: E_TENANT_MISMATCH records per caller in the window *)
  ds_window : float;  (** deny_spike window, seconds *)
  ds_factor : float;  (** window deny rate must be this many times the 24 h baseline *)
  ds_min : int;  (** deny_spike: minimum records in the window *)
  ds_floor : float;  (** baseline deny rate used when the real one is lower *)
  opa_window : float;
  opa_min : int;  (** E_EXTERNAL_POLICY denials in the window *)
  shadow_min : int;  (** shadow-denied records in 24 h per policy *)
  new_caller_hours : float;
}

let defaults =
  {
    ct_window = 600.;
    ct_min = 10;
    ds_window = 900.;
    ds_factor = 3.0;
    ds_min = 50;
    ds_floor = 0.01;
    opa_window = 900.;
    opa_min = 10;
    shadow_min = 1;
    new_caller_hours = 24.;
  }

let num = function `Int i -> Some (float_of_int i) | `Float f -> Some f | _ -> None

let settings_of_json (j : Yojson.Safe.t) =
  let get sect key =
    Option.bind (Api.member sect j) (Api.member key) |> Fun.flip Option.bind num
  in
  let f sect key d = Option.value (get sect key) ~default:d in
  let i sect key d = match get sect key with Some x -> int_of_float x | None -> d in
  let m = defaults in
  {
    ct_window = 60. *. f "cross_tenant" "window_minutes" (m.ct_window /. 60.);
    ct_min = max 1 (i "cross_tenant" "min_records" m.ct_min);
    ds_window = 60. *. f "deny_spike" "window_minutes" (m.ds_window /. 60.);
    ds_factor = f "deny_spike" "factor" m.ds_factor;
    ds_min = max 1 (i "deny_spike" "min_records" m.ds_min);
    ds_floor = f "deny_spike" "min_baseline_rate" m.ds_floor;
    opa_window = 60. *. f "opa_errors" "window_minutes" (m.opa_window /. 60.);
    opa_min = max 1 (i "opa_errors" "min_records" m.opa_min);
    shadow_min = max 1 (i "shadow_ready" "min_records" m.shadow_min);
    new_caller_hours = f "new_caller" "hours" m.new_caller_hours;
  }

(* ---- detections ---- *)

type detection = {
  kind : string;
  subject : string;  (** what the signal is about: caller, policy, verifier, source *)
  slug : string;  (** id-safe form of the subject *)
  bucket : float;  (** start of the window bucket the episode began in *)
  severity : string;  (** high | medium | low *)
  title : string;
  body : string;
  first_seen : float;
  last_seen : float;
  caller : string option;
  policy : string option;
  policy_version : string option;
  verifier : string option;
  link_kind : string;  (** investigation | fleet | rollout | agent *)
  link_target : string;
  facts : Yojson.Safe.t;
}

let severity_rank = function "high" -> 3 | "medium" -> 2 | "low" -> 1 | _ -> 0

let stamp t =
  let tm = Unix.gmtime t in
  Printf.sprintf "%04d%02d%02dT%02d%02d" (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday
    tm.tm_hour tm.tm_min

let id d = Printf.sprintf "sig_%s_%s_%s" d.kind d.slug (stamp d.bucket)

let slug s =
  let b = Buffer.create (String.length s) in
  String.iter
    (fun c ->
      let c = Char.lowercase_ascii c in
      match c with
      | 'a' .. 'z' | '0' .. '9' -> Buffer.add_char b c
      | _ ->
          let n = Buffer.length b in
          if n > 0 && Buffer.nth b (n - 1) <> '-' then Buffer.add_char b '-')
    s;
  let r = Buffer.contents b in
  let r =
    if String.ends_with ~suffix:"-" r then String.sub r 0 (String.length r - 1) else r
  in
  let r = if String.length r > 40 then String.sub r 0 40 else r in
  if r = s && r <> "" then r
  else (if r = "" then "x" else r) ^ "-" ^ String.sub (Haltsql.sha256_hex s) 0 6

let floor_to w t = if w <= 0. then t else Float.of_int (int_of_float (t /. w)) *. w

(* ---- helpers ---- *)

let has_code c (e : Index.entry) = List.mem c e.record.codes
let is_denied (e : Index.entry) = e.record.outcome = R.Denied
let is_shadow (e : Index.entry) = e.record.outcome = R.Shadow_denied
let plural n one many = Printf.sprintf "%d %s" n (if n = 1 then one else many)

let pct r =
  if r > 0. && r < 0.01 then Printf.sprintf "%.1f%%" (r *. 100.)
  else Printf.sprintf "%.0f%%" (r *. 100.)

let group_by key l =
  let tbl = Hashtbl.create 16 and order = ref [] in
  List.iter
    (fun x ->
      let k = key x in
      match Hashtbl.find_opt tbl k with
      | Some r -> r := x :: !r
      | None ->
          Hashtbl.add tbl k (ref [ x ]);
          order := k :: !order)
    l;
  List.rev_map (fun k -> (k, List.rev !(Hashtbl.find tbl k))) !order

let count_codes entries =
  let tbl = Hashtbl.create 8 and order = ref [] in
  List.iter
    (fun (e : Index.entry) ->
      List.iter
        (fun c ->
          match Hashtbl.find_opt tbl c with
          | Some n -> incr n
          | None ->
              Hashtbl.add tbl c (ref 1);
              order := c :: !order)
        e.record.codes)
    entries;
  List.rev_map (fun c -> (c, !(Hashtbl.find tbl c))) !order
  |> List.stable_sort (fun (_, a) (_, b) -> compare b a)

let codes_json l = `Assoc (List.map (fun (c, n) -> (c, `Int n)) l)

let span entries =
  List.fold_left
    (fun (lo, hi) (e : Index.entry) -> (Float.min lo e.ts, Float.max hi e.ts))
    (infinity, neg_infinity) entries

let most_common l =
  group_by Fun.id l
  |> List.map (fun (k, v) -> (k, List.length v))
  |> List.stable_sort (fun (_, a) (_, b) -> compare b a)
  |> function
  | (k, _) :: _ -> Some k
  | [] -> None

let minutes_between a b = max 1 (int_of_float (Float.ceil ((b -. a) /. 60.)))

(* Configured agents. A caller belongs to an agent when it equals one of the agent's
   [callers] (or starts with it: a configured "oidc:okta" covers "oidc:okta:svc-x"), or
   equals its [identity]. *)
let agent_for (agents : Console_config.agent list) caller =
  List.find_opt
    (fun (a : Console_config.agent) ->
      List.exists (fun c -> c = caller || String.starts_with ~prefix:c caller) a.a_callers
      || a.a_identity = Some caller)
    agents

let who agents caller =
  match agent_for agents caller with Some a -> a.a_name | None -> caller

(* ---- JSON access (fleet, chain status) ---- *)

let mem = Api.member
let jstr k j = match mem k j with Some (`String s) -> Some s | _ -> None
let jbool k j = match mem k j with Some (`Bool b) -> b | _ -> false
let jint k j = match mem k j with Some (`Int i) -> Some i | _ -> None
let jlist k j = match mem k j with Some (`List l) -> l | _ -> []

let render (j : Yojson.Safe.t) =
  match j with
  | `String s -> s
  | `Int i -> string_of_int i
  | `Assoc _ -> (
      match (jstr "location" j, jint "seq" j) with
      | Some l, _ -> l
      | None, Some s -> Printf.sprintf "seq %d" s
      | None, None -> Yojson.Safe.to_string j)
  | j -> Yojson.Safe.to_string j

(* ---- tenant values by re-verification ---- *)

let probe_value = "\000haltsql-console-probe"

(* "app.tickets.tenant_id is compared to 'globex', 'initech', which is not the caller's
   tenant value (table app.tickets)" -> ("tenant_id", ["globex"; "initech"]). *)
let parse_mismatch msg =
  let marker = " is compared to " and tail = ", which is not the caller's tenant value" in
  let find sub s from =
    let n = String.length sub and m = String.length s in
    let rec go i =
      if i + n > m then None else if String.sub s i n = sub then Some i else go (i + 1)
    in
    go from
  in
  match find marker msg 0 with
  | None -> None
  | Some i -> (
      let start = i + String.length marker in
      match find tail msg start with
      | None -> None
      | Some j ->
          let col = String.sub msg 0 i in
          let col =
            match String.rindex_opt col '.' with
            | Some k -> String.sub col (k + 1) (String.length col - k - 1)
            | None -> col
          in
          let lits = String.sub msg start (j - start) in
          (* A comma-separated list of 'string' or integer literals. *)
          let n = String.length lits in
          let rec scan p acc =
            if p >= n then List.rev acc
            else if lits.[p] = ' ' || lits.[p] = ',' then scan (p + 1) acc
            else if lits.[p] = '\'' then
              let rec close q =
                if q >= n then n
                else if lits.[q] = '\'' && (q + 1 >= n || lits.[q + 1] = ',') then q
                else close (q + 1)
              in
              let q = close (p + 1) in
              scan (q + 1) (String.sub lits (p + 1) (max 0 (q - p - 1)) :: acc)
            else
              let q =
                match String.index_from_opt lits p ',' with Some q -> q | None -> n
              in
              scan q (String.trim (String.sub lits p (q - p)) :: acc)
          in
          Some (col, scan 0 []))

(** Tenant literals a statement compares tenant columns to, by re-verifying it against its
    policy with a context value nothing can match (literal mode only). *)
let tenant_literals (policy : Haltsql.Policy.t) sql =
  match policy.tenancy.mode with
  | Haltsql.Policy.Bound -> []
  | Haltsql.Policy.Literal ->
      let ctx =
        Haltsql.Context.make
          (List.map
             (fun (_, field) -> (field, Haltsql.Context.One probe_value))
             policy.tenancy.keys)
      in
      let v = Haltsql.verify policy ctx sql in
      List.filter_map
        (fun (r : Haltsql.Reason.t) ->
          if r.code = Haltsql.Reason.E_TENANT_MISMATCH then parse_mismatch r.message
          else None)
        (v.reasons @ v.shadow_reasons)

let max_reverify = 500

(* ---- inputs ---- *)

type input = {
  now : float;
  recent : Index.entry list;  (** the last 24 h plus the longest window, oldest first *)
  index : Index.t;
  fleet : Yojson.Safe.t option;
  chain_status : Yojson.Safe.t;
  agents : Console_config.agent list;
  policies : (string * Haltsql.Policy.t) list;
  opa_error_delta : int option;  (** OPA errors counted by the fleet in the OPA window *)
}

let base ~kind ~subject ~slug_of ~bucket ~severity ~title ~body ~first_seen ~last_seen
    ~link_kind ~link_target ~facts =
  {
    kind;
    subject;
    slug = slug slug_of;
    bucket;
    severity;
    title;
    body;
    first_seen;
    last_seen;
    caller = None;
    policy = None;
    policy_version = None;
    verifier = None;
    link_kind;
    link_target;
    facts;
  }

let latest_policy (entries : Index.entry list) =
  match List.rev entries with
  | e :: _ -> (Some e.record.policy, e.record.policy_version)
  | [] -> (None, None)

(* ---- cross_tenant ---- *)

let cross_tenant s inp =
  let since = inp.now -. s.ct_window in
  let hits =
    List.filter
      (fun (e : Index.entry) ->
        e.ts >= since && e.ts <= inp.now && has_code "E_TENANT_MISMATCH" e)
      inp.recent
  in
  group_by (fun (e : Index.entry) -> e.record.caller) hits
  |> List.filter_map (fun (caller, es) ->
      let n = List.length es in
      if n < s.ct_min then None
      else
        let first, last = span es in
        let name = who inp.agents caller in
        let reverify (e : Index.entry) =
          match (Index.raw_sql e, List.assoc_opt e.record.policy inp.policies) with
          | Some sql, Some p -> tenant_literals p sql
          | _ -> []
        in
        let take n l = List.filteri (fun i _ -> i < n) l in
        let foreign = List.concat_map reverify (take max_reverify es) in
        let own =
          List.filter
            (fun (e : Index.entry) ->
              e.record.caller = caller && e.record.outcome = R.Allowed)
            inp.recent
          |> List.rev |> take 200 |> List.concat_map reverify |> List.concat_map snd
        in
        let column = Option.map fst (List.nth_opt foreign 0) in
        let values =
          List.concat_map snd foreign
          |> List.filter (fun v -> not (List.mem v own))
          |> List.sort_uniq compare
        in
        let own_value = most_common own in
        let denied = List.length (List.filter is_denied es) in
        let shadow = n - denied in
        let mins = minutes_between first last in
        let lead =
          match (column, values) with
          | Some col, (_ :: _ as vs) ->
              Printf.sprintf "%s in %s compared %s to %s%s." (plural n "query" "queries")
                (plural mins "minute" "minutes")
                col
                (plural (List.length vs) "value" "values")
                (match own_value with
                | Some o -> " other than " ^ o
                | None -> " that are not the caller's tenant")
          | _ ->
              Printf.sprintf
                "%s in %s compared a tenant column to a value other than the caller's \
                 tenant."
                (plural n "query" "queries")
                (plural mins "minute" "minutes")
        in
        let tail =
          if shadow = 0 then
            " All were denied at the tenancy check; none reached the database."
          else
            Printf.sprintf
              " %d %s denied at the tenancy check; %d ran because the policy is in \
               shadow mode."
              denied
              (if denied = 1 then "was" else "were")
              shadow
        in
        let policy, policy_version = latest_policy es in
        let verifier =
          Option.map (fun (e : Index.entry) -> e.verifier) (List.nth_opt (List.rev es) 0)
        in
        let d =
          base ~kind:"cross_tenant" ~subject:caller ~slug_of:name
            ~bucket:(floor_to s.ct_window first) ~severity:"high"
            ~title:(name ^ " is filtering on other tenants")
            ~body:(lead ^ tail) ~first_seen:first ~last_seen:last
            ~link_kind:"investigation" ~link_target:"" (* filled with the id by Signals *)
            ~facts:
              (`Assoc
                 [
                   ("records", `Int n);
                   ("denied", `Int denied);
                   ( "distinct_values",
                     match values with [] -> `Null | vs -> `Int (List.length vs) );
                   ("codes", codes_json (count_codes es));
                 ])
        in
        Some { d with caller = Some caller; policy; policy_version; verifier })

(* ---- deny_spike ---- *)

let deny_spike s inp =
  let w0 = inp.now -. s.ds_window and b0 = inp.now -. s.ds_window -. 86400. in
  let window =
    List.filter (fun (e : Index.entry) -> e.ts >= w0 && e.ts <= inp.now) inp.recent
  in
  group_by (fun (e : Index.entry) -> e.record.caller) window
  |> List.filter_map (fun (caller, ws) ->
      let w = List.length ws in
      let denied_w = List.filter is_denied ws in
      let wd = List.length denied_w in
      if w < s.ds_min || wd = 0 then None
      else
        let base_es =
          List.filter
            (fun (e : Index.entry) -> e.record.caller = caller && e.ts >= b0 && e.ts < w0)
            inp.recent
        in
        let b = List.length base_es in
        let bd = List.length (List.filter is_denied base_es) in
        let rate_w = float_of_int wd /. float_of_int w in
        let rate_b = if b = 0 then 0. else float_of_int bd /. float_of_int b in
        if rate_w < s.ds_factor *. Float.max rate_b s.ds_floor || rate_w <= rate_b then
          None
        else
          let first, last = span denied_w in
          let name = who inp.agents caller in
          let codes = count_codes denied_w in
          let mins = int_of_float (s.ds_window /. 60.) in
          let body =
            Printf.sprintf "%d of %s in the last %s were denied (%s), %s.%s" wd
              (plural w "query" "queries")
              (plural mins "minute" "minutes")
              (pct rate_w)
              (if b = 0 then "and this caller had no traffic in the previous 24 hours"
               else
                 Printf.sprintf "compared with %s over the previous 24 hours" (pct rate_b))
              (match codes with
              | (c, k) :: _ -> Printf.sprintf " Most common code: %s (%d)." c k
              | [] -> "")
          in
          let policy, policy_version = latest_policy ws in
          let d =
            base ~kind:"deny_spike" ~subject:caller ~slug_of:name
              ~bucket:(floor_to s.ds_window first) ~severity:"medium"
              ~title:(name ^ " is being denied far more than usual")
              ~body ~first_seen:first ~last_seen:last ~link_kind:"agent" ~link_target:name
              ~facts:
                (`Assoc
                   [
                     ("records", `Int w);
                     ("denied", `Int wd);
                     ("deny_rate", `Float rate_w);
                     ("baseline_records", `Int b);
                     ("baseline_deny_rate", `Float rate_b);
                     ("codes", codes_json codes);
                   ])
          in
          Some { d with caller = Some caller; policy; policy_version })

(* ---- opa_errors ---- *)

let opa_errors s inp =
  let w0 = inp.now -. s.opa_window in
  let hits =
    List.filter
      (fun (e : Index.entry) ->
        e.ts >= w0 && e.ts <= inp.now && is_denied e && has_code "E_EXTERNAL_POLICY" e)
      inp.recent
  in
  let n = List.length hits in
  let delta = Option.value inp.opa_error_delta ~default:0 in
  if n < s.opa_min && delta <= 0 then []
  else
    let mins = int_of_float (s.opa_window /. 60.) in
    let parts =
      (if n >= s.opa_min then
         [
           Printf.sprintf
             "%s in the last %s were denied by the external policy engine (OPA)."
             (plural n "query" "queries")
             (plural mins "minute" "minutes");
         ]
       else [])
      @
      if delta > 0 then
        [
          Printf.sprintf
            "Verifiers counted %s calling OPA in that time (timeouts or errors); with \
             on_error: deny, agents see these as denials."
            (plural delta "error" "errors");
        ]
      else []
    in
    let first, last = if hits = [] then (inp.now, inp.now) else span hits in
    [
      base ~kind:"opa_errors" ~subject:"opa" ~slug_of:"opa"
        ~bucket:(floor_to s.opa_window first) ~severity:"medium"
        ~title:"The external policy engine is denying or failing queries"
        ~body:(String.concat " " parts) ~first_seen:first ~last_seen:last
        ~link_kind:"fleet" ~link_target:"opa"
        ~facts:
          (`Assoc
             [
               ("records", `Int n);
               ( "fleet_errors",
                 match inp.opa_error_delta with Some d -> `Int d | None -> `Null );
               ("codes", codes_json (count_codes hits));
             ]);
    ]

(* ---- fleet-derived ---- *)

let fleet_verifiers inp =
  match inp.fleet with Some f -> jlist "verifiers" f | None -> []

let hour = 3600.

let sink_name = function
  | `String s -> s
  | j -> (
      match (jstr "name" j, jstr "type" j) with
      | Some n, _ -> n
      | None, Some t -> t
      | None, None -> Yojson.Safe.to_string j)

let sink_buffering _s inp =
  List.filter_map
    (fun v ->
      match jstr "name" v with
      | None -> None
      | Some name ->
          let unhealthy = jlist "unhealthy_sinks" v in
          if jstr "state" v <> Some "buffering" && unhealthy = [] then None
          else
            let sinks = List.map sink_name unhealthy in
            let body =
              Printf.sprintf
                "%s cannot deliver audit records to %s and is buffering them. Nothing is \
                 lost while the buffer has room, but downstream systems see the records \
                 late."
                name
                (match sinks with [] -> "one of its sinks" | l -> String.concat ", " l)
            in
            let d =
              base ~kind:"sink_buffering" ~subject:name ~slug_of:name
                ~bucket:(floor_to hour inp.now) ~severity:"medium"
                ~title:(name ^ " is buffering audit records")
                ~body ~first_seen:inp.now ~last_seen:inp.now ~link_kind:"fleet"
                ~link_target:name
                ~facts:(`Assoc [ ("unhealthy_sinks", Api.strings sinks) ])
            in
            Some { d with verifier = Some name })
    (fleet_verifiers inp)

let restart_pending _s inp =
  List.filter_map
    (fun v ->
      match jstr "name" v with
      | Some name
        when jbool "restart_pending" v || jstr "state" v = Some "restart_pending" ->
          let d =
            base ~kind:"restart_pending" ~subject:name ~slug_of:name
              ~bucket:(floor_to hour inp.now) ~severity:"medium"
              ~title:(name ^ " needs a restart to apply its audit settings")
              ~body:
                (name
               ^ " reports audit_restart_pending: its audit sink configuration changed \
                  and takes effect only after a restart. Until then it keeps writing to \
                  the sinks it started with.")
              ~first_seen:inp.now ~last_seen:inp.now ~link_kind:"fleet" ~link_target:name
              ~facts:(`Assoc [])
          in
          Some { d with verifier = Some name }
      | _ -> None)
    (fleet_verifiers inp)

let bundle_drift _s inp =
  let bundles = match inp.fleet with Some f -> jlist "bundles" f | None -> [] in
  group_by (fun b -> Option.value (jstr "source" b) ~default:"(bundle)") bundles
  |> List.filter_map (fun (source, bs) ->
      let versions = List.sort_uniq compare (List.filter_map (jstr "version") bs) in
      let out_of_sync = List.exists (fun b -> mem "in_sync" b = Some (`Bool false)) bs in
      if List.length versions <= 1 && not out_of_sync then None
      else
        let per =
          List.map
            (fun b ->
              Printf.sprintf "%s (%s)"
                (Option.value (jstr "version" b) ~default:"unknown")
                (plural
                   (Option.value (jint "verifiers" b) ~default:0)
                   "verifier" "verifiers"))
            bs
        in
        Some
          (base ~kind:"bundle_drift" ~subject:source ~slug_of:source
             ~bucket:(floor_to hour inp.now) ~severity:"medium"
             ~title:("Verifiers serve different versions of " ^ source)
             ~body:
               (Printf.sprintf
                  "Verifiers loading %s do not agree on the bundle: %s. Some agents are \
                   checked against a different policy than others."
                  source (String.concat ", " per))
             ~first_seen:inp.now ~last_seen:inp.now ~link_kind:"fleet" ~link_target:source
             ~facts:(`Assoc [ ("versions", Api.strings versions) ])))

let chain_broken _s inp =
  let checked = Option.bind (jstr "checked_at" inp.chain_status) Api.parse_time in
  let at = Option.value checked ~default:inp.now in
  List.filter_map
    (fun c ->
      match (jstr "verifier" c, jstr "state" c) with
      | Some v, Some "broken" ->
          let brk = Option.map render (mem "first_break" c) in
          let records = jint "records" c in
          let d =
            base ~kind:"chain_broken" ~subject:v ~slug_of:v ~bucket:(floor_to hour at)
              ~severity:"high"
              ~title:("The audit hash chain from " ^ v ^ " is broken")
              ~body:
                (Printf.sprintf
                   "The audit hash chain from %s is broken%s: a record was changed, \
                    removed or inserted after it was written.%s"
                   v
                   (match brk with Some b -> " at " ^ b | None -> "")
                   (match records with
                   | Some n ->
                       Printf.sprintf " %s were checked." (plural n "record" "records")
                   | None -> ""))
              ~first_seen:at ~last_seen:at ~link_kind:"fleet" ~link_target:v
              ~facts:
                (`Assoc
                   [
                     ("records", Api.opt_int records);
                     ("first_break", Option.value (mem "first_break" c) ~default:`Null);
                   ])
          in
          Some { d with verifier = Some v }
      | _ -> None)
    (jlist "chains" inp.chain_status)

(* ---- new_caller ---- *)

(* Only meaningful once the index reaches back further than the look-back: right after
   start-up every caller would look new. *)
let new_caller s inp =
  let horizon = inp.now -. (s.new_caller_hours *. 3600.) in
  match Index.oldest inp.index with
  | Some o when o < horizon ->
      let first_seen = Hashtbl.create 64 in
      Index.iter inp.index (fun e ->
          match Hashtbl.find_opt first_seen e.record.caller with
          | Some t when t <= e.ts -> ()
          | _ -> Hashtbl.replace first_seen e.record.caller e.ts);
      Hashtbl.fold
        (fun caller t acc ->
          if t >= horizon && agent_for inp.agents caller = None then (caller, t) :: acc
          else acc)
        first_seen []
      |> List.sort compare
      |> List.map (fun (caller, t) ->
          let es =
            List.filter
              (fun (e : Index.entry) -> e.record.caller = caller && e.ts >= t)
              inp.recent
          in
          let n = List.length es and denied = List.length (List.filter is_denied es) in
          let _, last = if es = [] then (t, t) else span es in
          let policy, policy_version = latest_policy es in
          let d =
            base ~kind:"new_caller" ~subject:caller ~slug_of:caller
              ~bucket:(floor_to hour t) ~severity:"low" ~title:("New caller: " ^ caller)
              ~body:
                (Printf.sprintf
                   "%s first appeared at %s and is not listed under agents in the \
                    console config. It has made %s since (%d denied)%s."
                   caller (Api.iso8601 t) (plural n "query" "queries") denied
                   (match policy with Some p -> ", under policy " ^ p | None -> ""))
              ~first_seen:t ~last_seen:last ~link_kind:"agent" ~link_target:caller
              ~facts:(`Assoc [ ("records", `Int n); ("denied", `Int denied) ])
          in
          { d with caller = Some caller; policy; policy_version })
  | _ -> []

(* ---- shadow_ready ---- *)

let shadow_ready s inp =
  let since = inp.now -. 86400. in
  List.filter (fun (e : Index.entry) -> e.ts >= since && is_shadow e) inp.recent
  |> group_by (fun (e : Index.entry) -> e.record.policy)
  |> List.filter_map (fun (policy, es) ->
      let n = List.length es in
      if n < s.shadow_min then None
      else
        let first, last = span es in
        let shapes =
          List.length
            (List.sort_uniq compare
               (List.map (fun (e : Index.entry) -> R.fingerprint_key e.record) es))
        in
        let callers =
          List.length
            (List.sort_uniq compare
               (List.map (fun (e : Index.entry) -> e.record.caller) es))
        in
        let _, policy_version = latest_policy es in
        let d =
          base ~kind:"shadow_ready" ~subject:policy ~slug_of:policy
            ~bucket:(floor_to 86400. first) ~severity:"low"
            ~title:
              (Printf.sprintf "%s: %s to review" policy
                 (plural n "shadow denial" "shadow denials"))
            ~body:
              (Printf.sprintf
                 "In the last 24 hours %s under %s would have been denied if it were \
                  enforced (%s, %s). Review them before switching it to enforce."
                 (plural n "query" "queries") policy
                 (plural shapes "query shape" "query shapes")
                 (plural callers "caller" "callers"))
            ~first_seen:first ~last_seen:last ~link_kind:"rollout" ~link_target:policy
            ~facts:
              (`Assoc
                 [
                   ("records", `Int n);
                   ("shapes", `Int shapes);
                   ("callers", `Int callers);
                   ("codes", codes_json (count_codes es));
                 ])
        in
        Some { d with policy = Some policy; policy_version })

(* ---- all ---- *)

let detectors =
  [
    cross_tenant;
    deny_spike;
    opa_errors;
    sink_buffering;
    restart_pending;
    bundle_drift;
    chain_broken;
    new_caller;
    shadow_ready;
  ]

let run s inp = List.concat_map (fun f -> f s inp) detectors

let longest_window s =
  List.fold_left Float.max 0. [ s.ct_window; s.ds_window; s.opa_window ]

(** Which records a signal of [kind] is about (for its investigation). *)
let relevant kind (e : Index.entry) =
  match kind with
  | "cross_tenant" -> has_code "E_TENANT_MISMATCH" e
  | "deny_spike" -> is_denied e
  | "opa_errors" -> is_denied e && has_code "E_EXTERNAL_POLICY" e
  | "new_caller" -> true
  | "shadow_ready" -> is_shadow e
  | _ -> false

(** OPA errors and timeouts the fleet has counted so far: [opa.decisions.error_denied],
    else the sum of every verifier's [opa.timeouts]. *)
let opa_error_total (fleet : Yojson.Safe.t option) =
  match fleet with
  | None -> None
  | Some f -> (
      match
        Option.bind (mem "opa" f) (mem "decisions")
        |> Fun.flip Option.bind (jint "error_denied")
      with
      | Some n -> Some n
      | None ->
          let per =
            List.filter_map
              (fun v -> Option.bind (mem "opa" v) (jint "timeouts"))
              (jlist "verifiers" f)
          in
          if per = [] then None else Some (List.fold_left ( + ) 0 per))
