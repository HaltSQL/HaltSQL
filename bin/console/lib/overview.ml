(* Overview: totals, series, posture checks and signal counts for a time range.
   See docs/console/api.md#overview. *)

module R = Haltsql_report.Record
module J = Detectors

(* range=1h -> 5 min buckets, 24h -> 1 h, 7d -> 6 h; explicit since/until (or any other
   range) -> Summary.auto_bucket. *)
let bucket_seconds (req : Cohttp.Request.t) (r : Api.range) =
  let explicit = Api.query req "since" <> None || Api.query req "until" <> None in
  match (explicit, Api.query req "range") with
  | false, Some "1h" -> 300
  | false, (Some "24h" | None) -> 3600
  | false, Some "7d" -> 21600
  | _ -> Haltsql_report.Summary.auto_bucket (Some r.since) (Some r.until)

(** Nearest-rank 99th percentile of [elapsed_us], in milliseconds (3 decimals). *)
let p99_ms (entries : Index.entry list) =
  match List.filter_map (fun (e : Index.entry) -> e.elapsed_us) entries with
  | [] -> None
  | l ->
      let a = Array.of_list l in
      Array.sort compare a;
      let n = Array.length a in
      let rank = int_of_float (Float.ceil (0.99 *. float_of_int n)) in
      let v = a.(max 0 (min (n - 1) (rank - 1))) in
      Some (Float.round (float_of_int v) /. 1000.)

let series (entries : Index.entry list) (r : Api.range) bucket =
  let w = float_of_int bucket in
  let start = J.floor_to w r.since in
  let nb = max 1 (int_of_float (Float.ceil ((r.until -. start) /. w))) in
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
  Array.to_list
    (Array.mapi
       (fun i (x, y, z) ->
         `Assoc
           [
             ("start", `String (Api.iso8601 (start +. (float_of_int i *. w))));
             ("allowed", `Int x);
             ("denied", `Int y);
             ("shadow_denied", `Int z);
           ])
       a)

(* ---- posture ---- *)

let check id state title detail =
  `Assoc
    [
      ("id", `String id);
      ("state", `String state);
      ("title", `String title);
      ("detail", `String detail);
    ]

let verifiers_of fleet = match fleet with Some f -> J.jlist "verifiers" f | None -> []

let bundle_in_sync (ctx : Ctx.t) =
  let title = "Policy bundles in sync" in
  match Fleet.snapshot ctx with
  | None -> check "bundle_in_sync" "unknown" title "No fleet snapshot yet."
  | Some f -> (
      match J.jlist "bundles" f with
      | [] ->
          check "bundle_in_sync" "unknown" title "No verifier reports a policy bundle."
      | bundles ->
          let drift =
            J.group_by (fun b -> Option.value (J.jstr "source" b) ~default:"") bundles
            |> List.filter (fun (_, bs) ->
                List.length
                  (List.sort_uniq compare (List.filter_map (J.jstr "version") bs))
                > 1
                || List.exists (fun b -> J.mem "in_sync" b = Some (`Bool false)) bs)
          in
          if drift = [] then
            let desc =
              List.map
                (fun b ->
                  Printf.sprintf "%s %s"
                    (Option.value (J.jstr "source" b) ~default:"bundle")
                    (Option.value (J.jstr "version" b) ~default:"(unknown version)"))
                bundles
            in
            check "bundle_in_sync" "ok" title
              (Printf.sprintf "Every verifier serves the same version: %s."
                 (String.concat ", " desc))
          else
            check "bundle_in_sync" "warning" title
              (Printf.sprintf "Verifiers disagree on %s."
                 (String.concat ", " (List.map fst drift))))

let audit_chains (ctx : Ctx.t) =
  let title = "Audit chains intact" in
  match J.jlist "chains" (Chain.status ctx) with
  | [] -> check "audit_chains" "unknown" title "No chain verification has run yet."
  | chains ->
      let st s = List.filter (fun c -> J.jstr "state" c = Some s) chains in
      let names l = String.concat ", " (List.filter_map (J.jstr "verifier") l) in
      let broken = st "broken" and intact = st "intact" in
      let when_ =
        match J.jstr "checked_at" (Chain.status ctx) with
        | Some t -> " Last checked " ^ t ^ "."
        | None -> ""
      in
      if broken <> [] then
        check "audit_chains" "error" title
          (Printf.sprintf "Broken: %s.%s" (names broken) when_)
      else if List.length intact = List.length chains then
        check "audit_chains" "ok" title
          (Printf.sprintf "%s verified intact.%s"
             (J.plural (List.length chains) "chain" "chains")
             when_)
      else
        check "audit_chains" "warning" title
          (Printf.sprintf "%d of %d chains could not be verified.%s"
             (List.length chains - List.length intact)
             (List.length chains) when_)

let pii_exposure (ctx : Ctx.t) =
  let title = "No tagged column allowed without an exception" in
  match Data.columns_doc ctx with
  | None -> check "pii_exposure" "unknown" title "No data catalog has been read."
  | Some cols ->
      let review =
        match Option.bind (J.mem "totals" cols) (J.jint "needs_review") with
        | Some n -> n
        | None ->
            List.length
              (List.filter
                 (fun c -> J.jstr "status" c = Some "needs_review")
                 (J.jlist "columns" cols))
      in
      if review = 0 then
        check "pii_exposure" "ok" title
          "Every tagged column a policy allows has an approved exception."
      else
        check "pii_exposure" "warning" title
          (Printf.sprintf "%s allowed by a policy without an approved exception."
             (J.plural review "tagged column is" "tagged columns are"))

let in_process_agents (ctx : Ctx.t) =
  let title = "Every agent is centrally audited" in
  match
    List.filter
      (fun (a : Console_config.agent) -> a.a_via = "in_process")
      ctx.config.agents
  with
  | [] -> check "in_process_agents" "ok" title "No agent is configured as in-process."
  | l ->
      check "in_process_agents" "warning" title
        (Printf.sprintf
           "%s (%s) %s queries in-process; their decisions are not in the central audit \
            log."
           (J.plural (List.length l) "agent" "agents")
           (String.concat ", " (List.map (fun (a : Console_config.agent) -> a.a_name) l))
           (if List.length l = 1 then "checks" else "check"))

let restart_pending (ctx : Ctx.t) =
  let title = "No verifier waiting for a restart" in
  match Fleet.snapshot ctx with
  | None -> check "restart_pending" "unknown" title "No fleet snapshot yet."
  | Some f -> (
      match
        List.filter
          (fun v ->
            J.jbool "restart_pending" v || J.jstr "state" v = Some "restart_pending")
          (J.jlist "verifiers" f)
      with
      | [] -> check "restart_pending" "ok" title "No verifier has audit_restart_pending."
      | l ->
          check "restart_pending" "warning" title
            (Printf.sprintf "%s audit settings that apply only after a restart."
               (String.concat ", " (List.filter_map (J.jstr "name") l)
               ^ if List.length l = 1 then " has" else " have")))

let posture ctx =
  [
    bundle_in_sync ctx;
    audit_chains ctx;
    pii_exposure ctx;
    in_process_agents ctx;
    restart_pending ctx;
  ]

(* ---- route ---- *)

let reporting_states = [ "ready"; "buffering"; "restart_pending" ]

let overview (ctx : Ctx.t) (req : Cohttp.Request.t) =
  let now = Ctx.now () in
  let r = Api.range ~now req in
  let bucket = bucket_seconds req r in
  let entries = Index.between ctx.index ~since:r.since ~until:r.until in
  let count p = List.length (List.filter p entries) in
  let denied = count J.is_denied in
  let denied_by_opa =
    count (fun e -> J.is_denied e && J.has_code "E_EXTERNAL_POLICY" e)
  in
  let shadow = count J.is_shadow in
  let reporting =
    match Fleet.snapshot ctx with
    | Some _ ->
        List.length
          (List.filter
             (fun v ->
               match J.jstr "state" v with
               | Some s -> List.mem s reporting_states
               | None -> false)
             (verifiers_of (Fleet.snapshot ctx)))
    | None ->
        List.length
          (List.sort_uniq compare
             (List.map (fun (e : Index.entry) -> e.verifier) entries))
  in
  `Assoc
    [
      ( "range",
        `Assoc
          [
            ("since", `String (Api.iso8601 r.since));
            ("until", `String (Api.iso8601 r.until));
            ("bucket_seconds", `Int bucket);
          ] );
      ("updated", `String (Api.iso8601 now));
      ("verifiers_reporting", `Int reporting);
      ( "totals",
        `Assoc
          [
            ("checked", `Int (List.length entries));
            ("denied", `Int denied);
            ("denied_by_opa", `Int denied_by_opa);
            ("shadow_denied", `Int shadow);
            ("p99_ms", Api.opt_float (p99_ms entries));
          ] );
      ("series", `List (series entries r bucket));
      ("posture", `List (posture ctx));
      ("signals", Signals.counts ctx);
    ]

let routes : Router.route list =
  [
    Router.get "/api/v1/overview" (fun ctx _p r -> Api.json (overview ctx r.Router.http));
  ]

let start (_ : Ctx.t) : unit Lwt.t = Lwt.return_unit
