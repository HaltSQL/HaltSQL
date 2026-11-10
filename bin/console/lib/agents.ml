(* Agents list and detail. Owner: PR console/05-build. See docs/console/api.md (Agents).

   Agents come from [agents:] in the config merged with every caller seen in the index.
   A caller listed in a configured agent's [callers] belongs to that agent; any other
   caller becomes its own agent, with [via] guessed from its records: proxy records ->
   proxy, a verifier of kind mcp -> mcp, else sidecar. *)

module C = Console_config
module R = Haltsql_report

type agent = {
  name : string;
  configured : C.agent option;
  via : string;
  callers : string list;  (** configured callers, or the callers seen *)
  records : Index.entry list;  (** in range, oldest first *)
}

(* ---- verifier kinds ---- *)

let verifier_kind (ctx : Ctx.t) name =
  match List.find_opt (fun (v : C.verifier) -> v.v_name = name) ctx.config.verifiers with
  | Some v -> Some (C.verifier_kind_to_string v.v_kind)
  | None ->
      List.find_map
        (fun v ->
          if Policies.str "name" v = Some name then Policies.str "kind" v else None)
        (Policies.fleet_verifiers ctx)

let guess_via ctx (e : Index.entry) =
  match e.record.source with
  | R.Record.Proxy -> "proxy"
  | R.Record.Server -> (
      match verifier_kind ctx e.verifier with
      | Some "mcp" -> "mcp"
      | Some "proxy" -> "proxy"
      | _ -> "sidecar")

(* ---- building ---- *)

let most_frequent l =
  let tbl = Hashtbl.create 8 in
  List.iter
    (fun x ->
      Hashtbl.replace tbl x (1 + Option.value (Hashtbl.find_opt tbl x) ~default:0))
    l;
  Hashtbl.fold
    (fun k n acc ->
      match acc with
      | Some (_, m) when m > n -> acc
      | Some (k', m) when m = n && compare k' k <= 0 -> acc
      | _ -> Some (k, n))
    tbl None
  |> Option.map fst

let build (ctx : Ctx.t) (range : Api.range) : agent list =
  let entries = Index.between ctx.index ~since:range.since ~until:range.until in
  let configured = ctx.config.agents in
  let owner caller =
    List.find_opt (fun (a : C.agent) -> List.mem caller a.a_callers) configured
  in
  let by_agent = Hashtbl.create 16 and seen_order = ref [] in
  List.iter
    (fun (e : Index.entry) ->
      let key =
        match owner e.record.caller with Some a -> a.a_name | None -> e.record.caller
      in
      if not (Hashtbl.mem by_agent key) then seen_order := key :: !seen_order;
      Hashtbl.replace by_agent key
        (e :: Option.value (Hashtbl.find_opt by_agent key) ~default:[]))
    entries;
  let records_of k = List.rev (Option.value (Hashtbl.find_opt by_agent k) ~default:[]) in
  let from_config =
    List.map
      (fun (a : C.agent) ->
        {
          name = a.a_name;
          configured = Some a;
          via = a.a_via;
          callers = a.a_callers;
          records = (if a.a_via = "in_process" then [] else records_of a.a_name);
        })
      configured
  in
  let names = List.map (fun (a : C.agent) -> a.a_name) configured in
  let seen =
    List.filter_map
      (fun k ->
        if List.mem k names then None
        else
          let records = records_of k in
          let via =
            Option.value
              (most_frequent (List.map (guess_via ctx) records))
              ~default:"sidecar"
          in
          Some { name = k; configured = None; via; callers = [ k ]; records })
      (List.rev !seen_order)
  in
  from_config @ seen

(* ---- policies ---- *)

let enforced_policy (a : agent) =
  match a.configured with
  | Some { a_policy = Some p; _ } -> Some p
  | _ ->
      most_frequent
        (List.filter_map
           (fun (e : Index.entry) ->
             if e.record.outcome = R.Record.Shadow_denied then None
             else Some e.record.policy)
           a.records)

(** Shadow policies: shadow siblings of the enforced policy, plus shadow-mode policies its
    records were logged under. *)
let shadow_policies ctx (a : agent) =
  let siblings =
    match enforced_policy a with
    | Some p ->
        List.map (fun (i : Policies.info) -> i.name) (Policies.shadow_siblings ctx p)
    | None -> []
  in
  let logged =
    List.filter_map
      (fun (e : Index.entry) ->
        match Policies.find ctx e.record.policy with
        | Some i when i.policy.mode = Haltsql.Policy.Shadow -> Some i.name
        | _ -> None)
      a.records
  in
  List.fold_left
    (fun acc n -> if List.mem n acc then acc else acc @ [ n ])
    [] (siblings @ logged)

let policy_version ctx (a : agent) name =
  match Policies.find ctx name with
  | Some i -> Some i.policy.version
  | None ->
      List.fold_left
        (fun acc (e : Index.entry) ->
          if e.record.policy = name then
            match e.record.policy_version with Some v -> Some v | None -> acc
          else acc)
        None a.records

(* ---- JSON ---- *)

let is_denied (e : Index.entry) = e.record.outcome = R.Record.Denied

let summary_json ctx (a : agent) =
  let cfg = a.configured in
  let get f = Option.bind cfg f in
  let in_process = a.via = "in_process" in
  let queries = List.length a.records in
  let denied = List.length (List.filter is_denied a.records) in
  let policy = enforced_policy a in
  let ts = List.map (fun (e : Index.entry) -> e.ts) a.records in
  let first =
    List.fold_left
      (fun acc t -> Some (match acc with Some x -> min x t | None -> t))
      None ts
  in
  let last =
    List.fold_left
      (fun acc t -> Some (match acc with Some x -> max x t | None -> t))
      None ts
  in
  let caller_types =
    List.sort_uniq compare
      (List.filter_map (fun (e : Index.entry) -> e.record.caller_type) a.records)
  in
  `Assoc
    [
      ("name", `String a.name);
      ("team", Api.opt_string (get (fun c -> c.C.a_team)));
      ("via", `String a.via);
      ("stack", Api.opt_string (get (fun c -> c.C.a_stack)));
      ( "identity",
        match get (fun c -> c.C.a_identity) with
        | Some i -> `String i
        | None -> ( match a.callers with c :: _ -> `String c | [] -> `Null) );
      ("callers", Api.strings a.callers);
      ("caller_types", Api.strings caller_types);
      ("policy", Api.opt_string policy);
      ("policy_version", Api.opt_string (Option.bind policy (policy_version ctx a)));
      ( "mode",
        match Option.bind policy (Policies.find ctx) with
        | Some i -> `String (Policies.mode_string i.policy)
        | None -> `String "enforce" );
      ("shadow", Api.strings (shadow_policies ctx a));
      ("queries", if in_process then `Null else `Int queries);
      ("denied", if in_process then `Null else `Int denied);
      ( "deny_rate",
        if in_process || queries = 0 then `Null
        else `Float (Float.of_int denied /. Float.of_int queries) );
      ("first_seen", Api.opt_time first);
      ("last_seen", Api.opt_time last);
      ("audit", `String (if in_process then "in_app" else "central"));
      ("configured", `Bool (cfg <> None));
    ]

let target_of_change (c : R.Suggest.change) =
  match c with
  | Add_column { schema; table; column } -> Printf.sprintf "%s.%s.%s" schema table column
  | Add_function f -> f
  | Set_limit_max { proposed; _ } -> Printf.sprintf "LIMIT %d" proposed
  | Add_table { schema; table; _ } -> schema ^ "." ^ table

(** [{code, count, top_object}] over the agent's denied and shadow-denied records. The
    object comes from the report library's own extraction (detailed reasons, re-derived
    from raw SQL when logged), else the most frequent table of the records. *)
let top_codes (ctx : Ctx.t) (a : agent) =
  let bad =
    List.filter (fun (e : Index.entry) -> e.record.outcome <> R.Record.Allowed) a.records
  in
  let counts = Hashtbl.create 8 in
  List.iter
    (fun (e : Index.entry) ->
      List.iter
        (fun c ->
          Hashtbl.replace counts c
            (1 + Option.value (Hashtbl.find_opt counts c) ~default:0))
        e.record.codes)
    bad;
  let verify = Policies.make_verify () in
  let sg =
    Policies.compute_suggest ctx ~verify
      (List.map (fun (e : Index.entry) -> e.record) bad)
  in
  let objects =
    List.map
      (fun (s : R.Suggest.suggestion) ->
        (s.code, target_of_change s.change, s.evidence.records))
      sg.suggestions
    @ List.map
        (fun (i : R.Suggest.item) -> (i.i_code, i.target, i.i_evidence.records))
        (sg.pii_flagged @ sg.not_suggested)
  in
  let top_object code =
    let best =
      List.fold_left
        (fun acc (c, t, n) ->
          if c <> code then acc
          else match acc with Some (_, m) when m >= n -> acc | _ -> Some (t, n))
        None objects
    in
    match best with
    | Some (t, _) -> Some t
    | None ->
        most_frequent
          (List.concat_map
             (fun (e : Index.entry) ->
               if List.mem code e.record.codes then e.record.tables else [])
             bad)
  in
  Hashtbl.fold (fun c n acc -> (c, n) :: acc) counts []
  |> List.sort (fun (c1, n1) (c2, n2) ->
      if n1 <> n2 then compare n2 n1 else compare c1 c2)
  |> List.map (fun (c, n) ->
      `Assoc
        [
          ("code", `String c);
          ("count", `Int n);
          ("top_object", Api.opt_string (top_object c));
        ])

let policy_ref_json ctx (a : agent) name =
  match Policies.find ctx name with
  | Some i ->
      `Assoc
        [
          ("name", `String name);
          ("version", `String i.policy.version);
          ("mode", `String (Policies.mode_string i.policy));
          ("origin", `String i.origin);
          ("loaded", `Bool true);
        ]
  | None ->
      `Assoc
        [
          ("name", `String name);
          ("version", Api.opt_string (policy_version ctx a name));
          ("mode", `Null);
          ("origin", `Null);
          ("loaded", `Bool false);
        ]

let detail_json ctx a =
  match summary_json ctx a with
  | `Assoc base ->
      `Assoc
        (base
        @ [
            ("top_codes", `List (top_codes ctx a));
            ( "policies",
              `Assoc
                [
                  ( "enforced",
                    match enforced_policy a with
                    | Some p -> policy_ref_json ctx a p
                    | None -> `Null );
                  ( "shadow",
                    `List (List.map (policy_ref_json ctx a) (shadow_policies ctx a)) );
                ] );
          ])
  | j -> j

(** An agent by name over the default range (for the Playground). *)
let find ctx
    ?(range = Api.{ since = Ctx.now () -. (7. *. 86400.); until = Ctx.now () +. 1. }) name
    =
  List.find_opt (fun a -> a.name = name) (build ctx range)

let vias = [ "sidecar"; "proxy"; "mcp"; "in_process" ]

let routes : Router.route list =
  [
    Router.get "/api/v1/agents" (fun ctx _p r ->
        let req = r.Router.http in
        let range = Api.range ~default:"7d" req in
        let via = Api.query req "via" in
        (match via with
        | Some v when v <> "" && not (List.mem v vias) ->
            Api.bad_request "via must be one of sidecar, proxy, mcp, in_process"
        | _ -> ());
        let agents = build ctx range in
        let counts =
          ("all", `Int (List.length agents))
          :: List.map
               (fun v ->
                 (v, `Int (List.length (List.filter (fun a -> a.via = v) agents))))
               vias
        in
        let shown =
          match via with
          | Some v when v <> "" -> List.filter (fun a -> a.via = v) agents
          | _ -> agents
        in
        let denied a = List.length (List.filter is_denied a.records) in
        let first a = match a.records with e :: _ -> e.Index.ts | [] -> neg_infinity in
        let sorted =
          match Api.query req "sort" with
          | None | Some "" | Some "denied" ->
              List.stable_sort (fun a b -> compare (denied b) (denied a)) shown
          | Some "queries" ->
              List.stable_sort
                (fun a b -> compare (List.length b.records) (List.length a.records))
                shown
          | Some "newest" ->
              List.stable_sort (fun a b -> compare (first b) (first a)) shown
          | Some _ -> Api.bad_request "sort must be one of denied, queries, newest"
        in
        Api.json
          (`Assoc
             [
               ("range", Api.range_to_json range);
               ("counts", `Assoc counts);
               ("agents", `List (List.map (summary_json ctx) sorted));
             ]));
    Router.get "/api/v1/agents/:name" (fun ctx _p r ->
        let range = Api.range ~default:"7d" r.Router.http in
        let name = Router.param r "name" in
        match List.find_opt (fun a -> a.name = name) (build ctx range) with
        | Some a -> Api.json (detail_json ctx a)
        | None -> Api.not_found "no agent %s" name);
  ]

let start (_ : Ctx.t) : unit Lwt.t = Lwt.return_unit
