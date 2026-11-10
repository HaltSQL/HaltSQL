(* Cases: durable investigations in the Store collection [cases], ids CASE-<n> from a
   counter starting at 1000. Any role reads; [write_cases] mutates. A case created from a
   signal links both ways. Optional Jira issue per case (best effort).
   See docs/console/api.md#cases. *)

open Lwt.Syntax

let collection = "cases"
let statuses = [ "open"; "contained"; "resolved" ]

let cross_tenant_steps =
  [
    "Confirm nothing leaked: every query was denied before reaching the database";
    "Quarantine the source: revoke or rotate the caller's identity at the identity \
     provider";
    "Copy the request ids into the incident ticket";
    "Fix the agent and resume its traffic";
  ]

let fields (j : Yojson.Safe.t) = match j with `Assoc l -> l | _ -> []
let get_str k j = match Api.member k j with Some (`String s) -> Some s | _ -> None
let set k v j = `Assoc ((k, v) :: List.remove_assoc k (fields j))

(* Keep the documented field order stable in responses. *)
let order =
  [
    "id";
    "title";
    "status";
    "assignee";
    "created";
    "updated";
    "created_by";
    "signal_id";
    "request_ids";
    "notes";
    "steps";
    "jira";
  ]

let normalize j =
  let l = fields j in
  `Assoc
    (List.filter_map (fun k -> Option.map (fun v -> (k, v)) (List.assoc_opt k l)) order
    @ List.filter (fun (k, _) -> not (List.mem k order)) l)

let find (ctx : Ctx.t) id =
  match Store.get ctx.store collection id with
  | Some c -> c
  | None -> Api.not_found "no case %s" id

let string_list k j =
  match Api.member k j with
  | Some (`List l) -> List.filter_map (function `String s -> Some s | _ -> None) l
  | _ -> []

let dedupe l =
  List.fold_left (fun acc x -> if List.mem x acc then acc else acc @ [ x ]) [] l

let check_resolved c =
  if get_str "status" c = Some "resolved" then
    Api.conflict "case %s is resolved; reopen it first"
      (Option.value (get_str "id" c) ~default:"")

(* ---- handlers ---- *)

let list_cases (ctx : Ctx.t) (p : Ctx.principal) (r : Router.req) =
  let status = Option.value (Router.query r "status") ~default:"open" in
  if status <> "open" && status <> "all" then Api.bad_request "status must be open or all";
  let assignee =
    match Router.query r "assignee" with
    | Some "me" -> Some p.id
    | Some "" | None -> None
    | Some a -> Some a
  in
  (* newest first: folding in insertion order and prepending reverses it *)
  let cases =
    Store.fold ctx.store collection
      (fun _ c acc ->
        if
          (status = "all" || get_str "status" c <> Some "resolved")
          && match assignee with None -> true | Some a -> get_str "assignee" c = Some a
        then c :: acc
        else acc)
      []
  in
  Api.json (`Assoc [ ("cases", `List (List.map normalize cases)) ])

let create_case (ctx : Ctx.t) (p : Ctx.principal) (r : Router.req) =
  let* body = Router.json_body r in
  let _ = Ctx.require ~body p r.http Rbac.Write_cases in
  let title = Option.get (Api.str_field ~required:true "title" body) in
  if String.trim title = "" then Api.bad_request "field title must not be empty";
  let signal_id = Api.str_field "signal_id" body in
  let assignee = Api.str_field "assignee" body in
  let request_ids = Api.str_list_field "request_ids" body in
  let signal =
    match signal_id with
    | None -> None
    | Some sid ->
        if not (Signals.exists ctx sid) then Api.bad_request "unknown signal %s" sid;
        (match Signals.case_of ctx sid with
        | Some c -> Api.conflict "signal %s is already linked to %s" sid c
        | None -> ());
        Signals.find ctx sid
  in
  let request_ids, steps =
    match signal with
    | Some l ->
        let inv = Signals.investigation ctx l in
        ( dedupe (request_ids @ string_list "request_ids" inv),
          if l.d.kind = "cross_tenant" then cross_tenant_steps else [] )
    | None -> (dedupe request_ids, [])
  in
  let* n = Store.next_counter ctx.store "case" ~start:1000 in
  let id = Printf.sprintf "CASE-%d" n in
  let now = Api.iso8601 (Ctx.now ()) in
  let doc =
    `Assoc
      [
        ("id", `String id);
        ("title", `String title);
        ("status", `String "open");
        ("assignee", Api.opt_string assignee);
        ("created", `String now);
        ("updated", `String now);
        ("created_by", `String p.id);
        ("signal_id", Api.opt_string signal_id);
        ("request_ids", Api.strings request_ids);
        ("notes", `List []);
        ( "steps",
          `List
            (List.map
               (fun t -> `Assoc [ ("text", `String t); ("done", `Bool false) ])
               steps) );
        ("jira", `Null);
      ]
  in
  let* () = Store.put ctx.store collection id doc in
  let* () =
    match signal_id with
    | Some sid -> Signals.set_case ctx sid id
    | None -> Lwt.return_unit
  in
  let* jira =
    if Notify.jira_configured ctx.config then
      Notify.jira_issue ctx.config
        ~summary:(id ^ ": " ^ title)
        ~description:
          (Printf.sprintf "HaltSQL console case %s, opened by %s.%s\nRequest ids: %s" id
             p.id
             (match signal with
             | Some l -> "\nSignal: " ^ l.d.title ^ "\n" ^ l.d.body
             | None -> "")
             (String.concat ", " (List.filteri (fun i _ -> i < 50) request_ids)))
    else Lwt.return_none
  in
  let* doc =
    match jira with
    | None -> Lwt.return doc
    | Some key ->
        let j =
          `Assoc
            [
              ("key", `String key);
              ("url", Api.opt_string (Notify.jira_browse_url ctx.config key));
            ]
        in
        let* d = Store.update ctx.store collection id (Option.map (set "jira" j)) in
        Lwt.return (Option.value d ~default:doc)
  in
  let* () =
    Activity.log ctx p ~action:"case.create" ~target:id
      ~detail:
        (`Assoc
           [
             ("title", `String title);
             ("signal_id", Api.opt_string signal_id);
             ("jira", Api.opt_string jira);
           ])
      ()
  in
  Api.json ~status:`Created (normalize doc)

let patch_case (ctx : Ctx.t) (p : Ctx.principal) (r : Router.req) =
  let id = Router.param r "id" in
  let* body = Router.json_body r in
  let _ = Ctx.require ~body p r.http Rbac.Write_cases in
  let c = find ctx id in
  let title = Api.str_field "title" body in
  let status = Api.str_field "status" body in
  let note = Api.str_field "note" body in
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
  | _ -> ());
  (match title with
  | Some t when String.trim t = "" -> Api.bad_request "field title must not be empty"
  | _ -> ());
  (match note with
  | Some t when String.trim t = "" -> Api.bad_request "field note must not be empty"
  | _ -> ());
  if title = None && status = None && note = None && assignee = None then
    Api.bad_request "send at least one of title, status, assignee, note";
  (* A resolved case only accepts being reopened (optionally with a note). *)
  if get_str "status" c = Some "resolved" && status <> Some "open" then check_resolved c;
  let now = Api.iso8601 (Ctx.now ()) in
  let* updated =
    Store.update ctx.store collection id (function
      | None -> None
      | Some c ->
          let c = match title with Some t -> set "title" (`String t) c | None -> c in
          let c = match status with Some s -> set "status" (`String s) c | None -> c in
          let c = match assignee with Some a -> set "assignee" a c | None -> c in
          let c =
            match note with
            | Some t ->
                let notes =
                  match Api.member "notes" c with Some (`List l) -> l | _ -> []
                in
                set "notes"
                  (`List
                     (notes
                     @ [
                         `Assoc
                           [
                             ("at", `String now); ("by", `String p.id); ("text", `String t);
                           ];
                       ]))
                  c
            | None -> c
          in
          Some (set "updated" (`String now) c))
  in
  let* () =
    Activity.log ctx p ~action:"case.update" ~target:id
      ~detail:
        (`Assoc
           (List.filter_map Fun.id
              [
                Option.map (fun t -> ("title", `String t)) title;
                Option.map (fun s -> ("status", `String s)) status;
                Option.map (fun a -> ("assignee", a)) assignee;
                Option.map (fun _ -> ("note", `Bool true)) note;
              ]))
      ()
  in
  Api.json (normalize (Option.value updated ~default:c))

let add_records (ctx : Ctx.t) (p : Ctx.principal) (r : Router.req) =
  let id = Router.param r "id" in
  let* body = Router.json_body r in
  let _ = Ctx.require ~body p r.http Rbac.Write_cases in
  let c = find ctx id in
  check_resolved c;
  let ids = Api.str_list_field "request_ids" body in
  if ids = [] then Api.bad_request "field request_ids must be a non-empty list";
  let now = Api.iso8601 (Ctx.now ()) in
  let* updated =
    Store.update ctx.store collection id
      (Option.map (fun c ->
           set "updated" (`String now)
             (set "request_ids"
                (Api.strings (dedupe (string_list "request_ids" c @ ids)))
                c)))
  in
  let* () =
    Activity.log ctx p ~action:"case.add_records" ~target:id
      ~detail:(`Assoc [ ("request_ids", Api.strings ids) ])
      ()
  in
  Api.json (normalize (Option.value updated ~default:c))

let set_step (ctx : Ctx.t) (p : Ctx.principal) (r : Router.req) =
  let id = Router.param r "id" in
  let* body = Router.json_body r in
  let _ = Ctx.require ~body p r.http Rbac.Write_cases in
  let n =
    match int_of_string_opt (Router.param r "n") with
    | Some n -> n
    | None -> Api.bad_request "step must be an integer index"
  in
  let c = find ctx id in
  check_resolved c;
  let done_ =
    match Api.bool_field "done" body with
    | Some b -> b
    | None -> Api.bad_request "field done is required"
  in
  let steps = match Api.member "steps" c with Some (`List l) -> l | _ -> [] in
  if n < 0 || n >= List.length steps then Api.not_found "case %s has no step %d" id n;
  let now = Api.iso8601 (Ctx.now ()) in
  let* updated =
    Store.update ctx.store collection id
      (Option.map (fun c ->
           let steps = match Api.member "steps" c with Some (`List l) -> l | _ -> [] in
           set "updated" (`String now)
             (set "steps"
                (`List
                   (List.mapi
                      (fun i s -> if i = n then set "done" (`Bool done_) s else s)
                      steps))
                c)))
  in
  let* () =
    Activity.log ctx p ~action:"case.step" ~target:id
      ~detail:(`Assoc [ ("step", `Int n); ("done", `Bool done_) ])
      ()
  in
  Api.json (normalize (Option.value updated ~default:c))

let routes : Router.route list =
  [
    Router.get "/api/v1/cases" list_cases;
    Router.post "/api/v1/cases" create_case;
    Router.get "/api/v1/cases/:id" (fun ctx _p r ->
        Api.json (normalize (find ctx (Router.param r "id"))));
    Router.patch "/api/v1/cases/:id" patch_case;
    Router.post "/api/v1/cases/:id/records" add_records;
    Router.post "/api/v1/cases/:id/steps/:n" set_step;
  ]

let start (_ : Ctx.t) : unit Lwt.t = Lwt.return_unit
