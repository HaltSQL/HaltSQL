(* Append-only activity log: who saw or did what, and why. Stored as activity.jsonl in the
   state dir; read by GET /api/v1/activity and evidence packs. *)

let log (ctx : Ctx.t) (p : Ctx.principal) ?reason ?(detail = `Assoc []) ~action ~target ()
    =
  Store.append_line ctx.store "activity"
    (`Assoc
       [
         ("at", `String (Api.iso8601 (Ctx.now ())));
         ("actor", `String p.id);
         ("role", `String (Rbac.role_to_string p.role));
         ("auth", `String p.auth);
         ("action", `String action);
         ("target", `String target);
         ("reason", Api.opt_string reason);
         ("detail", detail);
       ])

let entries (ctx : Ctx.t) = Store.read_lines ctx.store "activity"

let routes =
  [
    Router.get "/api/v1/activity" (fun ctx _p r ->
        let req = r.Router.http in
        let actor = Api.query req "actor" and action = Api.query req "action" in
        let since = Option.bind (Api.query req "since") Api.parse_time in
        let keep j =
          let s name =
            match Api.member name j with Some (`String s) -> Some s | _ -> None
          in
          (match actor with None -> true | Some a -> s "actor" = Some a)
          && (match action with
            | None -> true
            | Some a -> (
                match s "action" with
                | Some x -> String.starts_with ~prefix:a x
                | None -> false))
          &&
          match since with
          | None -> true
          | Some t -> (
              match Option.bind (s "at") Api.parse_time with
              | Some x -> x >= t
              | None -> false)
        in
        let all = List.rev (List.filter keep (entries ctx)) in
        let items, next, total = Api.page req all in
        Api.json
          (`Assoc
             [ ("entries", `List items); ("next_cursor", next); ("total", `Int total) ]));
  ]
